//! The Mac path end to end, on the CPU (T-219): the real agent (`Agent::run`) with the real sandboxed `pool-runner`
//! (`onnx` feature) and this OS's pinned ONNX Runtime CPU pack, against a scripted job server.
//!
//! 1. ModelHint -> the agent downloads the server-signed bge-m3 stand-in bundle (`onnxruntime`, XLM-R tokenizer,
//!    external weights; `pool-runner/tests/fixtures/xlmr-tiny`) and announces it.
//! 2. BenchmarkOffer (server-signed workload; the dev duration override shortens it) -> accepted -> a signed
//!    BenchmarkResult with exactly 20 segments -> BenchmarkReceipt RECEIVED.
//! 3. Offer -> Accept -> LeaseGrant -> Result: the embeddings match the engine reference worker's.
//! 4. The app's view: the runtime that ran (`onnxruntime-cpu`), and the speed the app measured during the benchmark
//!    (tokens per second, marked as received by the server), kept in `state.json` across a restart.
//!
//! macOS arm64 and Linux x64 only: those packs are CPU-only. (On Windows the agent uses the DirectML pack, a GPU path,
//! which this test must not run.) Needs the pinned pack (`node pool-app/scripts/runtime-packs.mjs`, or
//! `POOL_ORT_PACK=<dir>`); without it the test prints why and passes, unless `POOL_REQUIRE_ORT_PACK=1` (CI).
//!   cargo test -p pool-core --test onnx_cpu_path -- --nocapture
#![cfg(not(windows))]

use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message as AxMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use pool_core::agent::Agent;
use pool_core::config::Config;
use pool_core::platform::Readings;
use pool_proto::objects::{BenchmarkResult, BenchmarkWorkload, LeaseEnvelope, ResultClaims};
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use pool_proto::{cose, now_ms, object_types as ot, sha256};
use prost::Message as _;

const FILES: [&str; 4] = ["onnx/model.onnx", "onnx/model.onnx_data", "onnx/tokenizer.json", "onnx/tokenizer_config.json"];

fn fixture() -> PathBuf {
    FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../pool-runner/tests/fixtures/xlmr-tiny")
}

fn pack() -> Option<PathBuf> {
    let dir = pool_runner::accel::ort_pack().map(|p| p.dir.as_str()).unwrap_or("none");
    let p = std::env::var_os("POOL_ORT_PACK")
        .map(PathBuf::from)
        .unwrap_or_else(|| FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../pool-app/src-tauri/backends").join(dir));
    match pool_runner::accel::verify_pack(&p) {
        Ok(_) => Some(p),
        Err(e) if std::env::var("POOL_REQUIRE_ORT_PACK").as_deref() == Ok("1") => {
            panic!("POOL_REQUIRE_ORT_PACK=1: no usable pinned ONNX Runtime pack at {} ({e})", p.display())
        }
        Err(e) => {
            eprintln!("skipped: no pinned ONNX Runtime pack at {} ({e})", p.display());
            None
        }
    }
}

/// The runner as the release app ships it on macOS and Linux (`onnx`), built into this test's target dir.
fn onnx_runner_exe() -> PathBuf {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "pool-runner", "--features", "onnx", "--bin", "pool-runner"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("cargo build pool-runner --features onnx");
    assert!(status.success());
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("pool-runner")
}

struct Ctx {
    device_id: String,
    device_key_id: String,
    model_hash: [u8; 32],
    model_id: String,
    base: String,
}

#[derive(Default)]
struct Mock {
    device_spki: Mutex<Vec<u8>>,
    keyset: Mutex<Vec<u8>>,
    manifest: Mutex<Vec<u8>>,
    files: Mutex<Vec<(String, Vec<u8>)>>,
    bench_bundle: Mutex<Vec<u8>>,
    input: Mutex<Vec<u8>>,
    output: Mutex<Option<Vec<u8>>>,
    connections: AtomicUsize,
    result: Mutex<Option<Result<String, String>>>,
    ctx: Mutex<Option<Arc<Ctx>>>,
}

async fn keys_route(State(m): State<Arc<Mock>>) -> impl IntoResponse {
    m.keyset.lock().unwrap().clone()
}
async fn manifest_route(State(m): State<Arc<Mock>>, Path((_m, _v)): Path<(String, String)>) -> impl IntoResponse {
    m.manifest.lock().unwrap().clone()
}
async fn bundle_route(State(m): State<Arc<Mock>>, Path((_m, _v, p)): Path<(String, String, String)>) -> impl IntoResponse {
    match m.files.lock().unwrap().iter().find(|(n, _)| *n == p) {
        Some((_, b)) => (StatusCode::OK, b.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn bench_bundle_route(State(m): State<Arc<Mock>>) -> impl IntoResponse {
    m.bench_bundle.lock().unwrap().clone()
}
async fn input_route(State(m): State<Arc<Mock>>, Path(_lease): Path<String>) -> impl IntoResponse {
    m.input.lock().unwrap().clone()
}
async fn output_route(State(m): State<Arc<Mock>>, Path(_lease): Path<String>, body: Bytes) -> impl IntoResponse {
    *m.output.lock().unwrap() = Some(body.to_vec());
    StatusCode::OK
}
async fn ws_route(ws: WebSocketUpgrade, State(m): State<Arc<Mock>>) -> impl IntoResponse {
    ws.protocols(["pool.node.v1"]).on_upgrade(move |socket| async move {
        if m.connections.fetch_add(1, Ordering::SeqCst) == 0 {
            let r = script(socket, m.clone()).await;
            *m.result.lock().unwrap() = Some(r);
        }
    })
}

struct Hub {
    ws: WebSocket,
    seq: u64,
    inbound_seq: u64,
}

impl Hub {
    async fn send(&mut self, body: SB) -> Result<(), String> {
        self.seq += 1;
        let bytes = pb::ServerMessage { seq: self.seq, body: Some(body) }.encode_to_vec();
        self.ws.send(AxMsg::Binary(bytes.into())).await.map_err(|e| e.to_string())
    }
    /// Next node message other than Heartbeat (unless `want_heartbeat`).
    async fn recv(&mut self, want_heartbeat: bool) -> Result<NB, String> {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(120), self.ws.recv())
                .await
                .map_err(|_| "timeout waiting for node message".to_string())?
                .ok_or("connection closed")?
                .map_err(|e| e.to_string())?;
            let AxMsg::Binary(b) = m else { continue };
            let msg = pb::NodeMessage::decode(&b[..]).map_err(|e| e.to_string())?;
            if msg.seq != self.inbound_seq + 1 {
                return Err(format!("node seq {} after {}", msg.seq, self.inbound_seq));
            }
            self.inbound_seq = msg.seq;
            let body = msg.body.ok_or("empty body")?;
            if matches!(body, NB::Heartbeat(_)) && !want_heartbeat {
                continue;
            }
            return Ok(body);
        }
    }
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let d: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    d / (a.iter().map(|x| x * x).sum::<f64>().sqrt() * b.iter().map(|x| x * x).sum::<f64>().sqrt())
}

fn vectors(v: &serde_json::Value) -> Vec<Vec<f64>> {
    v.as_array().unwrap().iter().map(|e| e.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect()).collect()
}

async fn script(ws: WebSocket, m: Arc<Mock>) -> Result<String, String> {
    let c = m.ctx.lock().unwrap().clone().unwrap();
    let vault = pool_runner::testutil::vault();
    let device_key = pool_proto::keys::parse_spki(&m.device_spki.lock().unwrap()).unwrap();
    let mut hub = Hub { ws, seq: 0, inbound_seq: 0 };

    // session
    let nonce: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
    hub.send(SB::Challenge(pb::Challenge { nonce, server_time_ms: now_ms() as i64, protocol_version: "pool.node.v1".into() })).await?;
    let NB::Hello(_) = hub.recv(false).await? else { return Err("expected Hello".into()) };
    hub.send(SB::Welcome(pb::Welcome { session_id: uuid(), session_expires_ms: (now_ms() + 3_600_000) as i64, heartbeat_interval_s: 30, server_time_ms: now_ms() as i64 })).await?;

    // 1. the model is downloaded and announced
    hub.send(SB::ModelHint(pb::ModelHint { model_id: c.model_id.clone(), version: "1".into(), manifest_url: format!("/node/v1/manifests/{}/1", c.model_id) })).await?;
    loop {
        if let NB::Heartbeat(hb) = hub.recv(true).await? {
            if hb.cached_models.iter().any(|cm| cm.model_hash == c.model_hash) {
                break;
            }
        }
    }

    // 2. the probation benchmark on the CPU pack
    let exp: serde_json::Value = serde_json::from_slice(&std::fs::read(fixture().join("expected.json")).unwrap()).unwrap();
    let bench_input = serde_json::to_vec(&serde_json::json!({ "inputs": exp["inputs"] })).unwrap();
    *m.bench_bundle.lock().unwrap() = bench_input.clone();
    let w = BenchmarkWorkload {
        benchmark_id: uuid(),
        device_id: c.device_id.clone(),
        device_key_id: c.device_key_id.clone(),
        model_id: c.model_id.clone(),
        model_hash: c.model_hash,
        bundle_sha256: sha256(&bench_input),
        nonce: [9; 32],
        min_duration_s: 1200,
        issued_at: now_ms(),
        expires_at: now_ms() + 600_000,
    };
    let wbytes = vault.sign_workload(&w);
    hub.send(SB::BenchmarkOffer(pb::BenchmarkOffer { benchmark_id: w.benchmark_id.clone(), workload: wbytes.clone(), bundle_url: "/bench/bundle".into(), est_duration_s: 1200 })).await?;
    match hub.recv(false).await? {
        NB::BenchmarkResponse(r) if r.accept && r.benchmark_id == w.benchmark_id => {}
        other => return Err(format!("expected BenchmarkResponse(accept), got {other:?}")),
    }
    let br = match hub.recv(false).await? {
        NB::BenchmarkResult(r) => r,
        other => return Err(format!("expected BenchmarkResult, got {other:?}")),
    };
    let s = cose::verify_sign1(&br.result_sig, &device_key, ot::BENCHMARK_RESULT).map_err(|e| format!("bench sig: {e}"))?;
    let b = BenchmarkResult::from_value(&s.claims).map_err(|e| e.to_string())?;
    if b.workload_sha256 != sha256(&wbytes) || b.segments.len() != 20 || b.device_key_id != c.device_key_id {
        return Err(format!("benchmark result wrong: {b:?}"));
    }
    hub.send(SB::BenchmarkReceipt(pb::BenchmarkReceipt { benchmark_id: w.benchmark_id.clone(), status: pb::ReceiptStatus::Received as i32 })).await?;

    // 3. a paid job on the same pack
    let (job_id, lease_id) = (uuid(), uuid());
    let input = bench_input;
    *m.input.lock().unwrap() = input.clone();
    hub.send(SB::Offer(pb::Offer { job_id: job_id.clone(), model_id: c.model_id.clone(), model_hash: c.model_hash.to_vec(), est_units: 10, deadline_ms: (now_ms() + 120_000) as i64 })).await?;
    match hub.recv(false).await? {
        NB::Accept(a) if a.job_id == job_id => {}
        other => return Err(format!("expected Accept, got {other:?}")),
    }
    let now = now_ms();
    let env = LeaseEnvelope {
        job_id: job_id.clone(),
        lease_id: lease_id.clone(),
        device_id: c.device_id.clone(),
        device_key_id: c.device_key_id.clone(),
        model_id: c.model_id.clone(),
        model_hash: c.model_hash,
        input_sha256: sha256(&input),
        input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
        input_bytes: input.len() as u64,
        unit_type: "token".into(),
        issued_at: now,
        deadline: now + 120_000,
        language: None,
    };
    hub.send(SB::LeaseGrant(pb::LeaseGrant {
        job_id: job_id.clone(),
        lease_id: lease_id.clone(),
        lease_envelope: vault.sign_envelope(&env),
        input_url: format!("{}/node/v1/inputs/{lease_id}?t=tok", c.base),
        output_url: format!("{}/node/v1/outputs/{lease_id}?t=tok", c.base),
        lease_deadline_ms: env.deadline as i64 - 1000,
    }))
    .await?;
    let res = match hub.recv(false).await? {
        NB::Result(r) => r,
        other => return Err(format!("expected Result, got {other:?}")),
    };
    let s = cose::verify_sign1(&res.result_sig, &device_key, ot::RESULT_CLAIMS).map_err(|e| format!("result sig: {e}"))?;
    let rc = ResultClaims::from_value(&s.claims).map_err(|e| e.to_string())?;
    let stored = m.output.lock().unwrap().clone().ok_or("no output stored")?;
    if rc.job_id != job_id || rc.output_sha256 != sha256(&stored) || rc.model_hash != c.model_hash {
        return Err(format!("result claims wrong: {rc:?}"));
    }
    let doc: serde_json::Value = serde_json::from_slice(&stored).map_err(|e| e.to_string())?;
    let (got, want) = (vectors(&doc["embeddings"]), vectors(&exp["embeddings"]));
    if got.len() != want.len() {
        return Err(format!("{} embeddings, want {}", got.len(), want.len()));
    }
    let min = got.iter().zip(&want).map(|(g, w)| cosine(g, w)).fold(1f64, f64::min);
    if min < 0.99999 {
        return Err(format!("embeddings differ from the reference worker: min cosine {min}"));
    }
    hub.send(SB::ResultReceipt(pb::ResultReceipt { job_id, lease_id, status: pb::ReceiptStatus::Received as i32 })).await?;
    Ok(format!("bench segments {}, min cosine {min:.6}", b.segments.len()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mac_path_benchmark_and_job_on_the_cpu_pack() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").with_test_writer().try_init();
    let Some(pack) = pack() else { return };
    let vault = pool_runner::testutil::vault(); // installs the dev trust roots for agent and runner
    let files: Vec<(&str, Vec<u8>)> = FILES.iter().map(|f| (*f, std::fs::read(fixture().join(f)).unwrap())).collect();
    let fx = pool_runner::testutil::bundle_fixture_with(&files, "onnxruntime", "onnx", pool_proto::EMBED_BATCH_FORMAT, "bge-m3");
    let m = Arc::new(Mock::default());
    *m.keyset.lock().unwrap() = vault.keyset_bytes(3);
    *m.manifest.lock().unwrap() = fx.manifest_cose.clone();
    *m.files.lock().unwrap() =
        fx.manifest.files.iter().map(|f| (f.path.clone(), std::fs::read(fx.dir.path().join(&f.path)).unwrap())).collect();

    let app = Router::new()
        .route("/node/v1/connect", get(ws_route))
        .route("/v1/keys", get(keys_route))
        .route("/node/v1/manifests/{m}/{v}", get(manifest_route))
        .route("/node/v1/bundles/{m}/{v}/{*p}", get(bundle_route))
        .route("/bench/bundle", get(bench_bundle_route))
        .route("/node/v1/inputs/{lease}", get(input_route))
        .route("/node/v1/outputs/{lease}", axum::routing::put(output_route))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let data = tempfile::tempdir().unwrap();
    let cfg = Config {
        engine_ws_url: format!("ws://{addr}/node/v1/connect"),
        vault_url: format!("http://{addr}"),
        web_url: "http://127.0.0.1:3000".into(),
        dev: true,
        bench_duration_override_s: Some(4),
        runner_path: Some(onnx_runner_exe()),
        prefer_tpm: false,
        ort_pack_dir: Some(pack),
        ..Config::default()
    };
    let platform: Arc<dyn Fn() -> Readings + Send + Sync> = Arc::new(|| Readings { idle_s: Some(3600), on_ac: Some(true), ..Default::default() });
    let agent = Agent::with_platform(data.path().into(), cfg.clone(), platform.clone()).unwrap();
    *m.device_spki.lock().unwrap() = agent.key().spki_der();
    let device_id = uuid();
    *m.ctx.lock().unwrap() = Some(Arc::new(Ctx {
        device_id: device_id.clone(),
        device_key_id: agent.key().device_key_id(),
        model_hash: fx.model_hash,
        model_id: fx.manifest.model_id.clone(),
        base: format!("http://{addr}"),
    }));
    // linked as the T-213 path leaves it: a capped (software-key) device
    agent.set_enrollment(&device_id, "capped");
    let run = tokio::spawn(agent.clone().run());

    let deadline = Instant::now() + Duration::from_secs(300);
    let outcome = loop {
        if let Some(r) = m.result.lock().unwrap().take() {
            break r;
        }
        if Instant::now() > deadline {
            break Err(format!("timeout; status={:?}", agent.status.get()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let summary = outcome.unwrap();
    eprintln!("{summary}");
    // wait until the receipt has reached the agent's state
    let deadline = Instant::now() + Duration::from_secs(30);
    while !agent.state_snapshot().performance.first().is_some_and(|p| p.received) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    run.abort();

    // 4. what the app shows
    let status = agent.status.get();
    assert_eq!(status.backend.as_deref(), Some("onnxruntime-cpu"), "the runtime that ran, as reported by the runner");
    let b = status.benchmark.expect("benchmark status");
    assert_eq!((b.state.as_str(), b.model_id.as_str()), ("received", "bge-m3"));
    let snap = agent.snapshot();
    let perf = snap["performance"].as_array().expect("performance in the app snapshot");
    assert_eq!(perf.len(), 1, "{perf:?}");
    let p = &perf[0];
    assert_eq!(p["model_id"], "bge-m3");
    assert_eq!(p["received"], true);
    assert_eq!(p["measured"]["unit"], "token");
    assert_eq!(p["measured"]["backend"], "onnxruntime-cpu");
    let rate = p["measured"]["per_second"].as_f64().unwrap();
    let runs = p["measured"]["runs"].as_u64().unwrap();
    assert!(rate > 0.0 && rate.is_finite() && runs >= 1, "{p}");
    eprintln!("measured on this machine: {rate:.1} tokens per second over {runs} runs (stand-in model)");
    assert_eq!(snap["trust_ceiling"], "capped");

    // kept across a restart, and never part of what the device signs or sends (display only)
    drop(agent);
    let again = Agent::with_platform(data.path().into(), cfg, platform).unwrap();
    assert_eq!(again.snapshot()["performance"], serde_json::Value::Array(perf.clone()));
}
