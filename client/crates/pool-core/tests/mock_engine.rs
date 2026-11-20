//! Integration test: the real agent (`Agent::run`, real sandboxed `pool-runner`) against a scripted mock
//! the server job server + mock server key endpoint on loopback (dev `ws://`, zero TLS exporter).
//!
//! Scenario (each step asserts what the node must and must not do):
//! 1. Challenge -> Hello: the signature verifies with the device key over {device_id, nonce, exporter=0}.
//! 2. ModelHint -> the agent downloads the server-signed bundle and announces it in a Heartbeat.
//! 3. Offer for an uncached model -> Decline(MODEL_NOT_CACHED); a LeaseGrant for it -> no input fetch.
//! 4. Offer -> Accept within 5 s -> LeaseGrant (server-signed envelope) -> exactly one input GET with a
//!    valid Pool-Lease-Proof -> output PUT -> Result whose signature and hashes match what the server stored.
//! 5. Replayed LeaseGrant -> ignored, no second fetch.
//! 6. BenchmarkOffer (server-signed workload, duration override 2 s) -> BenchmarkResult signed by the device.
//! 7. User returns during a job -> Abandon(PREEMPTED) within 5 s.
//! 8. Goodbye(reconnect 1 s) -> reconnect; a replayed Challenge nonce gets no Hello.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message as AxMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use pool_core::agent::Agent;
use pool_core::config::Config;
use pool_core::platform::Readings;
use pool_proto::objects::{BenchmarkResult, BenchmarkWorkload, HelloClaims, LeaseEnvelope, LeaseProof, ResultClaims};
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use pool_proto::{cose, keys, now_ms, object_types as ot, sha256};
use prost::Message as _;

struct Lease {
    input: Vec<u8>,
    gets: usize,
    delay_ms: u64,
    output: Option<Vec<u8>>,
}

#[derive(Default)]
struct Mock {
    device_spki: Mutex<Vec<u8>>,
    keyset: Mutex<Vec<u8>>,
    manifest: Mutex<Vec<u8>>,
    files: Mutex<Vec<(String, Vec<u8>)>>,
    bench_bundle: Mutex<Vec<u8>>,
    leases: Mutex<std::collections::HashMap<String, Lease>>,
    proof_nonces: Mutex<HashSet<Vec<u8>>>,
    events: Mutex<Vec<String>>,
    connections: AtomicUsize,
    first_nonce: Mutex<Vec<u8>>,
    result: Mutex<Option<Result<(), String>>>,
}

impl Mock {
    fn log(&self, e: impl Into<String>) {
        self.events.lock().unwrap().push(e.into());
    }
    fn device_key(&self) -> p256::ecdsa::VerifyingKey {
        keys::parse_spki(&self.device_spki.lock().unwrap()).unwrap()
    }
    fn check_proof(&self, headers: &HeaderMap, lease_id: &str, method: &str, path: &str, body: Option<&[u8]>) -> Result<(), String> {
        let h = headers.get("Pool-Lease-Proof").ok_or("missing proof")?.to_str().map_err(|e| e.to_string())?;
        let cose_bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, h).map_err(|e| e.to_string())?;
        let s = cose::verify_sign1(&cose_bytes, &self.device_key(), ot::LEASE_PROOF).map_err(|e| e.to_string())?;
        let p = LeaseProof::from_value(&s.claims).map_err(|e| e.to_string())?;
        if p.lease_id != lease_id || p.method != method || p.path != path {
            return Err(format!("proof binding mismatch {p:?}"));
        }
        if p.ts.abs_diff(now_ms()) > 60_000 {
            return Err("stale proof".into());
        }
        if !self.proof_nonces.lock().unwrap().insert(p.nonce.to_vec()) {
            return Err("proof nonce replayed".into());
        }
        if let Some(b) = body {
            if p.body_sha256 != Some(sha256(b)) {
                return Err("body hash mismatch".into());
            }
        }
        Ok(())
    }
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
async fn input_route(State(m): State<Arc<Mock>>, Path(lease): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    m.log(format!("input_get:{lease}"));
    if let Err(e) = m.check_proof(&headers, &lease, "GET", &format!("/node/v1/inputs/{lease}"), None) {
        m.log(format!("bad_proof:{e}"));
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (body, delay) = {
        let mut l = m.leases.lock().unwrap();
        let Some(lease) = l.get_mut(&lease) else { return StatusCode::FORBIDDEN.into_response() };
        lease.gets += 1;
        if lease.gets > 1 {
            return StatusCode::GONE.into_response(); // token_used
        }
        (lease.input.clone(), lease.delay_ms)
    };
    tokio::time::sleep(Duration::from_millis(delay)).await;
    (StatusCode::OK, body).into_response()
}
async fn output_route(State(m): State<Arc<Mock>>, Path(lease): Path<String>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    m.log(format!("output_put:{lease}"));
    if let Err(e) = m.check_proof(&headers, &lease, "PUT", &format!("/node/v1/outputs/{lease}"), Some(&body)) {
        m.log(format!("bad_proof:{e}"));
        return StatusCode::UNAUTHORIZED;
    }
    match m.leases.lock().unwrap().get_mut(&lease) {
        Some(l) if l.output.is_none() => {
            l.output = Some(body.to_vec());
            StatusCode::OK
        }
        _ => StatusCode::GONE,
    }
}

async fn ws_route(ws: WebSocketUpgrade, State(m): State<Arc<Mock>>) -> impl IntoResponse {
    ws.protocols(["pool.node.v1"]).on_upgrade(move |socket| async move {
        let n = m.connections.fetch_add(1, Ordering::SeqCst);
        let r = if n == 0 { script(socket, m.clone()).await } else { replay_script(socket, m.clone()).await };
        if r.is_err() || n > 0 {
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
            let m = tokio::time::timeout(Duration::from_secs(30), self.ws.recv())
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

struct Ctx {
    device_id: String,
    device_key_id: String,
    model_hash: [u8; 32],
    model_id: String,
    input_format: String,
}

static CTX: std::sync::OnceLock<Ctx> = std::sync::OnceLock::new();
static IDLE_S: AtomicU64 = AtomicU64::new(3600);

fn envelope(lease_id: &str, job_id: &str, input: &[u8]) -> LeaseEnvelope {
    let c = CTX.get().unwrap();
    let now = now_ms();
    LeaseEnvelope {
        job_id: job_id.into(),
        lease_id: lease_id.into(),
        device_id: c.device_id.clone(),
        device_key_id: c.device_key_id.clone(),
        model_id: c.model_id.clone(),
        model_hash: c.model_hash,
        input_sha256: sha256(input),
        input_format: c.input_format.clone(),
        input_bytes: input.len() as u64,
        unit_type: "token".into(),
        issued_at: now,
        deadline: now + 60_000,
        language: None,
    }
}

fn grant(env: &LeaseEnvelope) -> SB {
    let v = pool_runner::testutil::vault();
    SB::LeaseGrant(pb::LeaseGrant {
        job_id: env.job_id.clone(),
        lease_id: env.lease_id.clone(),
        lease_envelope: v.sign_envelope(env),
        input_url: format!("{}/node/v1/inputs/{}?t=tok-{}", BASE.get().unwrap(), env.lease_id, uuid()),
        output_url: format!("{}/node/v1/outputs/{}?t=tok-{}", BASE.get().unwrap(), env.lease_id, uuid()),
        lease_deadline_ms: env.deadline as i64 - 1000,
    })
}

static BASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn offer(job_id: &str, model_hash: &[u8]) -> SB {
    let c = CTX.get().unwrap();
    SB::Offer(pb::Offer { job_id: job_id.into(), model_id: c.model_id.clone(), model_hash: model_hash.to_vec(), est_units: 10, deadline_ms: (now_ms() + 60_000) as i64 })
}

async fn script(ws: WebSocket, m: Arc<Mock>) -> Result<(), String> {
    let c = CTX.get().unwrap();
    let vault = pool_runner::testutil::vault();
    let mut hub = Hub { ws, seq: 0, inbound_seq: 0 };

    // 1. session proof
    let nonce: Vec<u8> = (0..32).map(|_| rand_byte()).collect();
    *m.first_nonce.lock().unwrap() = nonce.clone();
    hub.send(SB::Challenge(pb::Challenge { nonce: nonce.clone(), server_time_ms: now_ms() as i64, protocol_version: "pool.node.v1".into() })).await?;
    let NB::Hello(h) = hub.recv(false).await? else { return Err("expected Hello".into()) };
    let s = cose::verify_sign1(&h.hello_sig, &m.device_key(), ot::HELLO).map_err(|e| format!("hello sig: {e}"))?;
    let hc = HelloClaims::from_value(&s.claims).map_err(|e| e.to_string())?;
    if hc.nonce.to_vec() != nonce || hc.tls_exporter != [0u8; 32] || hc.device_id != c.device_id || h.device_key_id != c.device_key_id {
        return Err(format!("hello claims wrong: {hc:?}"));
    }
    if hc.ts.abs_diff(now_ms()) > 60_000 {
        return Err("hello ts".into());
    }
    m.log("hello_ok");
    hub.send(SB::Welcome(pb::Welcome { session_id: uuid(), session_expires_ms: (now_ms() + 3_600_000) as i64, heartbeat_interval_s: 30, server_time_ms: now_ms() as i64 })).await?;

    // 2. model hint -> cached
    hub.send(SB::ModelHint(pb::ModelHint { model_id: c.model_id.clone(), version: "1".into(), manifest_url: format!("/node/v1/manifests/{}/1", c.model_id) })).await?;
    loop {
        if let NB::Heartbeat(hb) = hub.recv(true).await? {
            if hb.accepting_work && hb.cached_models.iter().any(|cm| cm.model_hash == c.model_hash) {
                break;
            }
        }
    }
    m.log("model_cached");

    // 3. uncached model -> decline; a grant for it is never fetched
    let j0 = uuid();
    hub.send(offer(&j0, &[0xAB; 32])).await?;
    match hub.recv(false).await? {
        NB::Decline(d) if d.job_id == j0 && d.reason == pb::DeclineReason::ModelNotCached as i32 => {}
        other => return Err(format!("expected Decline(MODEL_NOT_CACHED), got {other:?}")),
    }
    let l0 = uuid();
    let in0 = br#"{"inputs":["never fetched"]}"#.to_vec();
    m.leases.lock().unwrap().insert(l0.clone(), Lease { input: in0.clone(), gets: 0, delay_ms: 0, output: None });
    hub.send(grant(&envelope(&l0, &j0, &in0))).await?;

    // 4. accepted job end to end
    let j1 = uuid();
    let l1 = uuid();
    let in1 = br#"{"inputs":["hello world","we pay for verified work only"]}"#.to_vec();
    let t_offer = Instant::now();
    hub.send(offer(&j1, &c.model_hash)).await?;
    match hub.recv(false).await? {
        NB::Accept(a) if a.job_id == j1 => {}
        other => return Err(format!("expected Accept, got {other:?}")),
    }
    if t_offer.elapsed() > Duration::from_secs(5) {
        return Err("accept later than 5 s".into());
    }
    if m.events.lock().unwrap().iter().any(|e| e.starts_with("input_get")) {
        return Err("input fetched before any lease was granted".into());
    }
    m.log(format!("accepted:{j1}"));
    m.leases.lock().unwrap().insert(l1.clone(), Lease { input: in1.clone(), gets: 0, delay_ms: 0, output: None });
    let env1 = envelope(&l1, &j1, &in1);
    hub.send(grant(&env1)).await?;
    let res = match hub.recv(false).await? {
        NB::Result(r) => r,
        other => return Err(format!("expected Result, got {other:?} events={:?}", m.events.lock().unwrap())),
    };
    let s = cose::verify_sign1(&res.result_sig, &m.device_key(), ot::RESULT_CLAIMS).map_err(|e| format!("result sig: {e}"))?;
    let rc = ResultClaims::from_value(&s.claims).map_err(|e| e.to_string())?;
    let stored = m.leases.lock().unwrap().get(&l1).and_then(|l| l.output.clone()).ok_or("no output stored")?;
    if rc.job_id != j1 || rc.lease_id != l1 || rc.model_hash != c.model_hash || rc.input_sha256 != sha256(&in1) || rc.output_sha256 != sha256(&stored) || rc.t_end < rc.t_start {
        return Err(format!("result claims wrong: {rc:?}"));
    }
    let out: serde_json::Value = serde_json::from_slice(&stored).map_err(|e| e.to_string())?;
    if out["embeddings"].as_array().map(|a| a.len()) != Some(2) {
        return Err(format!("bad output {out}"));
    }
    // the server's closed-object check (cddl 1.1.0 EmbedResult): exactly model_id, dim, embeddings
    let ctx = pool_proto::outputs::OutputContext { model_id: &c.model_id, duration_s: None, n_inputs: Some(2) };
    pool_proto::outputs::check_output(pool_proto::EMBED_RESULT_FORMAT, &stored, ctx).map_err(|e| format!("{e}: {out}"))?;
    if out.as_object().map(|o| o.len()) != Some(3) {
        return Err(format!("output has extra keys: {out}"));
    }
    hub.send(SB::ResultReceipt(pb::ResultReceipt { job_id: j1.clone(), lease_id: l1.clone(), status: pb::ReceiptStatus::Received as i32 })).await?;
    m.log("result_ok");

    // 5. replayed grant: ignored, never fetched twice
    hub.send(grant(&env1)).await?;

    // 6. benchmark
    let bench_input = br#"{"inputs":["the cat sat on the mat","vouch embed this text"]}"#.to_vec();
    *m.bench_bundle.lock().unwrap() = bench_input.clone();
    let w = BenchmarkWorkload {
        benchmark_id: uuid(),
        device_id: c.device_id.clone(),
        device_key_id: c.device_key_id.clone(),
        model_id: c.model_id.clone(),
        model_hash: c.model_hash,
        bundle_sha256: sha256(&bench_input),
        nonce: [5; 32],
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
    let s = cose::verify_sign1(&br.result_sig, &m.device_key(), ot::BENCHMARK_RESULT).map_err(|e| format!("bench sig: {e}"))?;
    let b = BenchmarkResult::from_value(&s.claims).map_err(|e| e.to_string())?;
    if b.workload_sha256 != sha256(&wbytes) || b.nonce != [5; 32] || b.segments.is_empty() || b.t_end - b.t_start < 2000 || b.device_key_id != c.device_key_id {
        return Err(format!("benchmark result wrong: {b:?}"));
    }
    hub.send(SB::BenchmarkReceipt(pb::BenchmarkReceipt { benchmark_id: w.benchmark_id.clone(), status: 1 })).await?;
    m.log(format!("bench_ok:{}", b.segments.len()));

    // 7. pre-emption: the user returns while the job is in flight
    let j2 = uuid();
    let l2 = uuid();
    let in2 = br#"{"inputs":["a"]}"#.to_vec();
    hub.send(offer(&j2, &c.model_hash)).await?;
    match hub.recv(false).await? {
        NB::Accept(a) if a.job_id == j2 => {}
        other => return Err(format!("expected Accept(j2), got {other:?}")),
    }
    m.leases.lock().unwrap().insert(l2.clone(), Lease { input: in2.clone(), gets: 0, delay_ms: 2500, output: None });
    hub.send(grant(&envelope(&l2, &j2, &in2))).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t_user = Instant::now();
    IDLE_S.store(0, Ordering::SeqCst); // user is back
    match hub.recv(false).await? {
        NB::Abandon(a) if a.job_id == j2 && a.reason == pb::AbandonReason::Preempted as i32 => {}
        other => return Err(format!("expected Abandon(PREEMPTED), got {other:?}")),
    }
    let took = t_user.elapsed();
    if took > Duration::from_secs(5) {
        return Err(format!("pre-emption took {took:?} (> 5 s)"));
    }
    m.log(format!("preempted_in_ms:{}", took.as_millis()));
    // while the user is active, new offers are declined
    let j3 = uuid();
    hub.send(offer(&j3, &c.model_hash)).await?;
    match hub.recv(false).await? {
        NB::Decline(d) if d.job_id == j3 && d.reason == pb::DeclineReason::UserActive as i32 => {}
        other => return Err(format!("expected Decline(USER_ACTIVE), got {other:?}")),
    }
    IDLE_S.store(3600, Ordering::SeqCst);

    // 7b. a running benchmark stopped because the user came back is reported as
    // BenchmarkResponse{accept: false, USER_ACTIVE} after the earlier accept (no BenchmarkResult)
    tokio::time::sleep(Duration::from_millis(1500)).await; // governor sees the idle machine again
    let w2 = BenchmarkWorkload { benchmark_id: uuid(), nonce: [6; 32], issued_at: now_ms(), expires_at: now_ms() + 600_000, ..w.clone() };
    let w2bytes = vault.sign_workload(&w2);
    hub.send(SB::BenchmarkOffer(pb::BenchmarkOffer { benchmark_id: w2.benchmark_id.clone(), workload: w2bytes, bundle_url: "/bench/bundle".into(), est_duration_s: 1200 })).await?;
    match hub.recv(false).await? {
        NB::BenchmarkResponse(r) if r.accept && r.benchmark_id == w2.benchmark_id => {}
        other => return Err(format!("expected BenchmarkResponse(accept) for the 2nd benchmark, got {other:?}")),
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    IDLE_S.store(0, Ordering::SeqCst);
    match hub.recv(false).await? {
        NB::BenchmarkResponse(r) if !r.accept && r.benchmark_id == w2.benchmark_id && r.reason == pb::DeclineReason::UserActive as i32 => {}
        other => return Err(format!("expected BenchmarkResponse(accept=false, USER_ACTIVE), got {other:?}")),
    }
    IDLE_S.store(3600, Ordering::SeqCst);
    m.log("bench_stopped");

    // no-input-before-Accept bookkeeping: the uncached/declined job's lease was never fetched; the accepted one exactly once
    {
        let l = m.leases.lock().unwrap();
        if l[&l0].gets != 0 {
            return Err("declined job's input was fetched".into());
        }
        if l[&l1].gets != 1 {
            return Err(format!("input fetched {} times", l[&l1].gets));
        }
    }
    if m.events.lock().unwrap().iter().any(|e| e.starts_with("bad_proof")) {
        return Err(format!("bad lease proof seen: {:?}", m.events.lock().unwrap()));
    }

    // 8. goodbye with reconnect
    hub.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 1 })).await?;
    m.log("goodbye_sent");
    Ok(())
}

/// Second connection: replay the first Challenge nonce. The node must not answer with a Hello.
async fn replay_script(ws: WebSocket, m: Arc<Mock>) -> Result<(), String> {
    let mut hub = Hub { ws, seq: 0, inbound_seq: 0 };
    let nonce = m.first_nonce.lock().unwrap().clone();
    hub.send(SB::Challenge(pb::Challenge { nonce, server_time_ms: now_ms() as i64, protocol_version: "pool.node.v1".into() })).await?;
    match tokio::time::timeout(Duration::from_secs(5), hub.recv(true)).await {
        Ok(Ok(NB::Hello(_))) => Err("node answered a replayed challenge nonce".into()),
        _ => {
            m.log("replayed_nonce_refused");
            Ok(())
        }
    }
}

fn rand_byte() -> u8 {
    let mut b = [0u8; 1];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b[0]
}

fn runner_exe() -> std::path::PathBuf {
    // Build the runner binary (no-op when fresh) and locate it in the same target dir as this test.
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "pool-runner", "--bin", "pool-runner"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("cargo build pool-runner");
    assert!(status.success());
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    dir.join(if cfg!(windows) { "pool-runner.exe" } else { "pool-runner" })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_against_mock_engine() {
    let _ = tracing_subscriber::fmt().with_env_filter("info,pool_core::runner_client=debug").with_test_writer().try_init();
    let vault = pool_runner::testutil::vault(); // installs dev trust roots for agent + runner
    let fx = pool_runner::testutil::bundle_fixture(&pool_runner::testutil::tiny_bert_files());
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
    BASE.set(format!("http://{addr}")).unwrap();

    let data = tempfile::tempdir().unwrap();
    let cfg = Config {
        engine_ws_url: format!("ws://{addr}/node/v1/connect"),
        vault_url: format!("http://{addr}"),
        web_url: "http://127.0.0.1:3000".into(),
        dev: true,
        bench_duration_override_s: Some(2),
        runner_path: Some(runner_exe()),
        prefer_tpm: false,
        ..Config::default()
    };
    let platform: Arc<dyn Fn() -> Readings + Send + Sync> =
        Arc::new(|| Readings { idle_s: Some(IDLE_S.load(Ordering::SeqCst)), on_ac: Some(true), ..Default::default() });
    let agent = Agent::with_platform(data.path().into(), cfg, platform).unwrap();
    let device_id = uuid();
    *m.device_spki.lock().unwrap() = agent.key().spki_der();
    CTX.set(Ctx {
        device_id: device_id.clone(),
        device_key_id: agent.key().device_key_id(),
        model_hash: fx.model_hash,
        model_id: fx.manifest.model_id.clone(),
        input_format: fx.manifest.input_format.clone(),
    })
    .ok()
    .unwrap();
    agent.set_enrollment(&device_id, "capped");
    let run = tokio::spawn(agent.clone().run());

    let deadline = Instant::now() + Duration::from_secs(120);
    let outcome = loop {
        if let Some(r) = m.result.lock().unwrap().take() {
            break r;
        }
        if Instant::now() > deadline {
            break Err(format!("timeout; events={:?}; status={:?}", m.events.lock().unwrap(), agent.status.get()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    run.abort();
    let events = m.events.lock().unwrap().clone();
    eprintln!("events: {events:?}");
    outcome.unwrap();
    for e in ["hello_ok", "model_cached", "result_ok", "goodbye_sent", "replayed_nonce_refused"] {
        assert!(events.iter().any(|x| x == e), "missing {e}: {events:?}");
    }
    assert!(events.iter().any(|x| x.starts_with("bench_ok")));
    assert!(events.iter().any(|x| x.starts_with("preempted_in_ms")));
    // the KeySet version seen is persisted for rollback protection
    let st = pool_core::config::State::load(data.path());
    assert_eq!(st.keyset_max_version, 3);
}
