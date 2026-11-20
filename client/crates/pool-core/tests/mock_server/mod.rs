//! Scripted mock job server + key/manifest/bundle/input/output routes, for the robustness and
//! soak tests. Unlike `mock_engine.rs` it is driven per connection by a test-supplied script, keeps a server clock
//! that can be skewed against the local one, and can drop the TCP connection abruptly.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use pool_proto::objects::{HelloClaims, LeaseEnvelope, LeaseProof, ResultClaims};
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use pool_proto::{cose, keys, now_ms, object_types as ot, sha256};
use prost::Message as _;

pub type Script = Box<dyn FnOnce(Hub, Arc<Mock>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send>;

pub struct Lease {
    pub input: Vec<u8>,
    pub gets: usize,
    pub delay_ms: u64,
    pub output: Option<Vec<u8>>,
    pub puts: usize,
}

#[derive(Default)]
pub struct Mock {
    pub device_spki: Mutex<Vec<u8>>,
    pub keyset: Mutex<Vec<u8>>,
    pub manifest: Mutex<Vec<u8>>,
    pub files: Mutex<Vec<(String, Vec<u8>)>>,
    pub leases: Mutex<HashMap<String, Lease>>,
    pub proof_nonces: Mutex<HashSet<Vec<u8>>>,
    pub problems: Mutex<Vec<String>>,
    pub connections: AtomicUsize,
    pub scripts: Mutex<VecDeque<Script>>,
    pub results: Mutex<Vec<Result<(), String>>>,
    /// server clock = local clock + skew (ms)
    pub skew_ms: AtomicI64,
    pub device_id: Mutex<String>,
    pub device_key_id: Mutex<String>,
    pub model_hash: Mutex<[u8; 32]>,
    pub model_id: Mutex<String>,
    pub input_format: Mutex<String>,
    pub base: Mutex<String>,
    /// Consent audit: every HTTP body the node sent to the server side (frames are in [`RAW`]).
    pub raw: Mutex<Vec<Vec<u8>>>,
    /// Bytes served at `/bench/bundle` (benchmark workloads).
    pub bench_bundle: Mutex<Vec<u8>>,
    /// Soak mode: forget finished leases and captured frames.
    pub prune: std::sync::atomic::AtomicBool,
}

impl Mock {
    pub fn problem(&self, p: impl Into<String>) {
        self.problems.lock().unwrap().push(p.into());
    }
    pub fn now(&self) -> u64 {
        pool_core::clock::apply(now_ms(), self.skew_ms.load(Ordering::SeqCst))
    }
    pub fn device_key(&self) -> p256::ecdsa::VerifyingKey {
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
        // the server's rule (config.proof_skew_s = 60), on the SERVER clock
        if p.ts.abs_diff(self.now()) > 60_000 {
            return Err(format!("stale proof: ts {} vs server {}", p.ts, self.now()));
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

    pub fn envelope(&self, lease_id: &str, job_id: &str, input: &[u8]) -> LeaseEnvelope {
        let now = self.now();
        LeaseEnvelope {
            job_id: job_id.into(),
            lease_id: lease_id.into(),
            device_id: self.device_id.lock().unwrap().clone(),
            device_key_id: self.device_key_id.lock().unwrap().clone(),
            model_id: self.model_id.lock().unwrap().clone(),
            model_hash: *self.model_hash.lock().unwrap(),
            input_sha256: sha256(input),
            input_format: self.input_format.lock().unwrap().clone(),
            input_bytes: input.len() as u64,
            unit_type: "token".into(),
            issued_at: now,
            deadline: now + 60_000,
            language: None,
        }
    }

    pub fn grant(&self, env: &LeaseEnvelope) -> SB {
        let v = pool_runner::testutil::vault();
        let base = self.base.lock().unwrap().clone();
        SB::LeaseGrant(pb::LeaseGrant {
            job_id: env.job_id.clone(),
            lease_id: env.lease_id.clone(),
            lease_envelope: v.sign_envelope(env),
            input_url: format!("{base}/node/v1/inputs/{}?t=tok-{}", env.lease_id, uuid()),
            output_url: format!("{base}/node/v1/outputs/{}?t=tok-{}", env.lease_id, uuid()),
            lease_deadline_ms: env.deadline as i64 - 1000,
        })
    }

    pub fn offer(&self, job_id: &str) -> SB {
        SB::Offer(pb::Offer {
            job_id: job_id.into(),
            model_id: self.model_id.lock().unwrap().clone(),
            model_hash: self.model_hash.lock().unwrap().to_vec(),
            est_units: 10,
            deadline_ms: (self.now() + 60_000) as i64,
        })
    }

    pub fn add_lease(&self, lease_id: &str, input: Vec<u8>, delay_ms: u64) {
        self.leases.lock().unwrap().insert(lease_id.into(), Lease { input, gets: 0, delay_ms, output: None, puts: 0 });
    }
}

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub struct Hub {
    pub ws: WebSocket,
    pub seq: u64,
    pub inbound_seq: u64,
    pub raw: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Hub {
    pub async fn send(&mut self, body: SB) -> Result<(), String> {
        self.seq += 1;
        let bytes = pb::ServerMessage { seq: self.seq, body: Some(body) }.encode_to_vec();
        self.ws.send(AxMsg::Binary(bytes.into())).await.map_err(|e| e.to_string())
    }
    /// Next node message other than Heartbeat (unless `want_heartbeat`).
    pub async fn recv(&mut self, want_heartbeat: bool) -> Result<NB, String> {
        self.recv_within(want_heartbeat, Duration::from_secs(30)).await
    }
    pub async fn recv_within(&mut self, want_heartbeat: bool, limit: Duration) -> Result<NB, String> {
        loop {
            let m = tokio::time::timeout(limit, self.ws.recv())
                .await
                .map_err(|_| "timeout waiting for node message".to_string())?
                .ok_or("connection closed")?
                .map_err(|e| e.to_string())?;
            let AxMsg::Binary(b) = m else { continue };
            self.raw.lock().unwrap().push(b.to_vec());
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

    /// Challenge -> Hello (checked on the server clock, as the server does: |ts - now| <= 60 s) -> Welcome.
    pub async fn handshake(&mut self, m: &Mock) -> Result<HelloClaims, String> {
        self.handshake_hb(m, 30).await
    }

    pub async fn handshake_hb(&mut self, m: &Mock, heartbeat_interval_s: u32) -> Result<HelloClaims, String> {
        let nonce: Vec<u8> = (0..32).map(|_| rand_byte()).collect();
        self.send(SB::Challenge(pb::Challenge { nonce: nonce.clone(), server_time_ms: m.now() as i64, protocol_version: "pool.node.v1".into() })).await?;
        let NB::Hello(h) = self.recv(false).await? else { return Err("expected Hello".into()) };
        let s = cose::verify_sign1(&h.hello_sig, &m.device_key(), ot::HELLO).map_err(|e| format!("hello sig: {e}"))?;
        let hc = HelloClaims::from_value(&s.claims).map_err(|e| e.to_string())?;
        if hc.nonce.to_vec() != nonce {
            return Err("hello nonce".into());
        }
        if hc.ts.abs_diff(m.now()) > 60_000 {
            return Err(format!("Hello.ts {} is {} ms off the server clock (vault refuses > 60 s)", hc.ts, hc.ts.abs_diff(m.now())));
        }
        self.send(SB::Welcome(pb::Welcome { session_id: uuid(), session_expires_ms: (m.now() + 3_600_000) as i64, heartbeat_interval_s, server_time_ms: m.now() as i64 })).await?;
        Ok(hc)
    }

    /// ModelHint, then wait for a heartbeat announcing the model.
    pub async fn ensure_cached(&mut self, m: &Mock) -> Result<(), String> {
        let model_id = m.model_id.lock().unwrap().clone();
        let hash = *m.model_hash.lock().unwrap();
        self.send(SB::ModelHint(pb::ModelHint { model_id: model_id.clone(), version: "1".into(), manifest_url: format!("/node/v1/manifests/{model_id}/1") })).await?;
        loop {
            if let NB::Heartbeat(hb) = self.recv(true).await? {
                if hb.accepting_work && hb.cached_models.iter().any(|cm| cm.model_hash == hash) {
                    return Ok(());
                }
            }
        }
    }

    /// One complete job: Offer -> Accept -> LeaseGrant -> Result, all checked like the server's verifier (signature,
    /// hashes, and t_start/t_end inside [accepted - 5 s, result + 5 s] on the server clock). Returns the output.
    pub async fn job(&mut self, m: &Mock, input: Vec<u8>) -> Result<Vec<u8>, String> {
        self.job_with_receipt(m, input, pb::ReceiptStatus::Received).await
    }

    /// Close the WebSocket with `code` (e.g. 1013 "try again later") without saying anything else.
    pub async fn close_with(&mut self, code: u16) -> Result<(), String> {
        let frame = axum::extract::ws::CloseFrame { code, reason: "busy".into() };
        self.ws.send(AxMsg::Close(Some(frame))).await.map_err(|e| e.to_string())
    }

    /// [`Hub::job`] answered with the given receipt status.
    pub async fn job_with_receipt(&mut self, m: &Mock, input: Vec<u8>, receipt: pb::ReceiptStatus) -> Result<Vec<u8>, String> {
        let (j, l) = (uuid(), uuid());
        self.send(m.offer(&j)).await?;
        match self.recv(false).await? {
            NB::Accept(a) if a.job_id == j => {}
            other => return Err(format!("expected Accept, got {other:?}")),
        }
        let accepted_at = m.now();
        m.add_lease(&l, input.clone(), 0);
        let env = m.envelope(&l, &j, &input);
        self.send(m.grant(&env)).await?;
        let res = match self.recv(false).await? {
            NB::Result(r) => r,
            other => return Err(format!("expected Result, got {other:?}")),
        };
        let result_at = m.now();
        let s = cose::verify_sign1(&res.result_sig, &m.device_key(), ot::RESULT_CLAIMS).map_err(|e| format!("result sig: {e}"))?;
        let rc = ResultClaims::from_value(&s.claims).map_err(|e| e.to_string())?;
        let out = m.leases.lock().unwrap().get(&l).and_then(|x| x.output.clone()).ok_or("no output stored")?;
        if rc.job_id != j || rc.lease_id != l || rc.input_sha256 != sha256(&input) || rc.output_sha256 != sha256(&out) {
            return Err(format!("result claims wrong: {rc:?}"));
        }
        // the server's result-time tolerance: 5 s
        if rc.t_start + 5_000 < accepted_at || rc.t_end > result_at + 5_000 || rc.t_end < rc.t_start {
            return Err(format!(
                "result times outside the lease window on the server clock: t_start {} t_end {} accepted {} result {} (vault refuses: unpaid)",
                rc.t_start, rc.t_end, accepted_at, result_at
            ));
        }
        self.send(SB::ResultReceipt(pb::ResultReceipt { job_id: j, lease_id: l.clone(), status: receipt as i32 })).await?;
        if m.prune.load(Ordering::SeqCst) {
            // soak: keep the mock's own memory flat, so growth measured in this process is the agent's
            m.leases.lock().unwrap().remove(&l);
            let mut n = m.proof_nonces.lock().unwrap();
            if n.len() > 4096 {
                n.clear();
            }
            self.raw.lock().unwrap().clear();
            m.raw.lock().unwrap().clear();
        }
        Ok(out)
    }
}

pub fn rand_byte() -> u8 {
    let mut b = [0u8; 1];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b[0]
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
    if let Err(e) = m.check_proof(&headers, &lease, "GET", &format!("/node/v1/inputs/{lease}"), None) {
        m.problem(format!("bad input proof: {e}"));
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (body, delay) = {
        let mut l = m.leases.lock().unwrap();
        let Some(lease) = l.get_mut(&lease) else { return StatusCode::FORBIDDEN.into_response() };
        lease.gets += 1;
        if lease.gets > 1 {
            return StatusCode::GONE.into_response();
        }
        (lease.input.clone(), lease.delay_ms)
    };
    tokio::time::sleep(Duration::from_millis(delay)).await;
    (StatusCode::OK, body).into_response()
}
async fn output_route(State(m): State<Arc<Mock>>, Path(lease): Path<String>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    m.raw.lock().unwrap().push(body.to_vec());
    if let Err(e) = m.check_proof(&headers, &lease, "PUT", &format!("/node/v1/outputs/{lease}"), Some(&body)) {
        m.problem(format!("bad output proof: {e}"));
        return StatusCode::UNAUTHORIZED;
    }
    match m.leases.lock().unwrap().get_mut(&lease) {
        Some(l) if l.output.is_none() => {
            l.puts += 1;
            l.output = Some(body.to_vec());
            StatusCode::OK
        }
        _ => StatusCode::GONE,
    }
}
async fn ws_route(ws: WebSocketUpgrade, State(m): State<Arc<Mock>>) -> impl IntoResponse {
    ws.protocols(["pool.node.v1"]).on_upgrade(move |socket| async move {
        m.connections.fetch_add(1, Ordering::SeqCst);
        let script = m.scripts.lock().unwrap().pop_front();
        let r = match script {
            Some(s) => s(Hub { ws: socket, seq: 0, inbound_seq: 0, raw: RAW.clone() }, m.clone()).await,
            None => {
                // no script: hold the connection (the test is over or waiting)
                let mut ws = socket;
                while let Some(Ok(_)) = ws.recv().await {}
                Ok(())
            }
        };
        m.results.lock().unwrap().push(r);
    })
}

pub fn runner_exe() -> std::path::PathBuf {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "pool-runner", "--bin", "pool-runner"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("cargo build pool-runner");
    assert!(status.success());
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(if cfg!(windows) { "pool-runner.exe" } else { "pool-runner" })
}

pub static IDLE_S: AtomicU64 = AtomicU64::new(3600);

/// Every raw node frame of the whole test process (all connections).
pub static RAW: std::sync::LazyLock<Arc<Mutex<Vec<Vec<u8>>>>> = std::sync::LazyLock::new(Default::default);

/// Start the mock and an enrolled agent (software key, dev mode) pointed at it.
pub async fn start(data: &std::path::Path) -> (Arc<Mock>, Arc<Agent>) {
    start_cfg(data, |_| {}).await
}

/// [`start`] with a hook to adjust the agent's config (e.g. the dev benchmark duration).
pub async fn start_cfg(data: &std::path::Path, adjust: impl FnOnce(&mut Config)) -> (Arc<Mock>, Arc<Agent>) {
    let vault = pool_runner::testutil::vault();
    let fx = pool_runner::testutil::bundle_fixture(&pool_runner::testutil::tiny_bert_files());
    let m = Arc::new(Mock::default());
    *m.keyset.lock().unwrap() = vault.keyset_bytes(3);
    *m.manifest.lock().unwrap() = fx.manifest_cose.clone();
    *m.files.lock().unwrap() = fx.manifest.files.iter().map(|f| (f.path.clone(), std::fs::read(fx.dir.path().join(&f.path)).unwrap())).collect();
    *m.model_hash.lock().unwrap() = fx.model_hash;
    *m.model_id.lock().unwrap() = fx.manifest.model_id.clone();
    *m.input_format.lock().unwrap() = fx.manifest.input_format.clone();
    let app = Router::new()
        .route("/node/v1/connect", get(ws_route))
        .route("/v1/keys", get(keys_route))
        .route("/node/v1/manifests/{m}/{v}", get(manifest_route))
        .route("/node/v1/bundles/{m}/{v}/{*p}", get(bundle_route))
        .route("/node/v1/inputs/{lease}", get(input_route))
        .route("/bench/bundle", get(bench_bundle_route))
        .route("/node/v1/outputs/{lease}", axum::routing::put(output_route))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    *m.base.lock().unwrap() = format!("http://{addr}");
    let mut cfg = Config {
        engine_ws_url: format!("ws://{addr}/node/v1/connect"),
        vault_url: format!("http://{addr}"),
        web_url: "http://127.0.0.1:3000".into(),
        dev: true,
        runner_path: Some(runner_exe()),
        prefer_tpm: false,
        ..Config::default()
    };
    adjust(&mut cfg);
    let platform: Arc<dyn Fn() -> Readings + Send + Sync> =
        Arc::new(|| Readings { idle_s: Some(IDLE_S.load(Ordering::SeqCst)), on_ac: Some(true), ..Default::default() });
    let agent = Agent::with_platform(data.into(), cfg, platform).unwrap();
    let device_id = uuid();
    *m.device_spki.lock().unwrap() = agent.key().spki_der();
    *m.device_id.lock().unwrap() = device_id.clone();
    *m.device_key_id.lock().unwrap() = agent.key().device_key_id();
    agent.set_enrollment(&device_id, "capped");
    // keep the fixture dir alive for the whole test process
    std::mem::forget(fx);
    (m, agent)
}

/// Wait until `n` connection scripts have finished; returns their results.
pub async fn wait_results(m: &Mock, n: usize, limit: Duration) -> Vec<Result<(), String>> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let r = m.results.lock().unwrap().clone();
        if r.len() >= n || tokio::time::Instant::now() > deadline {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Every file under `roots` modified at or after `since`, that contains `needle` (as bytes or UTF-16LE).
pub fn files_containing(roots: &[std::path::PathBuf], since: std::time::SystemTime, needle: &[u8]) -> Vec<std::path::PathBuf> {
    let utf16: Vec<u8> = String::from_utf8_lossy(needle).encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut hits = vec![];
    let mut stack: Vec<std::path::PathBuf> = roots.iter().filter(|r| r.exists()).cloned().collect();
    let mut scanned = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(p);
                continue;
            }
            let fresh = md.modified().map(|t| t >= since).unwrap_or(true);
            if !fresh || md.len() > 256 << 20 {
                continue;
            }
            scanned += 1;
            if let Ok(b) = std::fs::read(&p) {
                if b.windows(needle.len()).any(|w| w == needle) || b.windows(utf16.len()).any(|w| w == utf16.as_slice()) {
                    hits.push(p);
                }
            }
        }
    }
    eprintln!("disk audit: scanned {scanned} files changed since the test started");
    hits
}
