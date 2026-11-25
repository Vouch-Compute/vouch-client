//! Mock server 2.1.0 shared by the integration tests (`signin_enroll.rs`, `hw_ids.rs`).
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use p256::ecdsa::VerifyingKey;
use pool_core::agent::{Agent, SignIn};
use pool_core::config::Config;
use pool_proto::cbor::Value;
use pool_proto::{cose, keys, now_ms, object_types as ot};
use serde_json::{json, Value as J};

pub const ACCOUNT_ID: &str = "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f";

#[derive(Default)]
pub struct V {
    pub polls: AtomicUsize,
    pub nonce: Mutex<Vec<u8>>,
    pub challenge_id: Mutex<String>,
    pub scope: Mutex<String>,
    pub device_form: Mutex<HashMap<String, String>>,
    pub registered: Mutex<Option<J>>,
    pub registrations: AtomicUsize,
    pub problems: Mutex<Vec<String>>,
    /// device_id -> current device key
    pub devices: Mutex<HashMap<String, VerifyingKey>>,
    /// what `GET /v1/devices` lists
    pub listed: Mutex<Vec<J>>,
    /// a forced `POST /v1/devices` refusal: (status, code)
    pub refuse: Mutex<Option<(u16, String)>>,
    pub control_nonces: Mutex<HashSet<Vec<u8>>>,
    pub controls: Mutex<Vec<(String, Vec<u8>)>>,
    pub hw_reports: AtomicUsize,
    pub recovery: Mutex<Option<J>>,
    pub rotations: AtomicUsize,
    /// vault's T-213 rules for a release (non-dev) client with a software key: `key_attestation` must be
    /// `{format: "none", blob: null}`, and the signed `hw_ids` must carry at least two medium identifiers
    /// (`smbios_uuid`, `board_serial`, `disk_serial`, `gpu_uuid`), else `422 hw_ids_required`. vault applies the
    /// identifier rule to macOS and Windows; this mock applies it on every OS so the Linux CI checks the same path.
    pub t213: std::sync::atomic::AtomicBool,
    /// The refresh grant answers `400 invalid_grant` (an expired or revoked sign-in).
    pub refresh_refused: std::sync::atomic::AtomicBool,
    /// Enrollment challenges requested, and a delay before each answer (a slow server).
    pub challenges: AtomicUsize,
    pub challenge_delay_ms: std::sync::atomic::AtomicU64,
    /// A delay before `POST /v1/devices` registers (a slow answer to the registration itself).
    pub register_delay_ms: std::sync::atomic::AtomicU64,
    /// Refresh grants served, and the refresh tokens already used: a used one coming back is reuse, which revokes the
    /// sign-in as vault does (accounts/routes.py, refresh grant).
    pub refreshes: AtomicUsize,
    pub used_refresh: Mutex<HashSet<String>>,
    pub revoked: std::sync::atomic::AtomicBool,
    /// Lifetime of the access tokens the refresh grant issues (default 300 s when 0 is not set explicitly).
    pub access_ttl_s: Mutex<Option<u64>>,
    /// What `GET /v1/keys` serves (`None`: 404).
    pub keyset: Mutex<Option<Vec<u8>>>,
}

impl V {
    fn problem(&self, p: impl Into<String>) {
        self.problems.lock().unwrap().push(p.into());
    }
}

fn err(status: u16, code: &str) -> axum::response::Response {
    (StatusCode::from_u16(status).unwrap(), Json(json!({"error": {"code": code, "message": code, "request_id": "r"}}))).into_response()
}

async fn device_auth(State(v): State<Arc<V>>, Form(f): Form<HashMap<String, String>>) -> impl IntoResponse {
    *v.scope.lock().unwrap() = f.get("scope").cloned().unwrap_or_default();
    *v.device_form.lock().unwrap() = f.clone();
    Json(json!({"device_code": "dc-1", "user_code": "ABCD-EFGH", "verification_uri": "http://127.0.0.1:3000/app/link",
        "verification_uri_complete": "http://127.0.0.1:3000/app/link?user_code=ABCD-EFGH", "expires_in": 600, "interval": 1}))
}

async fn token(State(v): State<Arc<V>>, Form(f): Form<HashMap<String, String>>) -> axum::response::Response {
    match f.get("grant_type").map(String::as_str) {
        Some("refresh_token") => {
            if v.refresh_refused.load(Ordering::SeqCst) {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant", "error_description": "refresh token expired"}))).into_response();
            }
            let rt = f.get("refresh_token").cloned().unwrap_or_default();
            if v.revoked.load(Ordering::SeqCst) || !v.used_refresh.lock().unwrap().insert(rt) {
                v.revoked.store(true, Ordering::SeqCst);
                return err(400, "invalid_grant");
            }
            let n = v.refreshes.fetch_add(1, Ordering::SeqCst) + 2;
            let ttl = v.access_ttl_s.lock().unwrap().unwrap_or(300);
            return Json(json!({"access_token": format!("at-{n}"), "token_type": "Bearer", "expires_in": ttl, "refresh_token": format!("rt-{n}")}))
                .into_response();
        }
        Some("urn:ietf:params:oauth:grant-type:device_code") => {}
        _ => return err(400, "unsupported_grant_type"),
    }
    if v.polls.fetch_add(1, Ordering::SeqCst) == 0 {
        // the server's shape: 400 with the OAuth code in error.code
        return err(400, "authorization_pending");
    }
    let ttl = v.access_ttl_s.lock().unwrap().unwrap_or(300);
    Json(json!({"access_token": "at-1", "token_type": "Bearer", "expires_in": ttl, "refresh_token": "rt-1",
        "scope": "earnings:read devices:read devices:enroll"}))
    .into_response()
}

async fn challenge(State(v): State<Arc<V>>) -> impl IntoResponse {
    v.challenges.fetch_add(1, Ordering::SeqCst);
    let delay = v.challenge_delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let nonce: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7)).collect();
    *v.nonce.lock().unwrap() = nonce.clone();
    let challenge_id = uuid::Uuid::new_v4().to_string();
    *v.challenge_id.lock().unwrap() = challenge_id.clone();
    (StatusCode::CREATED, Json(json!({"challenge_id": challenge_id, "nonce": keys::b64(&nonce), "expires_at": "2099-01-01T00:00:00Z"})))
}

/// Exact COSE profile check: protected header `{1: -7, 4: kid}`, empty unprotected header, ES256 over Sig_structure,
/// payload deterministic CBOR. Returns the claims map. Written against the contract, not pool-proto's signer.
pub fn verify_cose(bytes: &[u8], key: &VerifyingKey, ty: &str) -> Result<Value, String> {
    let s = cose::parse_sign1(bytes, ty).map_err(|e| e.to_string())?;
    if s.kid != keys::device_key_id(key) {
        return Err("kid is not the device key id".into());
    }
    s.verify(key).map_err(|e| e.to_string())?;
    Ok(s.claims)
}

fn map_keys(v: &Value) -> Vec<String> {
    let Value::Map(m) = v else { return vec![] };
    let mut k: Vec<String> = m.iter().filter_map(|(k, _)| k.as_text().map(str::to_string)).collect();
    k.sort();
    k
}

fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    let Value::Map(m) = v else { return None };
    m.iter().find(|(x, _)| x.as_text() == Some(k)).map(|(_, v)| v)
}

async fn register(State(v): State<Arc<V>>, Json(b): Json<J>) -> axum::response::Response {
    let delay = v.register_delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    v.registrations.fetch_add(1, Ordering::SeqCst);
    let spki = keys::b64_decode(b["public_key"].as_str().unwrap_or("")).unwrap_or_default();
    let Ok(key) = keys::parse_spki(&spki) else {
        v.problem("public_key not P-256 SPKI");
        return err(422, "bad_key");
    };
    let (ch, nonce) = (v.challenge_id.lock().unwrap().clone(), v.nonce.lock().unwrap().clone());
    // nonce_sig: EnrollClaims
    match verify_cose(&keys::b64_decode(b["nonce_sig"].as_str().unwrap_or("")).unwrap_or_default(), &key, ot::ENROLL) {
        Ok(c) => {
            if map_keys(&c) != ["challenge_id", "nonce", "type"]
                || field(&c, "challenge_id") != Some(&Value::Text(ch.clone()))
                || field(&c, "nonce") != Some(&Value::Bytes(nonce.clone()))
            {
                v.problem(format!("EnrollClaims wrong: {c:?}"));
            }
        }
        Err(e) => v.problem(format!("nonce_sig: {e}")),
    }
    if b["challenge_id"].as_str() != Some(ch.as_str()) {
        v.problem("challenge_id");
    }
    let os = b["os"].as_str().unwrap_or("");
    let fmt = b["key_attestation"]["format"].as_str().unwrap_or("");
    let t213 = v.t213.load(Ordering::SeqCst);
    if t213 {
        if fmt != "none" || !b["key_attestation"]["blob"].is_null() {
            v.problem(format!("T-213: a software key must send format none with no blob, got {}", b["key_attestation"]));
        }
    } else if (os == "linux" && fmt != "none" && fmt != "tpm2") || (os == "windows" && fmt != "tpm2") || (os == "macos" && fmt != "apple_se") {
        v.problem(format!("attestation format {fmt} for {os}"));
    }
    let mut medium_ids = 0;
    for k in ["challenge_id", "hw_claims", "agent_version", "arch", "hw_ids", "hw_consent"] {
        if b.get(k).is_none() {
            v.problem(format!("missing {k}"));
        }
    }
    // 2.1.0: hw_ids signed by the new key; hw_consent is the in-app text's version and hash
    match verify_cose(&keys::b64_decode(b["hw_ids"].as_str().unwrap_or("")).unwrap_or_default(), &key, ot::HW_IDS) {
        Ok(c) => match pool_proto::objects::HwIdentifiers::from_value(&c) {
            Ok(h) if h.device_id == ch => {
                medium_ids = [h.smbios_uuid.is_some(), h.board_serial.is_some(), h.disk_serial.is_some(), !h.gpu_uuids.is_empty()]
                    .into_iter()
                    .filter(|x| *x)
                    .count();
            }
            Ok(h) => v.problem(format!("hw_ids device_id {} is not the challenge id", h.device_id)),
            Err(e) => v.problem(format!("hw_ids not a closed HwIdentifiers map: {e}")),
        },
        Err(e) => v.problem(format!("hw_ids: {e}")),
    }
    if b["hw_consent"]["text_sha256"].as_str() != Some(pool_core::hwids::consent_text_sha256().as_str())
        || b["hw_consent"]["version"].as_str() != Some(pool_core::hwids::CONSENT_VERSION)
    {
        v.problem(format!("hw_consent {}", b["hw_consent"]));
    }
    *v.registered.lock().unwrap() = Some(b.clone());
    if let Some((status, code)) = v.refuse.lock().unwrap().clone() {
        return err(status, &code);
    }
    if t213 && medium_ids < 2 {
        return err(422, "hw_ids_required");
    }
    if let Some(r) = b["replaces_device_id"].as_str() {
        if !v.listed.lock().unwrap().iter().any(|d| d["device_id"] == r) {
            return err(404, "not_found");
        }
    }
    let device_id = uuid::Uuid::new_v4().to_string();
    v.devices.lock().unwrap().insert(device_id.clone(), key);
    (StatusCode::CREATED, Json(json!({"device_id": device_id, "device_key_id": keys::device_key_id(&key), "tier": "probation", "trust_ceiling": "capped"})))
        .into_response()
}

async fn list_devices(State(v): State<Arc<V>>) -> impl IntoResponse {
    Json(json!({ "data": v.listed.lock().unwrap().clone() }))
}

async fn control(State(v): State<Arc<V>>, Path(id): Path<String>, Json(b): Json<J>) -> axum::response::Response {
    let Some(key) = v.devices.lock().unwrap().get(&id).copied() else { return err(404, "not_found") };
    let raw = keys::b64_decode(b["control"].as_str().unwrap_or("")).unwrap_or_default();
    let c = match verify_cose(&raw, &key, ot::DEVICE_CONTROL) {
        Ok(c) => c,
        Err(e) => {
            v.problem(format!("control: {e}"));
            return err(422, "signature_invalid");
        }
    };
    // exact closed map, deterministic (parse_sign1 already refused non-deterministic CBOR)
    if map_keys(&c) != ["action", "device_id", "nonce", "ts", "type"] {
        v.problem(format!("DeviceControl keys {:?}", map_keys(&c)));
    }
    let ok = pool_proto::objects::DeviceControl::from_value(&c);
    let Ok(dc) = ok else {
        v.problem("DeviceControl not closed".to_string());
        return err(422, "invalid");
    };
    if dc.device_id != id {
        return err(404, "not_found");
    }
    if dc.ts.abs_diff(now_ms()) > 60_000 {
        return err(422, "stale");
    }
    if !v.control_nonces.lock().unwrap().insert(dc.nonce.to_vec()) {
        return err(409, "nonce_used"); // replay
    }
    v.controls.lock().unwrap().push((dc.action.clone(), raw));
    if dc.action == "self_revoke" {
        v.devices.lock().unwrap().remove(&id);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn hw_ids(State(v): State<Arc<V>>, Path(id): Path<String>, Json(b): Json<J>) -> axum::response::Response {
    let Some(key) = v.devices.lock().unwrap().get(&id).copied() else { return err(404, "not_found") };
    match verify_cose(&keys::b64_decode(b["hw_ids"].as_str().unwrap_or("")).unwrap_or_default(), &key, ot::HW_IDS) {
        Ok(c) => match pool_proto::objects::HwIdentifiers::from_value(&c) {
            Ok(h) if h.device_id == id => {
                v.hw_reports.fetch_add(1, Ordering::SeqCst);
                StatusCode::NO_CONTENT.into_response()
            }
            _ => {
                v.problem("weekly hw_ids for another device or not closed");
                err(422, "invalid")
            }
        },
        Err(e) => {
            v.problem(format!("weekly hw_ids: {e}"));
            err(422, "signature_invalid")
        }
    }
}

async fn recovery_proof(State(v): State<Arc<V>>, Path(case): Path<String>, Json(b): Json<J>) -> axum::response::Response {
    let id = b["device_id"].as_str().unwrap_or("").to_string();
    let Some(key) = v.devices.lock().unwrap().get(&id).copied() else { return err(404, "not_found") };
    match verify_cose(&keys::b64_decode(b["proof"].as_str().unwrap_or("")).unwrap_or_default(), &key, ot::RECOVERY) {
        Ok(c) => match pool_proto::objects::RecoveryProof::from_value(&c) {
            Ok(p) if p.case_id == case && p.account_id == ACCOUNT_ID => {
                *v.recovery.lock().unwrap() = Some(json!({"case_id": p.case_id, "challenge": hex::encode(p.challenge)}));
                StatusCode::ACCEPTED.into_response()
            }
            _ => err(404, "not_found"),
        },
        Err(_) => err(404, "not_found"),
    }
}

async fn rotate(State(v): State<Arc<V>>, Path(id): Path<String>, Json(b): Json<J>) -> axum::response::Response {
    let Some(old) = v.devices.lock().unwrap().get(&id).copied() else { return err(404, "not_found") };
    let Ok(new) = keys::parse_spki(&keys::b64_decode(b["new_public_key"].as_str().unwrap_or("")).unwrap_or_default()) else {
        return err(422, "bad_key");
    };
    let want = pool_proto::objects::KeyRotationClaims {
        device_id: id.clone(),
        old_device_key_id: keys::device_key_id(&old),
        new_device_key_id: keys::device_key_id(&new),
    }
    .to_value();
    for (field, key) in [("old_key_sig", &old), ("new_key_sig", &new)] {
        match verify_cose(&keys::b64_decode(b[field].as_str().unwrap_or("")).unwrap_or_default(), key, ot::KEY_ROTATION) {
            Ok(c) if c == pool_proto::cbor::canonicalize(&want) => {}
            Ok(c) => v.problem(format!("{field} claims {c:?}")),
            Err(e) => v.problem(format!("{field}: {e}")),
        }
    }
    v.devices.lock().unwrap().insert(id, new);
    v.rotations.fetch_add(1, Ordering::SeqCst);
    (StatusCode::CREATED, Json(json!({"device_key_id": keys::device_key_id(&new)}))).into_response()
}

pub async fn spawn_vault() -> (Arc<V>, String) {
    let v = Arc::new(V::default());
    let app = Router::new()
        .route("/oauth2/device_authorization", post(device_auth))
        .route("/oauth2/token", post(token))
        .route("/v1/devices/enrollment-challenges", post(challenge))
        .route("/v1/devices", post(register).get(list_devices))
        .route("/v1/devices/{id}/control", post(control))
        .route("/v1/devices/{id}/hw-ids", post(hw_ids))
        .route("/v1/devices/{id}/key-rotations", post(rotate))
        .route("/v1/auth/recovery-cases/{case}/device-proof", post(recovery_proof))
        .route("/v1/me", get(|| async { Json(json!({"account_id": ACCOUNT_ID, "username": "alice"})) }))
        .route("/v1/keys", get(|State(v): State<Arc<V>>| async move {
            match v.keyset.lock().unwrap().clone() {
                Some(b) => ([("content-type", "application/cose")], b).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }))
        .with_state(v.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (v, format!("http://{addr}"))
}

pub fn new_agent(dir: &std::path::Path, vault_url: &str) -> Arc<Agent> {
    let cfg = Config { vault_url: vault_url.into(), prefer_tpm: false, ..Config::default() };
    let a = Agent::with_platform(dir.into(), cfg, Arc::new(pool_core::platform::Readings::default)).unwrap();
    a.set_hw_collector(fixture_collector());
    a
}

/// An agent as a release build behaves at enrollment: dev mode off (no dev attestation blob), software key.
pub fn release_mode_agent(dir: &std::path::Path, vault_url: &str) -> Arc<Agent> {
    let cfg = Config { vault_url: vault_url.into(), prefer_tpm: false, dev: false, ..Config::default() };
    let a = Agent::with_platform(dir.into(), cfg, Arc::new(pool_core::platform::Readings::default)).unwrap();
    a.set_hw_collector(fixture_collector());
    a
}

/// Fixture hardware: one physical NIC, one Docker bridge (filtered), sentinel serials.
pub fn fixture_collector() -> pool_core::hwids::Collector {
    use pool_core::hwids::{Medium, RawHw, RawNic};
    Arc::new(|| RawHw {
        smbios_uuid: Some("4C4C4544-0039-4810-8052-B4C04F4A3533".into()),
        board_serial: Some("BOARD-SENTINEL-7731".into()),
        disk_serial: Some("To be filled by O.E.M.".into()),
        os_install_id: Some("6f9619ff-8b86-d011-b42d-00c04fc964ff".into()),
        manufacturer: Some("Dell Inc.".into()),
        model: Some("XPS".into()),
        gpu_uuids: vec!["GPU-SENTINEL-1c2d".into()],
        nics: vec![
            RawNic {
                name: "Ethernet".into(),
                description: "Intel".into(),
                mac: Some([0x00, 0x1b, 0x21, 0xaa, 0x3f, 0x9a]),
                permanent_mac: Some([0x00, 0x1b, 0x21, 0xaa, 0x3f, 0x9a]),
                medium: Medium::Ethernet,
                virtual_: false,
                hardware: true,
            },
            RawNic { name: "docker0".into(), mac: Some([0x02, 0x42, 0xac, 0x11, 0, 1]), medium: Medium::Ethernet, virtual_: true, ..Default::default() },
        ],
        container: false,
        wsl: false,
    })
}

pub async fn wait_signin(agent: &Agent, done: impl Fn(&SignIn) -> bool) -> SignIn {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = agent.signin_state();
        if done(&s) {
            return s;
        }
        if let SignIn::Error { message, .. } = &s {
            panic!("sign-in failed: {message}");
        }
        assert!(Instant::now() < deadline, "timeout; state {s:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn consent(agent: &Agent, accept: bool) {
    agent.hw_consent_set(accept, &pool_core::hwids::consent_text_sha256()).await.unwrap();
}

pub async fn enrolled(dir: &std::path::Path) -> (Arc<V>, Arc<Agent>) {
    let (v, url) = spawn_vault().await;
    let agent = new_agent(dir, &url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    assert!(agent.device_id().is_some());
    (v, agent)
}

