//! The agent: ties identity, sign-in/enrollment, KeySet trust, the governor loop and the session loop
//! (with reconnect backoff) together, and serves the app's control requests.
//!
//! Contract 2.1.0 / node protocol 1.2.0 (M9-C):
//! * hardware identifiers only after the in-app consent; sent at enrollment and weekly ([`crate::hwids`]);
//! * the `tpm2` v2 attestation (credential activation) outside dev mode;
//! * device-key-signed `DeviceControl` (pause, resume, "Remove this device" with key and token wipe), "Replace existing
//!   device", "Recover my account" (`RecoveryProof`), "Repair device identity" (vouched key rotation).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use pool_proto::{now_ms, trust};
use rand_core::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::config::{Config, HwConsent, State};
use crate::governor::{Decision, Governor, Settings};
use crate::hwids;
use crate::identity::{self, DeviceKey, KeyStorage};
use crate::jobs::NodeIdentity;
use crate::lease::NonceBook;
use crate::platform::{self, Readings};
use crate::registry::Registry;
use crate::runner_client::RunnerClient;
use crate::session::{self, SessionEnd};
use crate::status::{Connection, Status, StatusHub};
use crate::vault::{DeviceCode, TokenPoll, VaultClient, VaultError};

/// An own device the user may be reinstalling ("Replace '<name>'").
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReplaceCandidate {
    pub device_id: String,
    pub name: String,
    pub last_seen_day: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SignIn {
    Idle,
    Pending { user_code: String, verification_uri: String, verification_uri_complete: String, expires_at_ms: u64 },
    /// Signed in; the hardware-identifier consent is needed before this computer can be registered.
    ConsentRequired,
    /// Signed in; the account has devices of this OS: the user says whether this is one of them (a reinstall).
    ChooseReplace { candidates: Vec<ReplaceCandidate> },
    Enrolling,
    Done,
    /// Enrollment refused for a reason the user can act on (`code` is the server's error code).
    Blocked { code: String, message: String },
    Error { message: String },
}

pub struct Agent {
    pub data_dir: PathBuf,
    pub cfg: Config,
    state: Mutex<State>,
    key: RwLock<Arc<dyn DeviceKey>>,
    vault: VaultClient,
    http: reqwest::Client,
    registry: Arc<Registry>,
    runner: Arc<RunnerClient>,
    pub status: Arc<StatusHub>,
    decision_tx: watch::Sender<Decision>,
    settings_tx: watch::Sender<Settings>,
    /// Bumped to end the live session at once (the device identity was wiped or rotated).
    stop_tx: watch::Sender<u64>,
    access: Mutex<Option<(String, u64)>>,
    signin: Mutex<SignIn>,
    platform: Arc<dyn Fn() -> Readings + Send + Sync>,
    hw_collector: Mutex<hwids::Collector>,
    seen_nonces: Arc<Mutex<VecDeque<Vec<u8>>>>,
    lease_nonces: Arc<NonceBook>,
    worked_ms: Arc<AtomicU64>,
    wake: tokio::sync::Notify,
    /// Dev builds in dev mode only: an idle-time override for headless e2e tests (`dev.simulate`), so "the user
    /// came back" can be driven without a keyboard. `None` = the real OS reading.
    sim_idle_s: Arc<Mutex<Option<u64>>>,
}

fn local_day() -> u64 {
    // days since epoch shifted by the local UTC offset is not needed precisely: a "day" boundary at local
    // midnight is approximated with the local minute-of-day reading.
    let (_, minute) = platform::local_time();
    (now_ms() / 60_000 - u64::from(minute)) / (24 * 60)
}

/// The enrollment challenge with the key attestation computed for it.
struct EnrollmentAttestation {
    challenge: crate::vault::EnrollmentChallenge,
    nonce: [u8; 32],
    format: String,
    blob: Option<String>,
}

/// Plain words for the server's enrollment refusals. Never more than the server says.
pub fn enrollment_refusal_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "hardware_in_use" => "This computer is already registered to another Vouch Compute account. Remove it from that account first (Devices on the web, signed in to the other account), then try again here. Only one account can use a computer.",
        "device_limit" => "Your account has reached its device limit. Verify your identity on the web, or remove a device you no longer use, then try again.",
        "enrollment_refused" => "Vouch Compute can't register this computer. If you think this is a mistake, contact support.",
        "consent_required" => hwids::REFUSED_MESSAGE,
        // vault 422 (T-213): a macOS/Windows software key reported fewer than two medium identifiers
        "hw_ids_required" => "This computer did not report enough hardware details to register.",
        // vault 422: this computer type cannot be registered yet (server setting), or a malformed hardware blob
        "attestation_invalid" => "This computer can't be registered for paid work right now.",
        _ => return None,
    })
}

impl Agent {
    pub fn new(data_dir: PathBuf, cfg: Config) -> anyhow::Result<Arc<Self>> {
        Self::with_platform(data_dir, cfg, Arc::new(platform::read))
    }

    /// `platform` supplies OS readings (tests inject fakes).
    pub fn with_platform(
        data_dir: PathBuf,
        cfg: Config,
        platform: Arc<dyn Fn() -> Readings + Send + Sync>,
    ) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(&data_dir)?;
        let sim_idle_s: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let platform: Arc<dyn Fn() -> Readings + Send + Sync> = if cfg.allow_insecure_dev() {
            let sim = sim_idle_s.clone();
            Arc::new(move || {
                let mut r = platform();
                if let Some(idle) = *sim.lock().unwrap() {
                    r.idle_s = Some(idle);
                }
                r
            })
        } else {
            platform
        };
        let state = State::load(&data_dir);
        let key = identity::load_or_create(&data_dir, cfg.prefer_tpm && !state.software_key, state.tpm_key_name.as_deref())?;
        if state.device_key_id.as_deref().is_some_and(|k| k != key.device_key_id()) {
            tracing::warn!("device key changed since enrollment: re-enrollment needed");
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            // Servers close idle keep-alive connections (uvicorn after 5 s, the device-code poll interval): drop
            // pooled connections first so a request never goes out on a socket the server already closed.
            .pool_idle_timeout(Duration::from_secs(4))
            .user_agent(concat!("vouch-core/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let registry = Arc::new(Registry::new(data_dir.join("models"), cfg.model_cache_gb));
        // Windows: a job's read access to its directories ends with the job; remove any that a crash left behind
        if cfg!(windows) {
            let mut dirs: Vec<PathBuf> =
                std::fs::read_dir(data_dir.join("models")).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()).unwrap_or_default();
            dirs.extend(cfg.ort_pack_dir());
            if !dirs.is_empty() {
                pool_sandbox::revoke_stale_grants(&dirs);
            }
        }
        let runner = Arc::new(RunnerClient {
            exe: cfg.runner_exe(),
            memory_limit_bytes: 8 << 30,
            ort_pack_dir: cfg.ort_pack_dir(),
            // macOS: only when the runner itself reports a Metal build (pool-runner's `metal` feature is the one switch)
            metal_gpu: cfg.use_gpu && crate::runner_client::runner_supports_metal(&cfg.runner_exe()),
        });
        let (decision_tx, _) = watch::channel(Decision::Pause(crate::governor::PauseReason::UserActive));
        let (settings_tx, _) = watch::channel(state.settings.clone());
        let (stop_tx, _) = watch::channel(0u64);
        let status = Arc::new(StatusHub::default());
        let connection = if state.device_id.is_some() && state.device_key_id.as_deref() == Some(&key.device_key_id()) {
            Connection::Connecting
        } else if state.refresh_token_sealed.is_some() {
            Connection::NotEnrolled
        } else {
            Connection::NotSignedIn
        };
        status.update(|s| s.connection = connection);
        Ok(Arc::new(Self {
            vault: VaultClient::new(&cfg.vault_url, &cfg.oauth_client_id, http.clone()),
            data_dir,
            cfg,
            state: Mutex::new(state),
            key: RwLock::new(key),
            http,
            registry,
            runner,
            status,
            decision_tx,
            settings_tx,
            stop_tx,
            access: Mutex::new(None),
            signin: Mutex::new(SignIn::Idle),
            platform,
            hw_collector: Mutex::new(hwids::os_collector()),
            seen_nonces: Arc::new(Mutex::new(VecDeque::new())),
            lease_nonces: Arc::new(NonceBook::default()),
            worked_ms: Arc::new(AtomicU64::new(0)),
            wake: tokio::sync::Notify::new(),
            sim_idle_s,
        }))
    }

    /// Replace the hardware-identifier collector (tests use fixtures with sentinel values).
    pub fn set_hw_collector(&self, c: hwids::Collector) {
        *self.hw_collector.lock().unwrap() = c;
    }

    pub fn key_storage(&self) -> KeyStorage {
        self.key().storage()
    }

    pub fn key(&self) -> Arc<dyn DeviceKey> {
        self.key.read().unwrap().clone()
    }

    pub fn device_id(&self) -> Option<String> {
        let s = self.state.lock().unwrap();
        match (&s.device_id, &s.device_key_id) {
            (Some(id), Some(k)) if *k == self.key().device_key_id() => Some(id.clone()),
            _ => None,
        }
    }

    fn save(&self) {
        if let Err(e) = self.state.lock().unwrap().save(&self.data_dir) {
            tracing::error!("saving state: {e}");
        }
    }

    pub fn state_snapshot(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    pub fn settings(&self) -> Settings {
        self.state.lock().unwrap().settings.clone()
    }

    pub fn set_settings(&self, s: Settings) -> Settings {
        let s = s.sanitized();
        self.state.lock().unwrap().settings = s.clone();
        self.save();
        self.settings_tx.send_replace(s.clone());
        s
    }

    /// Mark this device as enrolled (used by tests and after registration).
    pub fn set_enrollment(&self, device_id: &str, trust_ceiling: &str) {
        {
            let mut st = self.state.lock().unwrap();
            st.device_id = Some(device_id.into());
            st.device_key_id = Some(self.key().device_key_id());
            st.trust_ceiling = Some(trust_ceiling.into());
        }
        self.save();
        self.status.update(|s| s.connection = Connection::Connecting);
        self.wake.notify_waiters();
    }

    // ------------------------------------------------------------------ governor

    async fn governor_loop(self: Arc<Self>) {
        let mut g = Governor::new();
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            let r = (self.platform)();
            let day = local_day();
            let worked_s = {
                let mut st = self.state.lock().unwrap();
                let add = self.worked_ms.swap(0, Ordering::Relaxed) / 1000;
                if st.worked_day != day {
                    st.worked_day = day;
                    st.worked_today_s = 0;
                }
                st.worked_today_s += add;
                st.worked_today_s
            };
            let settings = self.settings_tx.borrow().clone();
            let d = g.decide(&settings, &platform::to_inputs(&r, now_ms(), worked_s));
            if *self.decision_tx.borrow() != d {
                tracing::info!("governor: {d:?}");
                self.decision_tx.send_replace(d);
            }
            self.status.update(|s| s.decision = d);
        }
    }

    // ------------------------------------------------------------------ trust + session loop

    async fn trusted_keyset(&self) -> anyhow::Result<trust::TrustedKeySet> {
        let bytes = self.vault.keyset().await?;
        let roots = trust::trust_roots().map_err(|e| anyhow::anyhow!("{e}"))?;
        let min = self.state.lock().unwrap().keyset_max_version;
        let ks = trust::verify_keyset(&bytes, &roots, min).map_err(|e| anyhow::anyhow!("KeySet rejected: {e}"))?;
        if ks.keyset.version > min {
            self.state.lock().unwrap().keyset_max_version = ks.keyset.version;
            self.save();
        }
        Ok(ks)
    }

    async fn session_loop(self: Arc<Self>) {
        let mut attempt: u32 = 0;
        loop {
            let Some(device_id) = self.device_id() else {
                self.wake.notified().await;
                continue;
            };
            self.status.update(|s| {
                s.connection = Connection::Connecting;
                s.reconnect_in_s = None;
            });
            let end = match self.trusted_keyset().await {
                Err(e) => {
                    self.status.update(|s| s.last_error = Some(e.to_string()));
                    SessionEnd::Reconnect(None)
                }
                Ok(ks) => {
                    self.registry.load_index(&ks);
                    match session::connect(&self.cfg).await {
                        Err(e) => {
                            self.status.update(|s| s.last_error = Some(format!("connect: {e}")));
                            SessionEnd::Reconnect(None)
                        }
                        Ok((ws, edge)) => {
                            let key = self.key();
                            let deps = Arc::new(session::Deps {
                                cfg: self.cfg.clone(),
                                me: NodeIdentity { device_id: device_id.clone(), device_key_id: key.device_key_id() },
                                key,
                                keyset: ks,
                                registry: self.registry.clone(),
                                runner: self.runner.clone(),
                                http: self.http.clone(),
                                status: self.status.clone(),
                                decision_rx: self.decision_tx.subscribe(),
                                settings_rx: self.settings_tx.subscribe(),
                                stop_rx: self.stop_tx.subscribe(),
                                seen_nonces: self.seen_nonces.clone(),
                                lease_nonces: self.lease_nonces.clone(),
                                platform: self.platform.clone(),
                                worked_ms: self.worked_ms.clone(),
                                perf: {
                                    let me = Arc::downgrade(&self);
                                    Arc::new(move |u| {
                                        if let Some(a) = me.upgrade() {
                                            a.record_performance(u);
                                        }
                                    })
                                },
                            });
                            let end = session::run(deps, ws, edge).await;
                            // Only a session that reached Welcome resets the backoff. A server that
                            // closes before the Challenge (1013 "busy") now gets exponential backoff instead of a
                            // reconnect every 1-2 s.
                            if self.status.get().connection == Connection::Connected {
                                attempt = 0;
                            }
                            end
                        }
                    }
                }
            };
            tracing::info!("session ended: {end:?}");
            let wait = match end {
                SessionEnd::Reconnect(Some(d)) => d,
                SessionEnd::Reconnect(None) | SessionEnd::ProtocolError(_) => {
                    if let SessionEnd::ProtocolError(e) = &end {
                        self.status.update(|s| s.last_error = Some(e.clone()));
                    }
                    attempt = attempt.saturating_add(1);
                    backoff(attempt)
                }
                SessionEnd::AuthFailed => {
                    self.status.update(|s| s.connection = Connection::AuthFailed);
                    attempt = attempt.saturating_add(1);
                    backoff(attempt).max(Duration::from_secs(60))
                }
                SessionEnd::UpdateRequired => {
                    self.status.update(|s| s.connection = Connection::UpdateRequired);
                    self.wake.notified().await;
                    continue;
                }
                SessionEnd::Revoked => {
                    // 2.1.0: a pause by Vouch Compute also ends sessions and can be lifted later, so a revoked
                    // session is retried slowly; a really revoked key is refused at Hello (AUTH_FAILED).
                    self.status.update(|s| s.connection = Connection::Revoked);
                    attempt = attempt.saturating_add(1);
                    backoff(attempt).max(Duration::from_secs(600))
                }
                SessionEnd::DoNotReconnect => {
                    self.status.update(|s| s.connection = Connection::Offline);
                    self.wake.notified().await;
                    continue;
                }
                SessionEnd::Stopped => continue,
            };
            if !matches!(self.status.get().connection, Connection::AuthFailed | Connection::Revoked) {
                self.status.update(|s| s.connection = Connection::Offline);
            }
            self.status.update(|s| {
                s.reconnect_in_s = Some(wait.as_secs());
                s.reconnect_attempts = attempt;
            });
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.wake.notified() => {}
            }
        }
    }

    /// Weekly hardware-identifier reports: checked every 15 minutes; the schedule is in `state.json`, so it
    /// survives restarts.
    async fn hw_report_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(15 * 60));
        loop {
            tick.tick().await;
            if let Err(e) = self.hw_report_tick().await {
                tracing::warn!("hardware identifier report: {e}");
            }
        }
    }

    pub async fn run(self: Arc<Self>) {
        let g = tokio::spawn(self.clone().governor_loop());
        let s = tokio::spawn(self.clone().session_loop());
        let h = tokio::spawn(self.clone().hw_report_loop());
        let _ = tokio::join!(g, s, h);
    }

    // ------------------------------------------------------------------ sign-in and enrollment

    async fn access_token(&self) -> anyhow::Result<String> {
        if let Some((t, exp)) = self.access.lock().unwrap().clone() {
            if exp > now_ms() + 30_000 {
                return Ok(t);
            }
        }
        let sealed = self.state.lock().unwrap().refresh_token_sealed.clone().ok_or_else(|| anyhow::anyhow!("not signed in"))?;
        let rt = String::from_utf8(unseal_b64(&sealed)?)?;
        let tokens = self.vault.refresh(&rt).await?;
        self.store_tokens(&tokens);
        Ok(tokens.access_token)
    }

    fn store_tokens(&self, t: &crate::vault::Tokens) {
        *self.access.lock().unwrap() = Some((t.access_token.clone(), now_ms() + t.expires_in * 1000));
        if let Some(rt) = &t.refresh_token {
            if let Ok(sealed) = seal_b64(rt.as_bytes()) {
                self.state.lock().unwrap().refresh_token_sealed = Some(sealed);
                self.save();
            }
        }
    }

    pub fn signin_state(&self) -> SignIn {
        self.signin.lock().unwrap().clone()
    }

    fn set_signin(&self, s: SignIn) {
        *self.signin.lock().unwrap() = s;
    }

    /// Start the RFC 8628 flow; the app shows the code and opens the browser (sign-in and second factor there).
    pub async fn signin_start(self: &Arc<Self>) -> anyhow::Result<SignIn> {
        let dc: DeviceCode = self.vault.device_authorization(&crate::vault::DeviceLinkInfo::this_device()).await?;
        let st = SignIn::Pending {
            user_code: dc.user_code.clone(),
            verification_uri: dc.verification_uri.clone(),
            verification_uri_complete: dc.verification_uri_complete.clone(),
            expires_at_ms: now_ms() + dc.expires_in * 1000,
        };
        self.set_signin(st.clone());
        let me = self.clone();
        tokio::spawn(async move {
            let mut interval = dc.interval.max(1);
            let deadline = now_ms() + dc.expires_in * 1000;
            let result: anyhow::Result<()> = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    if now_ms() > deadline {
                        anyhow::bail!("the sign-in code expired, start again");
                    }
                    // a transient network error (the server restarting, a dropped connection) is not a failed sign-in:
                    // keep polling until the code expires
                    let poll = match me.vault.poll_token(&dc.device_code).await {
                        Ok(p) => p,
                        Err(e) if e.downcast_ref::<reqwest::Error>().is_some() => {
                            tracing::warn!("device-code poll failed, retrying: {e}");
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    match poll {
                        TokenPoll::Pending => {}
                        TokenPoll::SlowDown => interval += 5,
                        TokenPoll::Denied => anyhow::bail!("sign-in was declined"),
                        TokenPoll::Expired => anyhow::bail!("the sign-in code expired, start again"),
                        TokenPoll::Ok(t) => {
                            me.store_tokens(&t);
                            break;
                        }
                    }
                }
                me.status.update(|s| s.connection = Connection::NotEnrolled);
                Ok(())
            }
            .await;
            match result {
                Ok(()) => me.continue_enrollment(None).await,
                Err(e) => me.set_signin(SignIn::Error { message: e.to_string() }),
            }
        });
        Ok(st)
    }

    fn consent_given(&self) -> bool {
        self.state.lock().unwrap().hw_consent.as_ref().is_some_and(|c| c.accepted)
    }

    /// The next enrollment step after sign-in or a user choice: consent, then "is this a reinstall?", then register.
    /// `choice`: `None` = not asked yet; `Some(None)` = a new computer; `Some(Some(id))` = replaces that device.
    pub async fn continue_enrollment(&self, choice: Option<Option<String>>) {
        if self.device_id().is_some() {
            self.set_signin(SignIn::Done);
            return;
        }
        if !self.consent_given() {
            self.set_signin(SignIn::ConsentRequired);
            return;
        }
        let replaces = match choice {
            Some(c) => c,
            None => match self.replace_candidates().await {
                Ok(c) if !c.is_empty() => {
                    self.set_signin(SignIn::ChooseReplace { candidates: c });
                    return;
                }
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("could not list this account's devices: {e}");
                    None
                }
            },
        };
        self.set_signin(SignIn::Enrolling);
        let r = self.enroll(replaces.as_deref()).await;
        self.set_signin(match r {
            Ok(()) => SignIn::Done,
            Err(e) => match e.downcast_ref::<VaultError>() {
                Some(v) if enrollment_refusal_message(&v.code).is_some() => {
                    SignIn::Blocked { code: v.code.clone(), message: enrollment_refusal_message(&v.code).unwrap_or_default().into() }
                }
                Some(v) if replaces.is_some() && (v.status == 409 || v.status == 404) => SignIn::Blocked {
                    code: "replace_not_confirmed".into(),
                    message: "Vouch Compute couldn't confirm that this is the same computer. Register it as a new device instead.".into(),
                },
                _ => SignIn::Error { message: e.to_string() },
            },
        });
    }

    /// Own, non-revoked devices with this OS: the ones this computer may be a reinstall of (the server confirms by a
    /// strong hardware match, so a wrong choice is refused, never applied).
    async fn replace_candidates(&self) -> anyhow::Result<Vec<ReplaceCandidate>> {
        let token = self.access_token().await?;
        let v = self.vault.devices(&token).await?;
        let os = platform::os_name();
        Ok(v.get("data")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|d| d.get("os").and_then(Value::as_str) == Some(os) && d.get("status").and_then(Value::as_str) != Some("revoked"))
                    .filter_map(|d| {
                        Some(ReplaceCandidate {
                            device_id: d.get("device_id")?.as_str()?.to_string(),
                            name: d.get("name").and_then(Value::as_str).unwrap_or("").chars().take(40).collect(),
                            last_seen_day: d.get("last_seen_day").and_then(Value::as_str).map(str::to_string),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    // ------------------------------------------------------------------ hardware identifiers

    /// The consent text the app shows, its version and hash, and what the user decided.
    pub fn hw_consent_view(&self) -> Value {
        let c = self.state.lock().unwrap().hw_consent.clone();
        json!({
            "kind": "hw_identifiers",
            "version": hwids::CONSENT_VERSION,
            "text": hwids::CONSENT_TEXT,
            "text_sha256": hwids::consent_text_sha256(),
            "decision": c.map(|c| if c.accepted { "accepted" } else { "refused" }),
            "refused_message": hwids::REFUSED_MESSAGE,
        })
    }

    /// Record the user's decision. `text_sha256` must be the hash of the text the app showed (this exact version).
    /// Refusing (or withdrawing) stops all reports; enrollment stays blocked until the user accepts.
    pub async fn hw_consent_set(&self, accept: bool, text_sha256: &str) -> anyhow::Result<Value> {
        if text_sha256 != hwids::consent_text_sha256() {
            anyhow::bail!("the consent text changed; show the current text again");
        }
        self.state.lock().unwrap().hw_consent =
            Some(HwConsent { accepted: accept, version: hwids::CONSENT_VERSION.into(), text_sha256: text_sha256.into(), at_ms: now_ms() });
        self.save();
        if !accept && matches!(self.signin_state(), SignIn::ConsentRequired) {
            self.set_signin(SignIn::Blocked { code: "consent_refused".into(), message: hwids::REFUSED_MESSAGE.into() });
        }
        if accept && matches!(self.signin_state(), SignIn::ConsentRequired | SignIn::Blocked { .. }) && self.device_id().is_none() {
            self.continue_enrollment(None).await;
        }
        Ok(self.hw_consent_view())
    }

    /// Collect and sign `HwIdentifiers` for `device_id` with `key` (raw values stay in this function's memory).
    fn signed_hw_ids(&self, device_id: &str, key: &dyn DeviceKey) -> anyhow::Result<String> {
        if !self.consent_given() {
            anyhow::bail!("no hardware-identifier consent");
        }
        let collector = self.hw_collector.lock().unwrap().clone();
        let raw = collector();
        let ek = key.tpm().and_then(|t| t.ek_public().ok()).map(|ek| identity::attest::ek_pub_sha256(&ek));
        let ids = hwids::build(&raw, device_id, ek, crate::clock::server_now_ms());
        tracing::info!("hardware identifiers: {} NIC(s), {} GPU(s), {} VM indicator(s)", ids.nics.len(), ids.gpu_uuids.len(), ids.vm_indicators.len());
        hwids::sign(&ids, key)
    }

    /// Send the weekly report when it is due. Returns whether a report was sent.
    pub async fn hw_report_tick(&self) -> anyhow::Result<bool> {
        let (last_sent, last_attempt) = {
            let st = self.state.lock().unwrap();
            (st.hw_report_last_sent_ms, st.hw_report_last_attempt_ms)
        };
        let Some(device_id) = self.device_id() else { return Ok(false) };
        if !hwids::report_due(self.consent_given(), true, last_sent, last_attempt, now_ms()) {
            return Ok(false);
        }
        self.state.lock().unwrap().hw_report_last_attempt_ms = Some(now_ms());
        self.save();
        let key = self.key();
        let hw = self.signed_hw_ids(&device_id, key.as_ref())?;
        self.vault.report_hw_ids(&device_id, &hw).await?;
        self.state.lock().unwrap().hw_report_last_sent_ms = Some(now_ms());
        self.save();
        tracing::info!("weekly hardware identifier report sent");
        Ok(true)
    }

    /// Register this device's key with the server. Needs the hardware-identifier consent.
    pub async fn enroll(&self, replaces_device_id: Option<&str>) -> anyhow::Result<()> {
        if !self.consent_given() {
            return Err(VaultError { status: 0, code: "consent_required".into(), details: Value::Null }.into());
        }
        let mut key = self.key();
        let token = self.access_token().await?;
        let dev = self.cfg.allow_insecure_dev();
        let mut att = self.enrollment_attestation(key.as_ref(), &token, dev).await?;
        // The TPM key that could not attest: deleted once the server has accepted the software key instead.
        let mut unused_tpm_key: Option<Arc<dyn DeviceKey>> = None;
        // CR-T213-01: never `tpm2` without a blob. A TPM that cannot attest enrolls this computer with a software
        // key and `none` instead: a capped device in Probation for good.
        if identity::needs_software_fallback(&att.format, att.blob.as_deref(), dev) {
            tracing::warn!("this TPM gave no tpm2 attestation: enrolling with a software key (capped, Probation tier)");
            // in memory only: the choice is saved once the server has accepted this key
            unused_tpm_key = Some(key.clone());
            key = identity::software_key(&self.data_dir)?;
            att = self.enrollment_attestation(key.as_ref(), &token, dev).await?;
        }
        let (ch, att_format, att_blob) = (att.challenge, att.format, att.blob);
        let sig = enroll_nonce_sig(&ch.challenge_id, &att.nonce, key.as_ref())?;
        let hw = platform::hw_claims();
        let mut hw_json = json!({ "os": hw.os, "arch": hw.arch, "cpu": hw.cpu, "ram_mb": hw.ram_mb,
            "key_storage": match key.storage() { KeyStorage::Tpm => "tpm2-platform", KeyStorage::SoftwareDev => "software-dev" } });
        if let Some(g) = hw.gpu {
            hw_json["gpu"] = json!(g);
        }
        if let Some(v) = hw.vram_mb {
            hw_json["vram_mb"] = json!(v);
        }
        // The device id is not known before registration: HwIdentifiers at enrollment carries the challenge id in
        // `device_id`; the weekly reports carry the real device id.
        let hw_ids = self.signed_hw_ids(&ch.challenge_id, key.as_ref())?;
        let mut body = json!({
            "challenge_id": ch.challenge_id,
            "public_key": pool_proto::keys::b64(&key.spki_der()),
            "key_attestation": { "format": att_format, "blob": att_blob },
            "nonce_sig": pool_proto::keys::b64(&sig),
            "hw_claims": hw_json,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "os": platform::os_name(),
            "arch": platform::arch(),
            "hw_ids": hw_ids,
            "hw_consent": { "version": hwids::CONSENT_VERSION, "text_sha256": hwids::consent_text_sha256() },
        });
        if let Some(r) = replaces_device_id {
            body["replaces_device_id"] = json!(r);
        }
        let reg = self.vault.register_device(&token, &body).await?;
        if reg.device_key_id != key.device_key_id() {
            anyhow::bail!("vault registered a different key id");
        }
        {
            let mut st = self.state.lock().unwrap();
            st.hw_report_last_sent_ms = Some(now_ms());
            st.hw_report_last_attempt_ms = None;
            st.tpm_key_name = key.key_name().filter(|n| n.as_str() != crate::identity::TPM_KEY_NAME);
            // The key the server now knows decides which key loads at start: a software key (the TPM fallback above, or
            // a TPM that failed to open in `load_or_create`) keeps the TPM skipped from now on (CR-T213-01).
            st.software_key = key.storage() == KeyStorage::SoftwareDev;
        }
        *self.key.write().unwrap() = key.clone();
        self.set_enrollment(&reg.device_id, &reg.trust_ceiling);
        // Housekeeping (vault follow-up to CR-T215-01): the TPM is skipped from now on, so its unused key is deleted.
        if let Some(unused) = unused_tpm_key {
            identity::discard_unused_key(unused.as_ref(), key.as_ref());
        }
        Ok(())
    }

    /// One enrollment challenge and the key attestation for `key` (contract 2.1.0; `tpm2` v2 for a TPM key).
    async fn enrollment_attestation(&self, key: &dyn DeviceKey, token: &str, dev: bool) -> anyhow::Result<EnrollmentAttestation> {
        // tpm2 v2: ask for a credential bound to this TPM's EK and AIK
        let publics = match identity::tpm_request(key, dev) {
            Some(Ok(p)) => Some(p),
            Some(Err(e)) => {
                tracing::warn!("this TPM cannot give its EK/AIK: {e}");
                None
            }
            None => None,
        };
        let ch = self.vault.enrollment_challenge(token, publics.as_ref().map(|p| (&p.ek_public[..], &p.aik_public[..]))).await?;
        let nonce: [u8; 32] = pool_proto::keys::b64_decode(&ch.nonce)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("enrollment nonce must be 32 bytes"))?;
        let activation = match &ch.tpm_activation {
            Some(a) => Some(identity::attest::TpmActivation {
                credential_blob: pool_proto::keys::b64_decode(&a.credential_blob).map_err(|e| anyhow::anyhow!("{e}"))?,
                encrypted_secret: pool_proto::keys::b64_decode(&a.encrypted_secret).map_err(|e| anyhow::anyhow!("{e}"))?,
            }),
            None => None,
        };
        let att_ch = identity::ChallengeForAttestation { challenge_id: &ch.challenge_id, nonce: &nonce, tpm_activation: activation.as_ref() };
        let (format, blob) = identity::attestation(key, platform::os_name(), &att_ch, publics.as_ref(), dev);
        Ok(EnrollmentAttestation { challenge: ch, nonce, format: format.to_string(), blob })
    }

    pub fn sign_out(&self) {
        *self.access.lock().unwrap() = None;
        {
            let mut st = self.state.lock().unwrap();
            st.refresh_token_sealed = None;
        }
        self.save();
        self.set_signin(SignIn::Idle);
        if self.device_id().is_none() {
            self.status.update(|s| s.connection = Connection::NotSignedIn);
        }
    }

    // ------------------------------------------------------------------ device control

    /// Sign a `DeviceControl` (fresh 16-byte nonce, current time) with the device's current key.
    pub fn device_control_cose(&self, action: &str) -> anyhow::Result<(String, Vec<u8>)> {
        let device_id = self.device_id().ok_or_else(|| anyhow::anyhow!("this computer is not registered"))?;
        let cose = sign_device_control(self.key().as_ref(), &device_id, action)?;
        Ok((device_id, cose))
    }

    /// "Pause on the server" / "Resume" / "Remove this device" from the app (no web session needed).
    pub async fn device_control(&self, action: &str) -> anyhow::Result<Value> {
        let (device_id, cose) = self.device_control_cose(action)?;
        match self.vault.device_control(&device_id, &cose).await {
            Ok(()) => {}
            Err(e) => {
                if let Some(v) = e.downcast_ref::<VaultError>() {
                    if v.code == "paused_by_tally" {
                        anyhow::bail!("This device was paused by Vouch Compute. Contact support to resume it.");
                    }
                }
                return Err(e);
            }
        }
        if action == "self_revoke" {
            self.wipe_local_identity()?;
        }
        Ok(json!({ "action": action, "done": true }))
    }

    /// After "Remove this device": delete the device key (TPM key / sealed file) and the device-link token, forget the
    /// enrollment, end the session, and start over with a fresh key (a later enrollment is a new device).
    pub fn wipe_local_identity(&self) -> anyhow::Result<()> {
        let old = self.key();
        old.destroy()?;
        *self.access.lock().unwrap() = None;
        {
            let mut st = self.state.lock().unwrap();
            st.device_id = None;
            st.device_key_id = None;
            st.trust_ceiling = None;
            st.refresh_token_sealed = None;
            st.hw_report_last_sent_ms = None;
            st.hw_report_last_attempt_ms = None;
            st.tpm_key_name = None;
            st.software_key = false;
            st.benchmark = None;
            st.performance.clear();
        }
        self.save();
        let fresh = identity::load_or_create(&self.data_dir, self.cfg.prefer_tpm, None)?;
        *self.key.write().unwrap() = fresh;
        self.stop_tx.send_modify(|n| *n += 1);
        self.set_signin(SignIn::Idle);
        self.status.update(|s| {
            s.connection = Connection::NotSignedIn;
            s.notices = Default::default();
        });
        self.wake.notify_waiters();
        tracing::info!("device removed: key and device-link token wiped");
        Ok(())
    }

    // ------------------------------------------------------------------ "Recover my account"

    /// Sign a `RecoveryProof` for the case code the user typed (shown by the web's `/recover`) and send it.
    /// Only ever started by the user.
    pub async fn recovery_prove(&self, code: &str) -> anyhow::Result<Value> {
        let device_id = self.device_id().ok_or_else(|| anyhow::anyhow!("this computer is not registered to an account"))?;
        let (case_id, challenge) = parse_recovery_code(code)?;
        let token = self.access_token().await?;
        let me = self.vault.me(&token).await?;
        let account_id = me.get("account_id").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("account unknown"))?.to_string();
        let p = pool_proto::objects::RecoveryProof { case_id: case_id.clone(), account_id, challenge, ts: crate::clock::server_now_ms() };
        pool_proto::objects::RecoveryProof::from_value(&p.to_value()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let cose = pool_proto::cose::sign1(&p.to_value(), self.key().as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.vault.recovery_device_proof(&case_id, &device_id, &cose).await?;
        Ok(json!({ "sent": true, "message": "Done. The recovery waits 72 hours, and payouts stay frozen for 7 days after it completes. If this wasn't you, cancel it on the web." }))
    }

    // ------------------------------------------------------------------ "Repair device identity": vouched re-key

    /// Rotate the device key: the old key vouches for a new one (`pool/key-rotation/v1`, both sign), so the tier is
    /// kept. The new key's attestation follows the enrollment rules.
    pub async fn rotate_key(&self) -> anyhow::Result<Value> {
        let device_id = self.device_id().ok_or_else(|| anyhow::anyhow!("this computer is not registered"))?;
        let old = self.key();
        let new = identity::create_rotation_key(&self.data_dir, old.as_ref())?;
        let r: anyhow::Result<String> = async {
            let token = self.access_token().await?;
            let dev = self.cfg.allow_insecure_dev();
            let publics = identity::tpm_request(new.as_ref(), dev).and_then(Result::ok);
            let ch = self.vault.enrollment_challenge(&token, publics.as_ref().map(|p| (&p.ek_public[..], &p.aik_public[..]))).await?;
            let nonce: [u8; 32] = pool_proto::keys::b64_decode(&ch.nonce)
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("nonce must be 32 bytes"))?;
            let activation = ch.tpm_activation.as_ref().and_then(|a| {
                Some(identity::attest::TpmActivation {
                    credential_blob: pool_proto::keys::b64_decode(&a.credential_blob).ok()?,
                    encrypted_secret: pool_proto::keys::b64_decode(&a.encrypted_secret).ok()?,
                })
            });
            let att_ch = identity::ChallengeForAttestation { challenge_id: &ch.challenge_id, nonce: &nonce, tpm_activation: activation.as_ref() };
            let (format, blob) = identity::attestation(new.as_ref(), platform::os_name(), &att_ch, publics.as_ref(), dev);
            // CR-T213-01: never `tpm2` without a blob. A rotation keeps the device's tier, so it is not downgraded to
            // a software key here: the rotation stops and the current key stays.
            if identity::needs_software_fallback(format, blob.as_deref(), dev) {
                anyhow::bail!("This computer's security chip could not certify the new key, so the key was not changed.");
            }
            let claims = pool_proto::objects::KeyRotationClaims {
                device_id: device_id.clone(),
                old_device_key_id: old.device_key_id(),
                new_device_key_id: new.device_key_id(),
            };
            let old_sig = pool_proto::cose::sign1(&claims.to_value(), old.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
            let new_sig = pool_proto::cose::sign1(&claims.to_value(), new.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
            let body = json!({
                "new_public_key": pool_proto::keys::b64(&new.spki_der()),
                "key_attestation": { "format": format, "blob": blob },
                "old_key_sig": pool_proto::keys::b64(&old_sig),
                "new_key_sig": pool_proto::keys::b64(&new_sig),
            });
            self.vault.rotate_key(&token, &device_id, &body).await
        }
        .await;
        let new_kid = match r {
            Ok(k) => k,
            Err(e) => {
                let _ = new.destroy();
                return Err(e);
            }
        };
        if new_kid != new.device_key_id() {
            let _ = new.destroy();
            anyhow::bail!("vault registered a different key id");
        }
        // the server revoked the old key: switch over, then wipe the old private key
        let committed = identity::commit_rotation_key(&self.data_dir, new.as_ref())?;
        {
            let mut st = self.state.lock().unwrap();
            st.device_key_id = Some(new_kid.clone());
            st.tpm_key_name = committed.key_name();
        }
        self.save();
        *self.key.write().unwrap() = committed;
        if old.storage() == KeyStorage::Tpm {
            let _ = old.destroy();
        }
        self.stop_tx.send_modify(|n| *n += 1);
        self.wake.notify_waiters();
        Ok(json!({ "device_key_id": new_kid }))
    }

    // ------------------------------------------------------------------ app-facing reads (read-only scopes)

    pub async fn estimate(&self) -> anyhow::Result<Value> {
        let id = self.device_id().ok_or_else(|| anyhow::anyhow!("device not enrolled"))?;
        self.vault.estimate(&self.access_token().await?, &id).await
    }
    pub async fn wallets(&self) -> anyhow::Result<Value> {
        self.vault.wallets(&self.access_token().await?).await
    }
    pub async fn earnings(&self) -> anyhow::Result<Value> {
        self.vault.earnings_summary(&self.access_token().await?).await
    }
    /// the server's `DeviceView` for this device, passed through the display field filter ([`crate::device_view`]). The
    /// reliability tier is shown as the server sent it and is never stored or computed here.
    pub async fn device_view(&self) -> anyhow::Result<Value> {
        let id = self.device_id().ok_or_else(|| anyhow::anyhow!("device not enrolled"))?;
        Ok(crate::device_view::for_app(&self.vault.device(&self.access_token().await?, &id).await?))
    }

    /// Leases whose proof nonces are still remembered (the soak test checks it stays bounded).
    pub fn tracked_leases(&self) -> usize {
        self.lease_nonces.leases()
    }

    /// Keep the app's own benchmark measurement (display only) in `state.json`.
    fn record_performance(&self, u: session::PerfUpdate) {
        let changed = {
            let mut st = self.state.lock().unwrap();
            match u {
                session::PerfUpdate::Measured(p) => {
                    crate::status::record_performance(&mut st.performance, p);
                    true
                }
                session::PerfUpdate::Received(id) => crate::status::mark_received(&mut st.performance, &id),
            }
        };
        if changed {
            self.save();
        }
    }

    pub fn snapshot(&self) -> Value {
        let st = self.state.lock().unwrap().clone();
        let status: Status = self.status.get();
        let key = self.key();
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "build": { "dev_build": pool_proto::DEV_BUILD, "info": pool_proto::BUILD_INFO },
            "status": status,
            "signed_in": st.refresh_token_sealed.is_some(),
            "device_id": self.device_id(),
            "trust_ceiling": st.trust_ceiling,
            "key_storage": key.storage(),
            "settings": st.settings,
            "worked_today_s": st.worked_today_s,
            // measured by this app during the benchmark; display only (the server's own measurement decides pay)
            "performance": st.performance,
            "signin": self.signin_state(),
            "hw_consent": st.hw_consent.as_ref().map(|c| if c.accepted { "accepted" } else { "refused" }),
            "links": {
                "wallet": format!("{}/app/wallet", self.cfg.web_url),
                "dashboard": format!("{}/app", self.cfg.web_url),
                "devices": format!("{}/app/devices", self.cfg.web_url),
                "recover": format!("{}/recover", self.cfg.web_url),
                "verify": format!("{}/app/wallet", self.cfg.web_url),
                "earn": format!("{}/earn", self.cfg.web_url),
                "trust": format!("{}/trust", self.cfg.web_url),
                "contributor_agreement": format!("{}/legal/contributor-agreement", self.cfg.web_url),
                "acceptable_use": format!("{}/legal/acceptable-use", self.cfg.web_url),
            },
            "hardware": platform::hw_claims().to_value_json(),
        })
    }

    /// Dev builds in dev mode only (`dev.simulate`): override the idle reading the governor sees.
    pub fn simulate_idle(&self, idle_s: Option<u64>) -> anyhow::Result<()> {
        if !self.cfg.allow_insecure_dev() {
            anyhow::bail!("dev.simulate is only available in dev builds with dev mode on");
        }
        *self.sim_idle_s.lock().unwrap() = idle_s;
        Ok(())
    }

    pub fn reconnect_now(&self) {
        self.wake.notify_waiters();
    }
}

/// The code "Recover my account" takes: `<case_id>.<challenge>` (the challenge as base64, base64url or hex), as the
/// web shows it. Whitespace is ignored.
/// A COSE-signed `DeviceControl` (fresh 16-byte nonce, current server time) for `device_id`.
pub fn sign_device_control(key: &dyn DeviceKey, device_id: &str, action: &str) -> anyhow::Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let c = pool_proto::objects::DeviceControl { device_id: device_id.to_string(), action: action.into(), ts: crate::clock::server_now_ms(), nonce };
    pool_proto::objects::DeviceControl::from_value(&c.to_value()).map_err(|e| anyhow::anyhow!("{e}"))?;
    pool_proto::cose::sign1(&c.to_value(), key).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Uninstall with "delete the application data": remove this device from the account before its keys are
/// deleted, by signing a `self_revoke` with the existing device key. Best effort and bounded by `limit`: no key
/// is ever created, and `Ok(false)` means there was nothing to revoke (not registered, or no key left). Without a
/// network path the device stays listed on the account until it is removed on the website.
pub async fn uninstall_self_revoke(data_dir: &std::path::Path, cfg: &Config, limit: Duration) -> anyhow::Result<bool> {
    let state = State::load(data_dir);
    let Some(device_id) = state.device_id.clone() else { return Ok(false) };
    let Some(key) = identity::open_existing(data_dir, cfg.prefer_tpm && !state.software_key, state.tpm_key_name.as_deref()) else { return Ok(false) };
    let cose = sign_device_control(key.as_ref(), &device_id, "self_revoke")?;
    let http = reqwest::Client::builder()
        .connect_timeout(limit)
        .timeout(limit)
        .user_agent(concat!("vouch-core/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let vault = VaultClient::new(&cfg.vault_url, &cfg.oauth_client_id, http);
    tokio::time::timeout(limit, vault.device_control(&device_id, &cose))
        .await
        .map_err(|_| anyhow::anyhow!("the account server did not answer in time"))??;
    Ok(true)
}

pub fn parse_recovery_code(code: &str) -> anyhow::Result<(String, [u8; 32])> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let (case_id, ch) = code.split_once(['.', ':']).ok_or_else(|| anyhow::anyhow!("enter the whole code shown on the web"))?;
    let case_id = case_id.to_lowercase();
    if uuid::Uuid::parse_str(&case_id).is_err() || case_id.len() != 36 {
        anyhow::bail!("that code is not valid");
    }
    use base64::Engine as _;
    let bytes = hex::decode(ch)
        .ok()
        .filter(|b| b.len() == 32)
        .or_else(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(ch.trim_end_matches('=')).ok())
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(ch).ok())
        .ok_or_else(|| anyhow::anyhow!("that code is not valid"))?;
    let challenge: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("that code is not valid"))?;
    Ok((case_id, challenge))
}

/// `nonce_sig` for `POST /v1/devices` (cddl 1.1.0 `EnrollClaims`): COSE_Sign1 by the new device key
/// (`kid` = its `device_key_id`) over the deterministic CBOR map `{"type": "pool/enroll/v1", challenge_id, nonce}`.
/// The domain-separated map replaces the deprecated raw-nonce payload, so the device key never signs bare bytes.
pub fn enroll_nonce_sig(challenge_id: &str, nonce: &[u8; 32], key: &dyn pool_proto::cose::Es256Signer) -> anyhow::Result<Vec<u8>> {
    let claims = pool_proto::objects::EnrollClaims { challenge_id: challenge_id.to_string(), nonce: *nonce };
    // refuse a challenge id that is not a uuid instead of signing something the server would not accept
    pool_proto::objects::EnrollClaims::from_value(&claims.to_value()).map_err(|e| anyhow::anyhow!("enrollment challenge: {e}"))?;
    pool_proto::cose::sign1(&claims.to_value(), key).map_err(|e| anyhow::anyhow!("{e}"))
}

fn backoff(attempt: u32) -> Duration {
    // exponential with full jitter, 1 s.. 5 min
    let cap = (1u64 << attempt.min(9)).min(300);
    let mut b = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut b);
    let ms = u64::from_le_bytes(b) % (cap * 1000).max(1000);
    Duration::from_millis(ms.max(1000))
}

fn seal_b64(data: &[u8]) -> anyhow::Result<String> {
    Ok(pool_proto::keys::b64(&crate::identity::seal_secret(data)?))
}

fn unseal_b64(s: &str) -> anyhow::Result<Vec<u8>> {
    crate::identity::unseal_secret(&pool_proto::keys::b64_decode(s).map_err(|e| anyhow::anyhow!("{e}"))?)
}

trait HwJson {
    fn to_value_json(&self) -> Value;
}

impl HwJson for pool_proto::objects::HwClaims {
    fn to_value_json(&self) -> Value {
        json!({ "os": self.os, "arch": self.arch, "cpu": self.cpu, "ram_mb": self.ram_mb, "gpu": self.gpu, "vram_mb": self.vram_mb })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn backoff_is_bounded_with_jitter() {
        for a in 0..20 {
            let d = super::backoff(a);
            assert!(d >= std::time::Duration::from_secs(1) && d <= std::time::Duration::from_secs(300));
        }
    }

    #[test]
    fn recovery_codes_parse() {
        let id = "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e";
        let ch = [7u8; 32];
        let b64u = pool_proto::keys::b64url(&ch);
        assert_eq!(super::parse_recovery_code(&format!("{id}.{b64u}")).unwrap(), (id.to_string(), ch));
        assert_eq!(super::parse_recovery_code(&format!(" {} : {} ", id.to_uppercase(), hex::encode(ch))).unwrap().1, ch);
        assert_eq!(super::parse_recovery_code(&format!("{id}.{}", pool_proto::keys::b64(&ch))).unwrap().1, ch);
        for bad in ["", "abc", &format!("{id}.AAAA"), &format!("not-a-uuid.{b64u}"), &b64u] {
            assert!(super::parse_recovery_code(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refusal_messages_are_plain_and_specific() {
        let m = super::enrollment_refusal_message("hardware_in_use").unwrap();
        assert!(m.contains("Remove it from that account first"), "{m}");
        assert!(super::enrollment_refusal_message("device_limit").unwrap().contains("Verify your identity"));
        assert!(super::enrollment_refusal_message("something_else").is_none());
        // CR-T213-01 copy
        assert_eq!(
            super::enrollment_refusal_message("hw_ids_required"),
            Some("This computer did not report enough hardware details to register.")
        );
        assert_eq!(super::enrollment_refusal_message("attestation_invalid"), Some("This computer can't be registered for paid work right now."));
        assert_eq!(super::enrollment_refusal_message("consent_required"), Some(crate::hwids::REFUSED_MESSAGE));
    }
}
