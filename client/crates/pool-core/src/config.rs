//! Agent configuration and persisted state (in the per-user data dir).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::governor::Settings;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Job server: `wss://<host>/node/v1/connect` (dev: `ws://127.0.0.1:8000/node/v1/connect`).
    pub engine_ws_url: String,
    /// the server public API (`/v1/*`, `/oauth2/*`).
    pub vault_url: String,
    /// face web app (wallet linking, KYC, dashboard).
    pub web_url: String,
    /// OAuth client id of the desktop app (RFC 8628 device grant).
    pub oauth_client_id: String,
    /// Dev mode: allows `ws://` with the all-zero TLS exporter (the server accepts it only with VAULT_ENV=dev).
    pub dev: bool,
    /// Dev/test only: run the benchmark for this many seconds instead of the signed `min_duration_s`.
    /// Ignored unless built with `dev-trust` and `dev` is true. the server rejects results shorter than 20 min.
    pub bench_duration_override_s: Option<u64>,
    /// Path to `pool-runner` (default: next to this executable).
    pub runner_path: Option<PathBuf>,
    /// Model cache cap in GB (LRU eviction).
    pub model_cache_gb: u32,
    /// Try the TPM for the device key (Windows).
    pub prefer_tpm: bool,
    /// The pinned GPU backend pack (default: `backends/ort-directml` next to the agent). Used only if every
    /// file matches its pinned SHA-256; `use_gpu: false` turns the GPU path off.
    pub ort_pack_dir: Option<PathBuf>,
    pub use_gpu: bool,
    /// Dev builds only (`dev-trust`): KeySet root public keys (base64 SPKI) of the local dev server,
    /// e.g. the public half of the server's `keyset` dev key. Exported to the runner as POOL_DEV_TRUST_ROOTS.
    pub dev_trust_roots: Vec<String>,
}

/// Release endpoints: the job server, the account server's device-facing host and the web app.
pub const RELEASE_ENGINE_WS_URL: &str = "wss://api.vouchcompute.com/node/v1/connect";
pub const RELEASE_VAULT_URL: &str = "https://enroll.vouchcompute.com";
pub const RELEASE_WEB_URL: &str = "https://www.vouchcompute.com";

impl Default for Config {
    fn default() -> Self {
        // Release builds use the fixed release hosts; dev builds keep the local dev stack.
        let dev = cfg!(feature = "dev-trust");
        let (engine_ws_url, vault_url, web_url) = if dev {
            ("ws://127.0.0.1:8000/node/v1/connect", "http://127.0.0.1:8100", "http://127.0.0.1:3000")
        } else {
            (RELEASE_ENGINE_WS_URL, RELEASE_VAULT_URL, RELEASE_WEB_URL)
        };
        Self {
            engine_ws_url: engine_ws_url.into(),
            vault_url: vault_url.into(),
            web_url: web_url.into(),
            oauth_client_id: "pool-desktop".into(),
            dev,
            bench_duration_override_s: None,
            runner_path: None,
            model_cache_gb: 20,
            prefer_tpm: true,
            ort_pack_dir: None,
            use_gpu: true,
            dev_trust_roots: vec![],
        }
    }
}

impl Config {
    /// `config.json` in the data dir, then `POOL_*` environment overrides.
    pub fn load(data_dir: &Path) -> Self {
        let mut c: Config = std::fs::read(data_dir.join("config.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if let Ok(v) = std::env::var("POOL_ENGINE_WS_URL") {
            c.engine_ws_url = v;
        }
        if let Ok(v) = std::env::var("POOL_VAULT_URL") {
            c.vault_url = v;
        }
        if let Ok(v) = std::env::var("POOL_WEB_URL") {
            c.web_url = v;
        }
        if let Ok(v) = std::env::var("POOL_RUNNER_PATH") {
            c.runner_path = Some(v.into());
        }
        if cfg!(feature = "dev-trust") {
            c
        } else {
            c.pinned_to_release()
        }
    }

    /// Release builds talk only to the release hosts: endpoint values from `config.json` or `POOL_*_URL` are
    /// replaced (and logged), so neither a local dev stack nor a host planted in the config can be used, and the
    /// dev switches are off.
    pub fn pinned_to_release(mut self) -> Self {
        for (field, fixed) in [
            (&mut self.engine_ws_url, RELEASE_ENGINE_WS_URL),
            (&mut self.vault_url, RELEASE_VAULT_URL),
            (&mut self.web_url, RELEASE_WEB_URL),
        ] {
            if field.as_str() != fixed {
                tracing::warn!("release build: endpoint {field} ignored, using {fixed}");
                *field = fixed.to_string();
            }
        }
        self.dev = false;
        self.bench_duration_override_s = None;
        self.dev_trust_roots.clear();
        self
    }

    /// The zero exporter / plain ws:// path is only possible in dev builds with dev mode on.
    pub fn allow_insecure_dev(&self) -> bool {
        cfg!(feature = "dev-trust") && self.dev
    }

    /// Where to look for the GPU backend pack (`None` when the GPU path is off).
    pub fn ort_pack_dir(&self) -> Option<PathBuf> {
        if !self.use_gpu {
            return None;
        }
        if let Some(p) = &self.ort_pack_dir {
            return Some(p.clone());
        }
        let exe = std::env::current_exe().ok()?;
        Some(exe.parent()?.join("backends").join("ort-directml"))
    }

    pub fn runner_exe(&self) -> PathBuf {
        if let Some(p) = &self.runner_path {
            return p.clone();
        }
        let exe = std::env::current_exe().unwrap_or_default();
        let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = if cfg!(windows) { "pool-runner.exe" } else { "pool-runner" };
        // Tauri bundles sidecars with the target-triple suffix stripped, next to the app binary.
        dir.join(name)
    }
}

/// Persisted agent state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    pub device_id: Option<String>,
    pub device_key_id: Option<String>,
    pub trust_ceiling: Option<String>,
    /// Highest KeySet version accepted (rollback protection).
    pub keyset_max_version: u64,
    pub settings: Settings,
    /// Sealed (DPAPI on Windows) refresh token of the read-only device-link grant, base64.
    pub refresh_token_sealed: Option<String>,
    pub account_email: Option<String>,
    /// Local day (days since epoch, local) and seconds worked on it.
    pub worked_day: u64,
    pub worked_today_s: u64,
    pub benchmark: Option<BenchmarkStatus>,
    /// The in-app `hw_identifiers` consent. `None` = not asked or withdrawn; `Some(false)` = refused.
    pub hw_consent: Option<HwConsent>,
    /// Weekly hardware-identifier report bookkeeping: timestamps only, never an identifier.
    pub hw_report_last_sent_ms: Option<u64>,
    pub hw_report_last_attempt_ms: Option<u64>,
    /// Persisted name of the TPM device key after a key rotation (`None` = the default name).
    pub tpm_key_name: Option<String>,
}

/// The consent the user gave (or refused) in the app, with the exact text version shown.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HwConsent {
    pub accepted: bool,
    pub version: String,
    pub text_sha256: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkStatus {
    pub benchmark_id: String,
    pub state: String, // "running" | "sent" | "received" | "failed"
    pub started_ms: u64,
    pub duration_s: u64,
    pub finished_ms: Option<u64>,
}

pub fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("POOL_DATA_DIR") {
        return d.into();
    }
    // `<local data dir>/<bundle id>`: Windows `%LOCALAPPDATA%\com.vouchcompute.app[.dev]`, Linux
    // `~/.local/share/com.vouchcompute.app[.dev]`, macOS `~/Library/Application Support/com.vouchcompute.app[.dev]`.
    directories::BaseDirs::new()
        .map(|b| b.data_local_dir().join(pool_proto::BUNDLE_ID))
        .unwrap_or_else(|| std::env::temp_dir().join(pool_proto::BUNDLE_ID))
}

impl State {
    pub fn load(data_dir: &Path) -> Self {
        std::fs::read(data_dir.join("state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Atomic write (temp file + rename).
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let tmp = data_dir.join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        #[cfg(unix)]
        {
            // holds the (sealed on Windows) refresh token: readable by its user only on Unix
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(tmp, data_dir.join("state.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a release build does with a config pointing at a dev stack or another host: the release hosts win.
    #[test]
    fn release_builds_refuse_dev_and_foreign_endpoints() {
        let planted = Config {
            engine_ws_url: "ws://127.0.0.1:8000/node/v1/connect".into(),
            vault_url: "http://127.0.0.1:8100".into(),
            web_url: "https://vouchcompute.com.evil.example".into(),
            dev: true,
            bench_duration_override_s: Some(5),
            dev_trust_roots: vec!["AAAA".into()],
            ..Config::default()
        };
        let c = planted.pinned_to_release();
        assert_eq!(c.engine_ws_url, "wss://api.vouchcompute.com/node/v1/connect");
        assert_eq!(c.vault_url, "https://enroll.vouchcompute.com");
        assert_eq!(c.web_url, "https://www.vouchcompute.com");
        assert!(!c.dev && c.bench_duration_override_s.is_none() && c.dev_trust_roots.is_empty());
        assert!(!c.allow_insecure_dev());
    }

    #[test]
    fn state_roundtrip_and_defaults() {
        let d = tempfile::tempdir().unwrap();
        let s = State::load(d.path());
        assert_eq!(s, State::default());
        assert_eq!(s.settings.mode, crate::governor::Mode::IdleOnly);
        let mut s2 = s.clone();
        s2.device_id = Some("x".into());
        s2.keyset_max_version = 3;
        s2.save(d.path()).unwrap();
        assert_eq!(State::load(d.path()), s2);
        let c = Config::load(d.path());
        assert!(c.engine_ws_url.starts_with("ws"));
    }
}
