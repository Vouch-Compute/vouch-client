//! Live agent status, shown by the app (no job content, no verification detail).

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::governor::Decision;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    NotSignedIn,
    NotEnrolled,
    Connecting,
    Connected,
    Offline,
    AuthFailed,
    UpdateRequired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentJob {
    pub model_id: String,
    pub since_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchProgress {
    pub benchmark_id: String,
    pub state: String,
    pub started_ms: u64,
    pub duration_s: u64,
    pub segments: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub connection: Connection,
    pub decision: Decision,
    pub job: Option<CurrentJob>,
    pub jobs_completed: u64,
    pub jobs_abandoned: u64,
    pub benchmark: Option<BenchProgress>,
    pub sandbox: Option<String>,
    pub last_error: Option<String>,
    pub reconnect_in_s: Option<u64>,
    /// Account notices from the server (node protocol 1.2.0 `AccountNotice`): banners only, no reason text.
    pub notices: Notices,
    /// How far the local clock is off the server clock (seconds), when more than 5 s. Signed timestamps use the
    /// server clock anyway; the app shows a hint so the user can fix the clock.
    #[serde(default)]
    pub clock_offset_s: Option<i64>,
    /// Consecutive connection attempts that did not reach a session (drives the backoff; 0 after a Welcome).
    #[serde(default)]
    pub reconnect_attempts: u32,
    /// The runtime that ran the last job (`onnxruntime-directml`, `candle-cuda`, `candle-cpu`,...).
    #[serde(default)]
    pub backend: Option<String>,
}

/// The banners `AccountNotice` drives. Reset at every new session: the server sends the ones that apply on connect.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Notices {
    /// `"user"` (paused from the web or the app) or `"tally"` (paused by Vouch Compute, the wire value stays), cleared by `RESUMED`.
    pub paused_by: Option<String>,
    pub recovery_in_progress: bool,
    pub reverify_required: bool,
}

impl Notices {
    /// Apply one `AccountNotice.kind`. Unknown kinds are ignored. Never changes how offers are treated.
    pub fn apply(&mut self, kind: i32) {
        use pool_proto::account_notice as k;
        match kind {
            k::PAUSED_BY_USER => self.paused_by = Some("user".into()),
            k::PAUSED_BY_TALLY => self.paused_by = Some("tally".into()),
            k::RESUMED => self.paused_by = None,
            k::RECOVERY_IN_PROGRESS => self.recovery_in_progress = true,
            k::REVERIFY_REQUIRED => self.reverify_required = true,
            _ => {}
        }
    }
}

impl Default for Status {
    fn default() -> Self {
        Self {
            connection: Connection::NotSignedIn,
            decision: Decision::Pause(crate::governor::PauseReason::UserActive),
            job: None,
            jobs_completed: 0,
            jobs_abandoned: 0,
            benchmark: None,
            sandbox: None,
            last_error: None,
            reconnect_in_s: None,
            notices: Notices::default(),
            clock_offset_s: None,
            reconnect_attempts: 0,
            backend: None,
        }
    }
}

#[derive(Default)]
pub struct StatusHub(Mutex<Status>);

impl StatusHub {
    pub fn get(&self) -> Status {
        self.0.lock().unwrap().clone()
    }
    pub fn update(&self, f: impl FnOnce(&mut Status)) {
        f(&mut self.0.lock().unwrap());
    }
}
