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
    #[serde(default)]
    pub model_id: String,
    /// What this app has measured so far in the benchmark window (display only, see [`Measured`]).
    #[serde(default)]
    pub measured: Option<Measured>,
}

/// Throughput the app measured on this computer during a benchmark, for the user to see. **Display only:** it is
/// never sent to the server and never used for pay. The server derives the rate it uses from the signed benchmark
/// timing and assigns the units itself; the user sees the server's status and tier next to this number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Measured {
    /// `token` (embeddings: tokens embedded) or `audio_second` (transcription: seconds of audio transcribed).
    pub unit: String,
    /// Units per second of wall time over the measured window (after the warm-up run).
    pub per_second: f64,
    /// Runs finished in the measured window.
    pub runs: u64,
    /// The runtime that ran them (`onnxruntime-cpu`, `onnxruntime-directml`, `candle-metal`,...).
    pub backend: Option<String>,
}

/// The last finished benchmark per model, kept in `state.json` so the result is still shown after a restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeasuredPerformance {
    pub model_id: String,
    pub benchmark_id: String,
    pub measured: Measured,
    pub finished_ms: u64,
    /// The server confirmed it stored the signed result (`BenchmarkReceipt` RECEIVED).
    #[serde(default)]
    pub received: bool,
}

/// How many models' results are kept.
pub const MAX_MEASURED_MODELS: usize = 8;

/// Insert or replace the result for its model (newest first, at most [`MAX_MEASURED_MODELS`]).
pub fn record_performance(list: &mut Vec<MeasuredPerformance>, p: MeasuredPerformance) {
    list.retain(|x| x.model_id != p.model_id);
    list.insert(0, p);
    list.truncate(MAX_MEASURED_MODELS);
}

/// Mark the result of `benchmark_id` as received by the server. Returns whether one changed.
pub fn mark_received(list: &mut [MeasuredPerformance], benchmark_id: &str) -> bool {
    match list.iter_mut().find(|x| x.benchmark_id == benchmark_id && !x.received) {
        Some(x) => {
            x.received = true;
            true
        }
        None => false,
    }
}

/// The unit a model's benchmark is measured in, from its input format.
pub fn unit_for(input_format: &str) -> &'static str {
    if input_format == pool_proto::CANONICAL_AUDIO_FORMAT {
        "audio_second"
    } else {
        "token"
    }
}

/// Running totals of a benchmark window.
#[derive(Debug, Default, Clone)]
pub struct Meter {
    units_milli: u64,
    runs: u64,
    reported: bool,
}

impl Meter {
    /// Count one run that finished inside the window. `units_milli` is what the runtime reported (`None`: the backend
    /// reports no units, and nothing is shown).
    pub fn add(&mut self, units_milli: Option<u64>) {
        self.runs += 1;
        if let Some(u) = units_milli {
            self.units_milli = self.units_milli.saturating_add(u);
            self.reported = true;
        }
    }

    /// The rate over `window_ms` (window start to the end of the last counted run).
    pub fn measured(&self, unit: &str, window_ms: u64, backend: Option<String>) -> Option<Measured> {
        if !self.reported || self.runs == 0 || window_ms == 0 {
            return None;
        }
        let per_second = (self.units_milli as f64 / 1000.0) / (window_ms as f64 / 1000.0);
        per_second.is_finite().then(|| Measured { unit: unit.to_string(), per_second, runs: self.runs, backend })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_reports_units_per_second_of_the_window() {
        let mut m = Meter::default();
        assert_eq!(m.measured("token", 1000, None), None, "nothing measured yet");
        m.add(Some(120_000));
        m.add(Some(120_000));
        let r = m.measured("token", 2000, Some("onnxruntime-cpu".into())).unwrap();
        assert_eq!((r.per_second, r.runs, r.unit.as_str(), r.backend.as_deref()), (120.0, 2, "token", Some("onnxruntime-cpu")));
        assert_eq!(m.measured("token", 0, None), None);
        let mut silent = Meter::default();
        silent.add(None);
        assert_eq!(silent.measured("token", 1000, None), None, "a backend without units shows nothing");
        assert_eq!(unit_for(pool_proto::CANONICAL_AUDIO_FORMAT), "audio_second");
        assert_eq!(unit_for(pool_proto::EMBED_BATCH_FORMAT), "token");
    }

    #[test]
    fn one_result_per_model_newest_first() {
        let p = |model: &str, id: &str| MeasuredPerformance {
            model_id: model.into(),
            benchmark_id: id.into(),
            measured: Measured { unit: "token".into(), per_second: 1.0, runs: 1, backend: None },
            finished_ms: 1,
            received: false,
        };
        let mut l = Vec::new();
        record_performance(&mut l, p("bge-m3", "b1"));
        record_performance(&mut l, p("bge-small", "b2"));
        record_performance(&mut l, p("bge-m3", "b3"));
        assert_eq!(l.iter().map(|x| x.benchmark_id.as_str()).collect::<Vec<_>>(), ["b3", "b2"]);
        assert!(!mark_received(&mut l, "b1"), "a replaced result is not marked");
        assert!(mark_received(&mut l, "b3"));
        assert!(!mark_received(&mut l, "b3"), "only once");
        assert!(l[0].received);
        for i in 0..20 {
            record_performance(&mut l, p(&format!("m{i}"), "x"));
        }
        assert_eq!(l.len(), MAX_MEASURED_MODELS);
    }
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
