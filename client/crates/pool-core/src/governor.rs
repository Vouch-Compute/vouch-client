//! Resource governor: decides whether the device may work right now. Pure logic (testable); the OS
//! readings come from `platform.rs`.
//!
//! Defaults: **idle-only** (start after 10 min without
//! input, stop on input), pause in fullscreen/games, never on battery, GPU temperature cap 80 °C with 5 °C
//! hysteresis. Hard limits that settings cannot override: 90 °C, no work on battery below 30 %.

use serde::{Deserialize, Serialize};

pub const HARD_MAX_TEMP_C: f32 = 90.0;
pub const HARD_MIN_BATTERY_PCT: u8 = 30;
pub const THERMAL_HYSTERESIS_C: f32 = 5.0;
pub const TEMP_CAP_RANGE: (u8, u8) = (65, 85);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    IdleOnly,
    Scheduled,
    AlwaysOn,
}

/// A weekly window: `days` bitmask (bit 0 = Monday ... bit 6 = Sunday), local minutes [start, end).
/// `end < start` wraps past midnight.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub days: u8,
    pub start_min: u16,
    pub end_min: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: Mode,
    pub idle_minutes: u32,
    pub temp_cap_c: u8,
    /// Share of time the runner may use the GPU/CPU (duty cycle), 10..=100.
    pub power_pct: u8,
    pub never_on_battery: bool,
    pub pause_in_fullscreen: bool,
    pub schedule: Vec<Window>,
    /// Upper bound on working hours per local day (None = no cap).
    pub daily_cap_hours: Option<f32>,
    /// Paused by the user until this time (ms since epoch).
    pub paused_until_ms: Option<u64>,
    /// Accept the signed sustained benchmark even when not idle (user pressed "Run benchmark now").
    pub benchmark_now: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::IdleOnly,
            idle_minutes: 10,
            temp_cap_c: 80,
            power_pct: 100,
            never_on_battery: true,
            pause_in_fullscreen: true,
            schedule: vec![],
            daily_cap_hours: None,
            paused_until_ms: None,
            benchmark_now: false,
        }
    }
}

impl Settings {
    /// Clamp user-supplied values into their allowed ranges.
    pub fn sanitized(mut self) -> Self {
        self.temp_cap_c = self.temp_cap_c.clamp(TEMP_CAP_RANGE.0, TEMP_CAP_RANGE.1);
        self.idle_minutes = self.idle_minutes.clamp(1, 240);
        self.power_pct = self.power_pct.clamp(10, 100);
        self.daily_cap_hours = self.daily_cap_hours.map(|h| h.clamp(0.5, 24.0));
        for w in &mut self.schedule {
            w.start_min = w.start_min.min(24 * 60 - 1);
            w.end_min = w.end_min.min(24 * 60);
            w.days &= 0x7f;
        }
        self
    }
}

/// Current readings. `None` means "unknown on this platform".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inputs {
    pub idle_s: Option<u64>,
    pub fullscreen: bool,
    pub on_ac: Option<bool>,
    pub battery_pct: Option<u8>,
    pub gpu_temp_c: Option<f32>,
    pub cpu_temp_c: Option<f32>,
    /// Local weekday (0 = Monday) and minute of day.
    pub weekday: u8,
    pub minute_of_day: u16,
    pub now_ms: u64,
    /// Seconds already worked today (local day).
    pub worked_today_s: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    PausedByUser,
    UserActive,
    Fullscreen,
    OnBattery,
    BatteryLow,
    Thermal,
    OutsideSchedule,
    DailyCapReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum Decision {
    Run,
    Pause(PauseReason),
}

impl Decision {
    pub fn is_run(&self) -> bool {
        matches!(self, Decision::Run)
    }
    /// Pauses that mean "the user is back": running work must be pre-empted within 5 s.
    pub fn preempts(&self) -> bool {
        matches!(self, Decision::Pause(PauseReason::UserActive | PauseReason::Fullscreen | PauseReason::PausedByUser))
    }
}

impl Window {
    pub fn contains(&self, weekday: u8, minute: u16) -> bool {
        let day_bit = |d: u8| self.days & (1 << (d % 7)) != 0;
        if self.start_min <= self.end_min {
            day_bit(weekday) && minute >= self.start_min && minute < self.end_min
        } else {
            // wraps midnight: the part before midnight belongs to `weekday`, the part after to the previous day
            (day_bit(weekday) && minute >= self.start_min) || (day_bit((weekday + 6) % 7) && minute < self.end_min)
        }
    }
}

#[derive(Debug, Default)]
pub struct Governor {
    thermal_paused: bool,
}

impl Governor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decide(&mut self, s: &Settings, i: &Inputs) -> Decision {
        use PauseReason::*;
        // hard limits first
        // A non-finite reading (NaN from a failing sensor) is "unknown". Before, a NaN compared false against
        // the cap, so a lone NaN reading ran the device and even cleared an active thermal pause.
        let temp = i
            .gpu_temp_c
            .into_iter()
            .chain(i.cpu_temp_c)
            .filter(|t| t.is_finite())
            .fold(None, |m: Option<f32>, t| Some(m.map_or(t, |m| m.max(t))));
        if temp.is_none() && self.thermal_paused {
            // the sensor vanished while hot: stay paused until a real reading shows it cooled down
            return Decision::Pause(Thermal);
        }
        if let Some(t) = temp {
            let cap = (s.temp_cap_c as f32).min(HARD_MAX_TEMP_C);
            let resume_below = cap - THERMAL_HYSTERESIS_C;
            if t >= cap || (self.thermal_paused && t > resume_below) {
                self.thermal_paused = true;
                return Decision::Pause(Thermal);
            }
            self.thermal_paused = false;
        }
        if i.on_ac == Some(false) {
            if i.battery_pct.is_some_and(|b| b < HARD_MIN_BATTERY_PCT) {
                return Decision::Pause(BatteryLow);
            }
            if s.never_on_battery {
                return Decision::Pause(OnBattery);
            }
        }
        if s.paused_until_ms.is_some_and(|u| u > i.now_ms) {
            return Decision::Pause(PausedByUser);
        }
        if s.pause_in_fullscreen && i.fullscreen {
            return Decision::Pause(Fullscreen);
        }
        if let Some(cap) = s.daily_cap_hours {
            if i.worked_today_s as f32 >= cap * 3600.0 {
                return Decision::Pause(DailyCapReached);
            }
        }
        match s.mode {
            Mode::AlwaysOn => Decision::Run,
            Mode::Scheduled => {
                if s.schedule.iter().any(|w| w.contains(i.weekday, i.minute_of_day)) {
                    Decision::Run
                } else {
                    Decision::Pause(OutsideSchedule)
                }
            }
            Mode::IdleOnly => match i.idle_s {
                Some(idle) if idle >= u64::from(s.idle_minutes) * 60 => Decision::Run,
                // unknown idle state: be conservative, the user may be there
                _ => Decision::Pause(UserActive),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle(min: u64) -> Inputs {
        Inputs { idle_s: Some(min * 60), on_ac: Some(true), weekday: 2, minute_of_day: 600, now_ms: 1_000, ..Default::default() }
    }

    #[test]
    fn defaults_are_idle_only_and_safe() {
        let s = Settings::default();
        assert_eq!(s.mode, Mode::IdleOnly);
        assert!(s.never_on_battery && s.pause_in_fullscreen);
        assert_eq!((s.idle_minutes, s.temp_cap_c), (10, 80));
        let mut g = Governor::new();
        assert_eq!(g.decide(&s, &idle(9)), Decision::Pause(PauseReason::UserActive));
        assert_eq!(g.decide(&s, &idle(10)), Decision::Run);
        // user returns -> pause that pre-empts
        let d = g.decide(&s, &Inputs { idle_s: Some(0), ..idle(0) });
        assert!(d.preempts());
        // unknown idle is treated as "user present"
        assert_eq!(g.decide(&s, &Inputs { idle_s: None, ..idle(0) }), Decision::Pause(PauseReason::UserActive));
    }

    #[test]
    fn thermal_cap_with_hysteresis_and_hard_limit() {
        let s = Settings { mode: Mode::AlwaysOn, ..Default::default() };
        let mut g = Governor::new();
        let at = |t: f32| Inputs { gpu_temp_c: Some(t), ..idle(0) };
        assert_eq!(g.decide(&s, &at(79.0)), Decision::Run);
        assert_eq!(g.decide(&s, &at(80.0)), Decision::Pause(PauseReason::Thermal));
        assert_eq!(g.decide(&s, &at(76.0)), Decision::Pause(PauseReason::Thermal), "hysteresis holds");
        assert_eq!(g.decide(&s, &at(75.0)), Decision::Run, "resumes at cap - 5");
        // a user cap above the allowed range is clamped; the hard 90 °C cannot be exceeded
        let hot = Settings { temp_cap_c: 120, mode: Mode::AlwaysOn, ..Default::default() }.sanitized();
        assert_eq!(hot.temp_cap_c, 85);
        let raw = Settings { temp_cap_c: 120, mode: Mode::AlwaysOn, ..Default::default() };
        let mut g = Governor::new();
        assert_eq!(g.decide(&raw, &at(90.0)), Decision::Pause(PauseReason::Thermal));
        // CPU temperature counts too
        let mut g = Governor::new();
        assert_eq!(g.decide(&s, &Inputs { cpu_temp_c: Some(85.0), ..idle(0) }), Decision::Pause(PauseReason::Thermal));
    }

    #[test]
    fn battery_rules() {
        let mut g = Governor::new();
        let on_batt = |pct| Inputs { on_ac: Some(false), battery_pct: Some(pct), ..idle(30) };
        assert_eq!(g.decide(&Settings::default(), &on_batt(90)), Decision::Pause(PauseReason::OnBattery));
        let allow = Settings { never_on_battery: false, ..Default::default() };
        assert_eq!(g.decide(&allow, &on_batt(90)), Decision::Run);
        assert_eq!(g.decide(&allow, &on_batt(29)), Decision::Pause(PauseReason::BatteryLow), "hard floor");
    }

    #[test]
    fn fullscreen_pause_and_user_pause() {
        let mut g = Governor::new();
        let s = Settings::default();
        assert_eq!(g.decide(&s, &Inputs { fullscreen: true, ..idle(30) }), Decision::Pause(PauseReason::Fullscreen));
        let paused = Settings { paused_until_ms: Some(5_000), ..Default::default() };
        assert_eq!(g.decide(&paused, &idle(30)), Decision::Pause(PauseReason::PausedByUser));
        assert_eq!(g.decide(&paused, &Inputs { now_ms: 5_001, ..idle(30) }), Decision::Run);
    }

    #[test]
    fn schedule_windows_and_daily_cap() {
        // weeknights 22:00-06:00 (Mon..Fri start days)
        let w = Window { days: 0b0011111, start_min: 22 * 60, end_min: 6 * 60 };
        assert!(w.contains(0, 23 * 60)); // Mon 23:00
        assert!(w.contains(1, 5 * 60)); // Tue 05:00 (from Monday's window)
        assert!(!w.contains(0, 5 * 60)); // Mon 05:00 belongs to Sunday's window: Sunday not selected
        assert!(w.contains(5, 3 * 60)); // Sat 03:00 from Friday night
        assert!(!w.contains(5, 23 * 60)); // Sat 23:00 not selected
        let s = Settings { mode: Mode::Scheduled, schedule: vec![w], ..Default::default() };
        let mut g = Governor::new();
        let at = |d, m| Inputs { weekday: d, minute_of_day: m, ..idle(0) };
        assert_eq!(g.decide(&s, &at(0, 23 * 60)), Decision::Run);
        assert_eq!(g.decide(&s, &at(0, 12 * 60)), Decision::Pause(PauseReason::OutsideSchedule));
        let capped = Settings { daily_cap_hours: Some(2.0), ..s };
        assert_eq!(
            g.decide(&capped, &Inputs { worked_today_s: 7200, ..at(0, 23 * 60) }),
            Decision::Pause(PauseReason::DailyCapReached)
        );
    }

    /// Failing sensors. A NaN reading is unknown: it never runs a hot device and never clears a thermal pause.
    #[test]
    fn non_finite_temperatures_fail_safe() {
        let s = Settings { mode: Mode::AlwaysOn, ..Default::default() };
        let mut g = Governor::new();
        let at = |t: Option<f32>| Inputs { gpu_temp_c: t, ..idle(0) };
        assert_eq!(g.decide(&s, &at(Some(f32::NAN))), Decision::Run, "unknown temperature on a cool device");
        assert_eq!(g.decide(&s, &at(Some(88.0))), Decision::Pause(PauseReason::Thermal));
        assert_eq!(g.decide(&s, &at(Some(f32::NAN))), Decision::Pause(PauseReason::Thermal), "NaN must not clear the pause");
        assert_eq!(g.decide(&s, &at(None)), Decision::Pause(PauseReason::Thermal), "a vanished sensor must not clear it");
        assert_eq!(g.decide(&s, &at(Some(f32::INFINITY))), Decision::Pause(PauseReason::Thermal));
        assert_eq!(g.decide(&s, &at(Some(70.0))), Decision::Run, "a real cool reading resumes");
        // a NaN GPU next to a hot CPU still pauses
        let mut g = Governor::new();
        assert_eq!(g.decide(&s, &Inputs { gpu_temp_c: Some(f32::NAN), cpu_temp_c: Some(91.0), ..idle(0) }), Decision::Pause(PauseReason::Thermal));
    }

    use proptest::prelude::*;

    fn any_settings() -> impl Strategy<Value = Settings> {
        (
            prop_oneof![Just(Mode::IdleOnly), Just(Mode::Scheduled), Just(Mode::AlwaysOn)],
            any::<u32>(),
            any::<u8>(),
            any::<u8>(),
            any::<bool>(),
            any::<bool>(),
            proptest::option::of(-10.0f32..100.0),
            proptest::option::of(any::<u64>()),
            proptest::collection::vec((any::<u8>(), any::<u16>(), any::<u16>()), 0..3),
        )
            .prop_map(|(mode, idle_minutes, temp_cap_c, power_pct, nob, pif, cap, paused, w)| Settings {
                mode,
                idle_minutes,
                temp_cap_c,
                power_pct,
                never_on_battery: nob,
                pause_in_fullscreen: pif,
                schedule: w.into_iter().map(|(days, start_min, end_min)| Window { days, start_min, end_min }).collect(),
                daily_cap_hours: cap,
                paused_until_ms: paused,
                benchmark_now: false,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

        /// The hard limits hold for every possible setting (raw or sanitized) and every reading sequence:
        /// never Run at >= 90 C, never Run on battery below 30 %, never Run while the user pause is active, never
        /// Run with an unknown idle state in idle-only mode. And nothing panics.
        #[test]
        fn hard_limits_hold_for_any_settings(
            s in any_settings(),
            sanitize in any::<bool>(),
            seq in proptest::collection::vec((proptest::option::of(-50.0f32..150.0), proptest::option::of(any::<bool>()), proptest::option::of(0u8..=100), proptest::option::of(any::<u64>()), any::<bool>(), 0u8..7, 0u16..1440, any::<u64>(), any::<u64>()), 1..12),
        ) {
            let s = if sanitize { s.sanitized() } else { s };
            let mut g = Governor::new();
            for (temp, on_ac, batt, idle_s, fullscreen, weekday, minute_of_day, now_ms, worked) in seq {
                let i = Inputs { idle_s, fullscreen, on_ac, battery_pct: batt, gpu_temp_c: temp, cpu_temp_c: None, weekday, minute_of_day, now_ms, worked_today_s: worked };
                let d = g.decide(&s, &i);
                if d.is_run() {
                    prop_assert!(temp.is_none_or(|t| t < HARD_MAX_TEMP_C), "ran at {temp:?}");
                    prop_assert!(!(on_ac == Some(false) && batt.is_some_and(|b| b < HARD_MIN_BATTERY_PCT)), "ran on low battery");
                    prop_assert!(!s.paused_until_ms.is_some_and(|u| u > now_ms), "ran while paused by the user");
                    if s.mode == Mode::IdleOnly {
                        prop_assert!(idle_s.is_some(), "ran with unknown idle state");
                    }
                }
            }
            let c = s.clone().sanitized();
            prop_assert!((TEMP_CAP_RANGE.0..=TEMP_CAP_RANGE.1).contains(&c.temp_cap_c));
            prop_assert!((10..=100).contains(&c.power_pct) && (1..=240).contains(&c.idle_minutes));
        }
    }
}
