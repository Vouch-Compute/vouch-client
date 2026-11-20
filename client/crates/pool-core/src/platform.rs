//! OS readings for the governor and hardware claims. Readings are informational: nothing here is ever
//! used for pay (the server's signed benchmark decides eligibility; device-reported values are never trusted).
//!
//! * Windows: `GetLastInputInfo` (idle), `SHQueryUserNotificationState` (fullscreen D3D / presentation /
//!   busy), `GetSystemPowerStatus` (AC, battery), NVML (GPU temperature).
//! * macOS: `ioreg -c IOHIDSystem` HIDIdleTime, `pmset -g batt`.
//! * Linux: logind `IdleHint` via `loginctl`, `/sys/class/power_supply`, hwmon CPU temperature.

use crate::governor::Inputs;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Readings {
    pub idle_s: Option<u64>,
    pub fullscreen: bool,
    pub on_ac: Option<bool>,
    pub battery_pct: Option<u8>,
    pub gpu_temp_c: Option<f32>,
    pub cpu_temp_c: Option<f32>,
    /// GPU utilisation 0..100 (NVML), for the 1.2.0 heartbeat telemetry only.
    pub gpu_util_pct: Option<u32>,
}

pub fn read() -> Readings {
    let mut r = os::read();
    if r.gpu_temp_c.is_none() {
        r.gpu_temp_c = gpu::temp_c();
    }
    if r.gpu_util_pct.is_none() {
        r.gpu_util_pct = gpu::util_pct();
    }
    r
}

/// Local weekday (0 = Monday) and minute of day, from the OS local time.
pub fn local_time() -> (u8, u16) {
    os::local_time()
}

pub fn to_inputs(r: &Readings, now_ms: u64, worked_today_s: u64) -> Inputs {
    let (weekday, minute_of_day) = local_time();
    Inputs {
        idle_s: r.idle_s,
        fullscreen: r.fullscreen,
        on_ac: r.on_ac,
        battery_pct: r.battery_pct,
        gpu_temp_c: r.gpu_temp_c,
        cpu_temp_c: r.cpu_temp_c,
        weekday,
        minute_of_day,
        now_ms,
        worked_today_s,
    }
}

pub fn os_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

pub fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// The user-visible computer name, shown on face's `/app/link` as "reported by the app" so the
/// user can spot a relayed sign-in code. Windows: `COMPUTERNAME`; Unix: `gethostname`. Not a secret, not an id.
pub fn device_name() -> String {
    #[cfg(windows)]
    let name = std::env::var("COMPUTERNAME").ok();
    #[cfg(unix)]
    let name = {
        let mut buf = [0u8; 256];
        // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success when it fits.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        (rc == 0).then(|| {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        })
    };
    #[cfg(not(any(windows, unix)))]
    let name: Option<String> = None;
    name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or_else(|| "This computer".into())
}

/// Hardware claims: informational only ("We found an RTX 4070, 12 GB"), never used for pay.
pub fn hw_claims() -> pool_proto::objects::HwClaims {
    let cpu = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    let (gpu, vram_mb, driver) = gpu::info();
    pool_proto::objects::HwClaims {
        os: os_name().into(),
        arch: arch().into(),
        cpu,
        ram_mb: os::ram_mb(),
        gpu,
        vram_mb,
        driver,
        backend: Some("candle-cpu".into()),
    }
}

#[cfg(feature = "nvml")]
mod gpu {
    use std::sync::OnceLock;
    fn nvml() -> Option<&'static nvml_wrapper::Nvml> {
        static N: OnceLock<Option<nvml_wrapper::Nvml>> = OnceLock::new();
        N.get_or_init(|| nvml_wrapper::Nvml::init().ok()).as_ref()
    }
    pub fn temp_c() -> Option<f32> {
        let d = nvml()?.device_by_index(0).ok()?;
        d.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu).ok().map(|t| t as f32)
    }
    pub fn util_pct() -> Option<u32> {
        nvml()?.device_by_index(0).ok()?.utilization_rates().ok().map(|u| u.gpu)
    }
    pub fn info() -> (Option<String>, Option<u64>, Option<String>) {
        let Some(n) = nvml() else { return (None, None, None) };
        let Ok(d) = n.device_by_index(0) else { return (None, None, None) };
        (d.name().ok(), d.memory_info().ok().map(|m| m.total / (1024 * 1024)), n.sys_driver_version().ok())
    }
}

#[cfg(not(feature = "nvml"))]
mod gpu {
    pub fn temp_c() -> Option<f32> {
        None
    }
    pub fn util_pct() -> Option<u32> {
        None
    }
    pub fn info() -> (Option<String>, Option<u64>, Option<String>) {
        (None, None, None)
    }
}

#[cfg(windows)]
mod os {
    use super::Readings;
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows::Win32::System::SystemInformation::{GetLocalTime, GetTickCount, GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows::Win32::UI::Shell::{
        SHQueryUserNotificationState, QUNS_BUSY, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
    };

    pub fn read() -> Readings {
        let mut r = Readings::default();
        unsafe {
            let mut lii = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
            if GetLastInputInfo(&mut lii).as_bool() {
                r.idle_s = Some(u64::from(GetTickCount().wrapping_sub(lii.dwTime)) / 1000);
            }
            if let Ok(state) = SHQueryUserNotificationState() {
                r.fullscreen = state == QUNS_RUNNING_D3D_FULL_SCREEN || state == QUNS_PRESENTATION_MODE || state == QUNS_BUSY;
            }
            let mut ps = SYSTEM_POWER_STATUS::default();
            if GetSystemPowerStatus(&mut ps).is_ok() {
                r.on_ac = match ps.ACLineStatus {
                    0 => Some(false),
                    1 => Some(true),
                    _ => None,
                };
                // 128 = no system battery (desktop)
                if ps.BatteryFlag & 128 == 0 && ps.BatteryLifePercent <= 100 {
                    r.battery_pct = Some(ps.BatteryLifePercent);
                }
            }
        }
        r
    }

    pub fn local_time() -> (u8, u16) {
        let t = unsafe { GetLocalTime() };
        // wDayOfWeek: 0 = Sunday
        (((t.wDayOfWeek + 6) % 7) as u8, t.wHour * 60 + t.wMinute)
    }

    pub fn ram_mb() -> u64 {
        let mut m = MEMORYSTATUSEX { dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
        unsafe {
            if GlobalMemoryStatusEx(&mut m).is_ok() {
                return m.ullTotalPhys / (1024 * 1024);
            }
        }
        0
    }
}

#[cfg(unix)]
mod os {
    use super::Readings;

    fn cmd(prog: &str, args: &[&str]) -> Option<String> {
        let out = std::process::Command::new(prog).args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[cfg(target_os = "macos")]
    pub fn read() -> Readings {
        let mut r = Readings::default();
        if let Some(s) = cmd("ioreg", &["-c", "IOHIDSystem", "-d", "4"]) {
            if let Some(line) = s.lines().find(|l| l.contains("HIDIdleTime")) {
                if let Some(ns) = line.rsplit('=').next().and_then(|v| v.trim().parse::<u64>().ok()) {
                    r.idle_s = Some(ns / 1_000_000_000);
                }
            }
        }
        if let Some(s) = cmd("pmset", &["-g", "batt"]) {
            r.on_ac = Some(s.contains("AC Power"));
            if let Some(p) = s.split('%').next().and_then(|x| x.rsplit(|c: char| !c.is_ascii_digit()).next()) {
                r.battery_pct = p.parse().ok();
            }
        }
        r
    }

    #[cfg(not(target_os = "macos"))]
    pub fn read() -> Readings {
        let mut r = Readings::default();
        if let Ok(id) = std::env::var("XDG_SESSION_ID") {
            if let Some(s) = cmd("loginctl", &["show-session", &id, "-p", "IdleHint", "-p", "IdleSinceHint"]) {
                let idle = s.contains("IdleHint=yes");
                let since = s
                    .lines()
                    .find_map(|l| l.strip_prefix("IdleSinceHint="))
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                let now_us = pool_proto::now_ms() * 1000;
                r.idle_s = Some(if idle && since > 0 { now_us.saturating_sub(since) / 1_000_000 } else { 0 });
            }
        }
        if let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") {
            for e in rd.flatten() {
                let p = e.path();
                let t = std::fs::read_to_string(p.join("type")).unwrap_or_default();
                if t.trim() == "Mains" {
                    r.on_ac = std::fs::read_to_string(p.join("online")).ok().map(|v| v.trim() == "1");
                } else if t.trim() == "Battery" {
                    r.battery_pct = std::fs::read_to_string(p.join("capacity")).ok().and_then(|v| v.trim().parse().ok());
                }
            }
        }
        if let Ok(rd) = std::fs::read_dir("/sys/class/hwmon") {
            let mut max: Option<f32> = None;
            for e in rd.flatten() {
                for i in 1..8 {
                    if let Some(v) = std::fs::read_to_string(e.path().join(format!("temp{i}_input")))
                        .ok()
                        .and_then(|v| v.trim().parse::<f32>().ok())
                    {
                        let c = v / 1000.0;
                        max = Some(max.map_or(c, |m: f32| m.max(c)));
                    }
                }
            }
            r.cpu_temp_c = max;
        }
        r
    }

    pub fn local_time() -> (u8, u16) {
        unsafe {
            let t = libc::time(std::ptr::null_mut());
            let mut tm: libc::tm = std::mem::zeroed();
            libc::localtime_r(&t, &mut tm);
            (((tm.tm_wday + 6) % 7) as u8, (tm.tm_hour * 60 + tm.tm_min) as u16)
        }
    }

    pub fn ram_mb() -> u64 {
        unsafe {
            let pages = libc::sysconf(libc::_SC_PHYS_PAGES);
            let size = libc::sysconf(libc::_SC_PAGESIZE);
            if pages > 0 && size > 0 {
                return (pages as u64 * size as u64) / (1024 * 1024);
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn readings_do_not_panic_and_time_is_sane() {
        let r = super::read();
        if let Some(b) = r.battery_pct {
            assert!(b <= 100);
        }
        let (d, m) = super::local_time();
        assert!(d < 7 && m < 24 * 60);
        assert!(super::hw_claims().ram_mb > 0);
    }
}
