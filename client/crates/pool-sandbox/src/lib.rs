//! Launching `pool-runner` inside the OS sandbox (used by `pool-core` and the runner's tests). Same contract on every OS:
//! no network, no read access outside the model bundle dir (plus system libraries), no writes,
//! no child processes, capped memory, no crash dumps, I/O over pipes only.
//!
//! | OS      | Mechanism (implemented)                                                                 | Level reported |
//! |---------|-----------------------------------------------------------------------------------------|----------------|
//! | Windows | Less-Privileged AppContainer (no capabilities => no network, no user files) + Job Object (kill on close, 1 process, memory cap, UI limits) + child-process policy; plain AppContainer if LPAC is refused | `windows-lpac` / `windows-appcontainer` |
//! | Linux   | parent: new user+network namespace (`unshare`), `RLIMIT_DATA`/`RLIMIT_CORE`, `PDEATHSIG`; runner: Landlock + seccomp (`harden.rs`). If namespaces are blocked (Ubuntu 24.04 AppArmor policy without our profile), seccomp+Landlock still apply | `linux-userns` / `linux-seccomp-landlock` |
//! | macOS   | `sandbox-exec` with a deny-default SBPL profile (no network, read-only model dir + system libs, no writes, no exec except the runner, metadata and sysctl reads allow-listed) + a memory watchdog that kills the runner over its cap (macOS applies no memory rlimit) | `macos-sandbox-exec` |
//!
//! Production designs that need signing/packaging (release setup): macOS App Sandbox entitlements on a separately signed helper, the Linux
//! AppArmor profile shipped in the .deb (`packaging/linux/apparmor/vouchcompute-runner`), bubblewrap when present.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxLevel {
    WindowsLpac,
    WindowsAppcontainer,
    LinuxUserns,
    LinuxSeccompLandlock,
    MacosSandboxExec,
    /// Only for the test control run; never used for jobs.
    None,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Directories the runner may read (the model bundle dir). Everything else is denied.
    pub readable_dirs: Vec<PathBuf>,
    /// Job memory cap in bytes (macOS: a soft cap, enforced by a footprint watchdog in the agent).
    pub memory_limit_bytes: u64,
    /// Hard cap on the runner's share of the machine's total CPU time, in percent (1..=100). Windows enforces
    /// it with the Job Object's CPU rate control (hard cap); Linux and macOS have no unprivileged equivalent, so
    /// there the runner only runs at a lower scheduling priority (`nice` 10). `None` = no cap.
    pub cpu_rate_pct: Option<u8>,
    /// Windows: try a Less-Privileged AppContainer first (default). `false` starts a regular AppContainer directly.
    pub lpac: bool,
    /// Extra environment variables. The runner gets a minimal environment, never the parent's.
    pub env: Vec<(String, String)>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self { readable_dirs: vec![], memory_limit_bytes: 8 << 30, cpu_rate_pct: None, lpac: true, env: vec![] }
    }
}

/// Kills the whole sandboxed process tree (pre-emption). Cloneable and callable from any thread.
#[derive(Clone)]
pub struct KillHandle(Arc<dyn Fn() + Send + Sync>);

impl KillHandle {
    pub fn kill(&self) {
        (self.0)()
    }
    pub(crate) fn new(f: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }
}

pub trait SandboxProcess: Send {
    /// Block until exit; returns the exit code.
    fn wait(&mut self) -> io::Result<i32>;
    fn kill_handle(&self) -> KillHandle;
}

pub struct Spawned {
    pub stdin: Box<dyn Write + Send>,
    pub stdout: Box<dyn Read + Send>,
    pub stderr: Box<dyn Read + Send>,
    pub process: Box<dyn SandboxProcess>,
    pub level: SandboxLevel,
}

/// Start `exe args...` inside the strongest sandbox available on this OS.
/// Remove what the sandbox left on the system (the Windows AppContainer profiles); nothing to do elsewhere.
pub fn remove_os_profiles() {
    #[cfg(windows)]
    windows::remove_profiles();
}

pub fn spawn_sandboxed(exe: &Path, args: &[String], cfg: &SandboxConfig) -> io::Result<Spawned> {
    #[cfg(windows)]
    {
        windows::spawn(exe, args, cfg)
    }
    #[cfg(unix)]
    {
        unix::spawn(exe, args, cfg, true)
    }
}

/// Start without a sandbox. Only the sandbox tests use this, as a control run.
pub fn spawn_unsandboxed(exe: &Path, args: &[String], cfg: &SandboxConfig) -> io::Result<Spawned> {
    #[cfg(windows)]
    {
        windows::spawn_plain(exe, args, cfg)
    }
    #[cfg(unix)]
    {
        unix::spawn(exe, args, cfg, false)
    }
}

/// Minimal environment passed to the runner (plus `cfg.env`).
pub(crate) fn base_env(cfg: &SandboxConfig) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    // Windows: CreateProcess for an AppContainer rewrites LOCALAPPDATA/TEMP/TMP to the container's own
    // folder and fails with ERROR_ENVVAR_NOT_FOUND if they are missing; the container can't read the
    // user's real folders anyway.
    for k in [
        "SystemRoot", "SYSTEMROOT", "windir", "PATH", "LANG", "TZ", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP",
    ] {
        if let Ok(v) = std::env::var(k) {
            if k == "PATH" && cfg!(windows) {
                // only the system directory, never user-writable PATH entries
                if let Ok(root) = std::env::var("SystemRoot") {
                    env.push((k.into(), format!("{root}\\System32")));
                }
                continue;
            }
            env.push((k.into(), v));
        }
    }
    // the dev trust-root override reaches the runner only in dev-trust builds
    #[cfg(feature = "dev-trust")]
    if let Ok(v) = std::env::var("POOL_DEV_TRUST_ROOTS") {
        env.push(("POOL_DEV_TRUST_ROOTS".into(), v));
    }
    for k in ["RUST_LOG", "RUST_BACKTRACE"] {
        if let Ok(v) = std::env::var(k) {
            env.push((k.into(), v));
        }
    }
    env.extend(cfg.env.iter().cloned());
    env
}
