//! Linux and macOS sandbox launchers.
//!
//! Linux: the child unshares a new user + network namespace before exec (empty netns: no interfaces
//! except a down `lo`), sets `RLIMIT_CORE=0`, `RLIMIT_DATA` (not `RLIMIT_AS`, which breaks CUDA), `PR_SET_PDEATHSIG` and `no_new_privs`. The
//! runner then applies Landlock and seccomp to itself (`harden.rs`). If unprivileged user namespaces are
//! blocked (Ubuntu 24.04 without our AppArmor profile), the namespace step is skipped and the level drops
//! to `linux-seccomp-landlock`, which still blocks sockets and file access.
//!
//! macOS: `sandbox-exec -p <profile>` with a deny-default SBPL profile. Production uses a separately
//! signed helper with App Sandbox entitlements instead (release setup).

use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use super::{base_env, KillHandle, SandboxConfig, SandboxLevel, SandboxProcess, Spawned};

struct UnixProcess {
    child: Arc<Mutex<Child>>,
    pid: i32,
}

impl SandboxProcess for UnixProcess {
    fn wait(&mut self) -> io::Result<i32> {
        // poll so kill() from another thread can take the lock
        loop {
            if let Some(st) = self.child.lock().unwrap().try_wait()? {
                return Ok(st.code().unwrap_or(-1));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    fn kill_handle(&self) -> KillHandle {
        let pid = self.pid;
        KillHandle::new(move || unsafe {
            libc::kill(pid, libc::SIGKILL);
        })
    }
}

/// The deny-default SBPL profile for one job.
///
/// * `file-read-data (literal "/")`: dyld on macOS 27 opens the root directory itself while locating the shared
///   cache; without it every sandboxed process aborts in dyld before `main` (SIGABRT, `ignition_halt`). It grants
///   the listing of `/` only (top-level names such as `Users`, `Applications`), not anything below it.
/// * `file-read-metadata` only for the paths the runner reads and their parent directories (path resolution needs
///   them), plus `/private` and the system symlinks `/var`, `/tmp`, `/etc`. A global allowance let a job `stat` any
///   file of the user (existence, size, modification times).
/// * `sysctl-read` only for hardware, CPU and OS-version names (it was global).
///
/// **Known gap, not closed by this profile:** `KERN_PROCARGS2` (the arguments and environment variables of the
/// user's other processes) is not mediated by `sandbox-exec` at all; no `sysctl-read` or `process-info*` rule
/// changes it. See `known_gap_same_user_process_environment_is_readable` in pool-runner's `tests/sandbox_macos.rs`.
#[cfg(target_os = "macos")]
fn sbpl_profile(exe: &Path, cfg: &SandboxConfig) -> String {
    fn q(p: &Path) -> String {
        p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
    }
    let exe_given = exe.to_path_buf();
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let mut reads = String::new();
    let mut parents = std::collections::BTreeSet::new();
    let mut add_parents = |p: &Path| {
        for a in p.ancestors().skip(1) {
            parents.insert(a.to_path_buf());
        }
    };
    add_parents(&exe);
    add_parents(&exe_given);
    for d in &cfg.readable_dirs {
        add_parents(d);
        let d = d.canonicalize().unwrap_or_else(|_| d.clone());
        add_parents(&d);
        reads.push_str(&format!(" (subpath \"{}\")", q(&d)));
    }
    for s in ["/var", "/tmp", "/etc", "/private"] {
        parents.insert(s.into());
    }
    let meta: String = parents.iter().map(|p| format!(" (literal \"{}\")", q(p))).collect();
    format!(
        r#"(version 1)
(deny default)
(allow process-exec (literal "{exe}"))
(allow file-read-metadata{meta})
(allow file-read-data (literal "/"))
(allow file-read* (literal "{exe}") (subpath "/usr/lib") (subpath "/System") (subpath "/Library/Apple")
  (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes") (literal "/dev/null")
  (literal "/dev/urandom") (literal "/dev/random"){reads})
(allow file-write-data (literal "/dev/null"))
(allow sysctl-read (sysctl-name-prefix "hw.") (sysctl-name-prefix "machdep.cpu.") (sysctl-name "kern.osversion")
  (sysctl-name "kern.osrelease") (sysctl-name "kern.ostype") (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.version") (sysctl-name "kern.argmax") (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "sysctl.proc_cputype") (sysctl-name "sysctl.proc_native") (sysctl-name "kern.secure_kernel")
  (sysctl-name "vm.pagesize"))
(allow mach-lookup (global-name "com.apple.system.logger"))
(allow signal (target self))
(deny network*)
(deny process-fork)
{gpu}"#,
        exe = q(&exe),
        meta = meta,
        reads = reads,
        gpu = if cfg.gpu { METAL_RULES } else { "" }
    )
}

/// What a GPU job needs for Metal, and nothing else. Measured one rule at a time: without the GPU user client no
/// Metal device is visible; without the compiler service candle cannot build its kernels. (`IOSurfaceRootUserClient`
/// was tried and is not needed, so it stays denied.) **For security review:**
/// * `AGXDeviceUserClient`: the Apple GPU kernel driver's user client. This is the added attack surface: a driver
///   bug reachable from it could escape the sandbox. Safari's web content processes are granted the same client.
/// * `com.apple.MTLCompilerService`: Apple's shader compiler, an XPC service in its own sandbox; candle compiles its
///   kernels from source at run time and sends it only that source.
///
/// No file, network or other Mach service is added; the job still cannot write anywhere.
#[cfg(target_os = "macos")]
const METAL_RULES: &str = r#"(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient"))
(allow mach-lookup (global-name "com.apple.MTLCompilerService"))
"#;

pub fn spawn(exe: &Path, args: &[String], cfg: &SandboxConfig, sandboxed: bool) -> io::Result<Spawned> {
    #[cfg(target_os = "macos")]
    let (mut cmd, level) = if sandboxed {
        let mut c = Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(sbpl_profile(exe, cfg)).arg(exe).args(args);
        (c, SandboxLevel::MacosSandboxExec)
    } else {
        let mut c = Command::new(exe);
        c.args(args);
        (c, SandboxLevel::None)
    };
    #[cfg(not(target_os = "macos"))]
    let (mut cmd, mut level) = {
        let mut c = Command::new(exe);
        c.args(args);
        (c, if sandboxed { SandboxLevel::LinuxUserns } else { SandboxLevel::None })
    };

    cmd.env_clear().envs(base_env(cfg)).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = exe.parent() {
        cmd.current_dir(dir);
    }

    #[cfg(target_os = "linux")]
    if sandboxed {
        use std::os::unix::process::CommandExt;
        let mem = cfg.memory_limit_bytes;
        // Probe once whether unprivileged user namespaces work here; the child repeats the unshare.
        let userns_ok = userns_available();
        if !userns_ok {
            level = SandboxLevel::LinuxSeccompLandlock;
        }
        unsafe {
            cmd.pre_exec(move || {
                let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_CORE, &core);
                // RLIMIT_DATA, not RLIMIT_AS. Since Linux 4.7 it counts the heap and private writable mappings
                // (what a job's memory really is), but not inaccessible address-space reservations, which the CUDA
                // driver makes in the tens of GB: under RLIMIT_AS every CUDA allocation failed (out of memory).
                let a = libc::rlimit { rlim_cur: mem, rlim_max: mem };
                libc::setrlimit(libc::RLIMIT_DATA, &a);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                // The user's own programs always win the CPU (no unprivileged hard cap on Linux)
                libc::setpriority(libc::PRIO_PROCESS, 0, 10);
                if userns_ok && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(target_os = "macos")]
    if sandboxed {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_CORE, &core);
                libc::setpriority(libc::PRIO_PROCESS, 0, 10);
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| io::Error::other("no stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| io::Error::other("no stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| io::Error::other("no stderr"))?;
    let pid = child.id() as i32;
    let child = Arc::new(Mutex::new(child));
    #[cfg(target_os = "macos")]
    if sandboxed {
        memory_watchdog(child.clone(), pid, cfg.memory_limit_bytes);
    }
    Ok(Spawned {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr: Box::new(stderr),
        process: Box::new(UnixProcess { child, pid }),
        level,
    })
}

/// macOS enforces no memory rlimit (`RLIMIT_DATA` / `RLIMIT_AS` / `RLIMIT_RSS` are not applied to allocations),
/// so the job's memory cap is a watchdog: every [`WATCHDOG_PERIOD`] it reads the runner's physical footprint
/// (`proc_pid_rusage`, the figure Activity Monitor shows: resident + compressed + swapped dirty memory) and kills
/// the runner once it is over `limit`. A soft cap: a job can overshoot by what it allocates within one period.
/// The kill happens under the child lock after `try_wait` saw it still running, so the pid is never reaped (and
/// never reused) at that point.
#[cfg(target_os = "macos")]
const WATCHDOG_PERIOD: std::time::Duration = std::time::Duration::from_millis(50);

#[cfg(target_os = "macos")]
fn memory_watchdog(child: Arc<Mutex<Child>>, pid: i32, limit: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(WATCHDOG_PERIOD);
        // a poisoned lock (a panic elsewhere while holding it) must not switch the memory cap off
        let mut c = child.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(c.try_wait(), Ok(None)) {
            return;
        }
        let Some(footprint) = phys_footprint(pid) else { continue };
        if footprint > limit {
            tracing::warn!("runner {pid} over its memory cap ({} MiB > {} MiB): killed", footprint >> 20, limit >> 20);
            // SAFETY: plain kill(2) of our own unreaped child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return;
        }
    });
}

#[cfg(target_os = "macos")]
fn phys_footprint(pid: i32) -> Option<u64> {
    let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: `ri` is a writable rusage_info_v4, matching the RUSAGE_INFO_V4 flavor.
    let rc = unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, (&mut ri as *mut libc::rusage_info_v4).cast()) };
    (rc == 0).then_some(ri.ri_phys_footprint)
}

#[cfg(target_os = "linux")]
fn userns_available() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let r = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
            libc::_exit(if r == 0 { 0 } else { 1 });
        }
        if pid < 0 {
            return false;
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    })
}
