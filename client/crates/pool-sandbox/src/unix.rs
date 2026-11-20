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

#[cfg(target_os = "macos")]
fn sbpl_profile(exe: &Path, cfg: &SandboxConfig) -> String {
    fn q(p: &Path) -> String {
        p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
    }
    let mut reads = String::new();
    for d in &cfg.readable_dirs {
        let d = d.canonicalize().unwrap_or_else(|_| d.clone());
        reads.push_str(&format!(" (subpath \"{}\")", q(&d)));
    }
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    format!(
        r#"(version 1)
(deny default)
(allow process-exec (literal "{exe}"))
(allow file-read-metadata)
(allow file-read* (literal "{exe}") (subpath "/usr/lib") (subpath "/System") (subpath "/Library/Apple")
  (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes") (literal "/dev/null")
  (literal "/dev/urandom") (literal "/dev/random"){reads})
(allow file-write-data (literal "/dev/null"))
(allow sysctl-read)
(allow mach-lookup (global-name "com.apple.system.logger"))
(allow signal (target self))
(deny network*)
(deny process-fork)
"#,
        exe = q(&exe),
        reads = reads
    )
}

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
    Ok(Spawned {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr: Box::new(stderr),
        process: Box::new(UnixProcess { child: Arc::new(Mutex::new(child)), pid }),
        level,
    })
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
