//! In-process hardening the runner applies to itself, on top of the OS sandbox its parent created
//! (`pool-sandbox`). Applied right after the request header is read and before input bytes or model files
//! are touched.
//!
//! * all OSes: no core dumps / crash dumps with job buffers.
//! * Linux: `PR_SET_NO_NEW_PRIVS`, not dumpable, Landlock (read-only access to the model dir, the verified ONNX
//!   Runtime pack dir and system library dirs, no writes anywhere), seccomp (no `socket` except AF_UNIX, no `execve`, no `ptrace`).
//! * Windows: no WER dialog / dump (`SetErrorMode`); network and file isolation come from the
//!   AppContainer + Job Object set up by the parent.
//! * macOS: no core dumps; isolation comes from the `sandbox-exec` profile set up by the parent.

use std::path::Path;

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct HardenReport {
    pub core_dumps_disabled: bool,
    pub landlock: Option<String>,
    pub seccomp: bool,
    pub notes: Vec<String>,
}

#[cfg(target_os = "linux")]
pub fn apply(model_dir: &Path) -> HardenReport {
    let mut r = HardenReport::default();
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        r.core_dumps_disabled = libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0;
        // dev builds only: POOL_DIAG_DUMPABLE=1 keeps the process traceable to diagnose sandbox denials
        if !(cfg!(feature = "dev-trust") && std::env::var("POOL_DIAG_DUMPABLE").as_deref() == Ok("1")) {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            r.notes.push("no_new_privs failed".into());
        }
    }
    r.landlock = Some(landlock_restrict(model_dir));
    match seccomp_restrict() {
        Ok(()) => r.seccomp = true,
        Err(e) => r.notes.push(format!("seccomp: {e}")),
    }
    r
}

#[cfg(target_os = "linux")]
fn landlock_restrict(model_dir: &Path) -> String {
    use landlock::{path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI};
    let abi = ABI::V2;
    let mut read_dirs: Vec<std::path::PathBuf> = vec![model_dir.to_path_buf()];
    // The ONNX Runtime pack (`accel`), read-only: the directory pool-core verified against the pins and passed in
    // `POOL_ORT_PACK_DIR`. The runner checks every file again before loading it. Only an absolute directory counts.
    if let Some(pack) = pack_dir_from_env() {
        read_dirs.push(pack);
    }
    for d in ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/etc/ld.so.cache", "/proc/self", "/sys/devices/system/cpu", "/sys/fs/cgroup"] {
        if Path::new(d).exists() {
            read_dirs.push(d.into());
        }
    }
    // The NVIDIA driver's device files (read + write, which CUDA's ioctls need)
    // and its user-space libraries / proc entries (read). WSL2 exposes the GPU as /dev/dxg with libraries under
    // /usr/lib/wsl. Nothing else is added: still no network, no user files, no writes outside these device nodes.
    let mut gpu_devices: Vec<std::path::PathBuf> = vec![];
    // libcuda names its worker threads by writing /proc/self/task/<tid>/comm and gives up cuInit when that fails
    // (CUDA_ERROR_OPERATING_SYSTEM). Write access below the runner's own task dir only: it covers
    // only this process's threads, never another process.
    let mut own_tasks: Vec<std::path::PathBuf> = vec![];
    if cfg!(feature = "cuda") {
        own_tasks.push("/proc/self/task".into());
        // the two procfs files libcuda reads at cuInit (without them cuInit fails with
        // CUDA_ERROR_OPERATING_SYSTEM). Single files, not /proc as a whole.
        for d in ["/proc/driver/nvidia", "/usr/lib/wsl", "/sys/bus/pci", "/sys/devices", "/etc/nvidia", "/proc/sys/vm/mmap_min_addr", "/proc/cpuinfo"] {
            if Path::new(d).exists() {
                read_dirs.push(d.into());
            }
        }
        if let Ok(rd) = std::fs::read_dir("/dev") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("nvidia") || n == "dxg" {
                    gpu_devices.push(e.path());
                }
            }
        }
    }
    let res = (|| -> Result<landlock::RestrictionStatus, landlock::RulesetError> {
        let dev_access = AccessFs::ReadFile | AccessFs::WriteFile;
        Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?
            .add_rules(path_beneath_rules(&read_dirs, AccessFs::from_read(abi)))?
            .add_rules(path_beneath_rules(&gpu_devices, dev_access))?
            .add_rules(path_beneath_rules(&own_tasks, AccessFs::WriteFile))?
            .restrict_self()
    })();
    match res {
        Ok(s) => format!("{:?}", s.ruleset),
        Err(e) => format!("error: {e}"),
    }
}

/// The pack directory pool-core passed to this runner (`crate::accel::PACK_ENV`), if it is an absolute directory.
#[cfg(target_os = "linux")]
fn pack_dir_from_env() -> Option<std::path::PathBuf> {
    let p = std::path::PathBuf::from(std::env::var_os(crate::accel::PACK_ENV)?);
    (p.is_absolute() && p.is_dir()).then_some(p)
}

/// Syscalls the runner never needs and a compromised parser would want. Previously `socket` was allowed for
/// `AF_UNIX`, which let a compromised runner connect to pathname sockets outside the network namespace (the user's
/// D-Bus session bus, and through it `systemd --user`), and io_uring could open and connect sockets around the
/// `socket`/`connect` rules. The runner only uses the pipes it inherits.
#[cfg(target_os = "linux")]
const DENIED_SYSCALLS: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept4,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
];

#[cfg(target_os = "linux")]
fn seccomp_restrict() -> Result<(), String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    let arch = if cfg!(target_arch = "aarch64") { TargetArch::aarch64 } else { TargetArch::x86_64 };
    let rules: BTreeMap<i64, Vec<SeccompRule>> = DENIED_SYSCALLS.iter().map(|s| (*s, vec![])).collect(); // empty = always
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)
        .map_err(|e| e.to_string())?;
    let prog: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?;
    seccompiler::apply_filter(&prog).map_err(|e| e.to_string())
}

impl HardenReport {
    /// Fail-closed rule: on Linux a job runs only when seccomp applied and Landlock is enforced (fully or, on
    /// kernels older than ABI 2, partially). Without Landlock a compromised parser could read the user's files and put
    /// them in the output that goes back to the buyer. Other OSes are isolated by their parent sandbox.
    pub fn job_allowed(&self) -> Result<(), String> {
        if cfg!(target_os = "linux") {
            if !self.seccomp {
                return Err(format!("seccomp filter not applied: {:?}", self.notes));
            }
            let ll = self.landlock.as_deref().unwrap_or("missing");
            if !(ll.contains("FullyEnforced") || ll.contains("PartiallyEnforced")) {
                return Err(format!("Landlock not enforced ({ll}): this kernel cannot isolate the user's files"));
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub fn apply(_model_dir: &Path) -> HardenReport {
    // Declared directly (kernel32) so the runner binary does not pull in the `windows` crate's COM error
    // machinery (ole32/oleaut32 -> user32), whose DLL init fails inside an AppContainer without a desktop.
    #[link(name = "kernel32")]
    extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
    HardenReport {
        core_dumps_disabled: true,
        notes: vec!["isolation by parent: AppContainer + Job Object".into()],
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
pub fn apply(_model_dir: &Path) -> HardenReport {
    let ok = unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0
    };
    HardenReport {
        core_dumps_disabled: ok,
        notes: vec!["isolation by parent: sandbox-exec profile".into()],
        ..Default::default()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn apply(_model_dir: &Path) -> HardenReport {
    HardenReport { notes: vec!["no hardening on this OS".into()], ..Default::default() }
}
