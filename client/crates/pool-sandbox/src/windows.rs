//! Windows sandbox: Less-Privileged AppContainer + Job Object.
//!
//! * An AppContainer profile (`vouchcompute.runner.v2`, created per user, no admin needed) with **no
//!   capabilities**: no `internetClient`/`privateNetworkClientServer`, so outbound connections and
//!   loopback are blocked by the OS; no access to the user's files (they are not ACL'd for the container).
//! * LPAC (`ALL_APPLICATION_PACKAGES` opt-out): not even the objects granted to all app packages.
//!   Falls back to a regular AppContainer if the OS refuses LPAC.
//! * The runner executable gets a read/execute ACE for the container SID (kept: it is the runner itself).
//! * **Per-job grants:** each directory a job may read (its model dir, the runtime pack) gets a read/execute ACE for
//!   the container SID when the job starts, and the ACE is removed when the job's process has ended ([`JobGrant`]).
//!   Every job shares the container SID, so without this a job could read every model dir granted to an earlier job
//!   (T-218 design review). Overlapping jobs on one directory share its ACE (counted). ACEs left behind by a crash
//!   are removed at the next start ([`revoke_stale_grants`]). The 0.1.0 profile (`vouchcompute.runner.v1`), whose
//!   ACEs were never removed, is deleted, so nothing runs under that SID any more.
//! * Job Object: kill-on-close, one active process, process memory cap, die on unhandled exception,
//!   UI restrictions (no clipboard, desktop, global atoms, system parameters).
//! * Child-process policy: the runner can't create processes.
//! * Explicit handle list: only the three pipe ends are inherited; minimal environment block.
//! * `DETACHED_PROCESS`: no console. (With `CREATE_NO_WINDOW` the console attach fails inside the
//!   AppContainer and every process dies with STATUS_DLL_INIT_FAILED.)

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, ERROR_ALREADY_EXISTS, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL,
    WAIT_OBJECT_0, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, ACCESS_MODE, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SDDL_REVISION_1,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, InitializeProcThreadAttributeList, ResumeThread,
    UpdateProcThreadAttribute, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS, CREATE_SUSPENDED, DETACHED_PROCESS, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW,
};

use super::{base_env, KillHandle, SandboxConfig, SandboxLevel, SandboxProcess, Spawned};

const PROFILE_NAME: &str = "vouchcompute.runner.v2";
/// Earlier profiles, deleted once so no stale container (and its folder) is left behind and nothing runs under their
/// SIDs again: the 0.1.0 profile, whose directory grants were never removed, and the pre-rename profile.
const OLD_PROFILE_NAMES: [&str; 2] = ["vouchcompute.runner.v1", "Tally.Runner.v1"];
// winbase.h attribute ids (stable ABI values)
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002_000E;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x01;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 0x01;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn os_err(e: windows::core::Error) -> io::Error {
    let hr = e.code().0 as u32;
    // HRESULT_FROM_WIN32 (facility 7) -> the Win32 error code, so io::Error prints it properly
    let code = if hr & 0xFFFF_0000 == 0x8007_0000 { (hr & 0xFFFF) as i32 } else { hr as i32 };
    io::Error::from_raw_os_error(code)
}

fn win32(e: WIN32_ERROR) -> io::Result<()> {
    if e.0 == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(e.0 as i32))
    }
}

/// The container SID as a leaked pointer (lives for the whole process).
struct Sid(PSID);
unsafe impl Send for Sid {}
unsafe impl Sync for Sid {}

fn container_sid() -> io::Result<PSID> {
    static SID: OnceLock<Result<Sid, i32>> = OnceLock::new();
    let r = SID.get_or_init(|| unsafe {
        for old in OLD_PROFILE_NAMES {
            let _ = DeleteAppContainerProfile(PCWSTR(wide(OsStr::new(old)).as_ptr()));
        }
        let name = wide(OsStr::new(PROFILE_NAME));
        let display = wide(OsStr::new("Vouch Compute job runner"));
        let desc = wide(OsStr::new("Sandbox for Vouch Compute model jobs: no network, no user files"));
        match CreateAppContainerProfile(PCWSTR(name.as_ptr()), PCWSTR(display.as_ptr()), PCWSTR(desc.as_ptr()), None) {
            Ok(sid) => Ok(Sid(sid)),
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr())).map(Sid).map_err(|e| e.code().0)
            }
            Err(e) => Err(e.code().0),
        }
    });
    match r {
        Ok(s) => Ok(s.0),
        Err(c) => Err(io::Error::from_raw_os_error(*c)),
    }
}

/// An AppContainer may write its own profile folder (`%LOCALAPPDATA%\Packages\vouchcompute.runner.v2\AC`, which is
/// also where Windows points its TEMP/TMP). A compromised parser could keep one buyer's input there for a later job to
/// read. Windows grants the container that folder through a *critical* allow ACE, which a deny ACE does not override
///  (tried first). So the folder gets a new **protected** DACL: full access for SYSTEM, Administrators and the
/// user, read and execute only for the container SID; its contents inherit it. Done once per process; a failure
/// fails the spawn (the sandbox is never weakened silently).
fn lock_container_storage(sid: PSID) -> io::Result<()> {
    static DONE: OnceLock<Result<(), i32>> = OnceLock::new();
    let r = DONE.get_or_init(|| unsafe {
        let code = |e: windows::core::Error| e.code().0;
        let container = sid_string(sid).map_err(code)?;
        let folder = GetAppContainerFolderPath(PCWSTR(wide(OsStr::new(&container)).as_ptr())).map_err(code)?;
        // the returned string is CoTaskMem-allocated; it is leaked once per process
        let path = folder.to_string().map_err(|_| -1)?;
        let user = current_user_sid().map_err(code)?;
        // 0x1200a9 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
        let sddl = format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{container})");
        set_protected_dacl(Path::new(&path), &sddl).map_err(|e| e.raw_os_error().unwrap_or(-1))
    });
    r.map_err(io::Error::from_raw_os_error)
}

unsafe fn sid_string(sid: PSID) -> windows::core::Result<String> {
    let mut s = PWSTR::null();
    ConvertSidToStringSidW(sid, &mut s)?;
    let out = s.to_string().unwrap_or_default();
    let _ = LocalFree(Some(HLOCAL(s.0.cast())));
    Ok(out)
}

unsafe fn current_user_sid() -> windows::core::Result<String> {
    let mut token = HANDLE::default();
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
    let mut len = 0u32;
    let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
    let mut buf = vec![0u8; len as usize];
    let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
    let _ = CloseHandle(token);
    r?;
    let user = &*(buf.as_ptr() as *const TOKEN_USER);
    sid_string(user.User.Sid)
}

fn set_protected_dacl(path: &Path, sddl: &str) -> io::Result<()> {
    let w = wide(path.as_os_str());
    let sddl = wide(OsStr::new(sddl));
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(os_err)?;
        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let r = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).map_err(os_err);
        let r = r.and_then(|()| {
            win32(SetNamedSecurityInfoW(
                PCWSTR(w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            ))
        });
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        r
    }
}

/// Read + execute for the container SID on the runner executable, once per path. This grant stays: it is the runner
/// binary itself, not data.
fn grant_exe(path: &Path, sid: PSID) -> io::Result<()> {
    static DONE: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    let done = DONE.get_or_init(|| Mutex::new(Vec::new()));
    let canon = path.canonicalize()?;
    if done.lock().unwrap_or_else(|e| e.into_inner()).contains(&canon) {
        return Ok(());
    }
    set_ace(path, sid, GRANT_ACCESS)?;
    done.lock().unwrap_or_else(|e| e.into_inner()).push(canon);
    Ok(())
}

/// Directories granted to running jobs, by canonical path, with the number of live jobs using each.
fn live_grants() -> &'static Mutex<HashMap<PathBuf, usize>> {
    static LIVE: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One job's read access to one directory. Granted on creation; the ACE is removed when the last live grant of that
/// directory is dropped, that is when the job's process has ended (or its spawn failed).
pub(crate) struct JobGrant {
    key: PathBuf,
    path: PathBuf,
}

impl JobGrant {
    fn new(path: &Path) -> io::Result<Self> {
        let sid = container_sid()?;
        let key = path.canonicalize()?;
        let mut live = live_grants().lock().unwrap_or_else(|e| e.into_inner());
        let n = live.get(&key).copied().unwrap_or(0);
        if n == 0 {
            set_ace(path, sid, GRANT_ACCESS)?;
        }
        live.insert(key.clone(), n + 1);
        Ok(Self { key, path: path.to_path_buf() })
    }
}

impl Drop for JobGrant {
    fn drop(&mut self) {
        // never panic in Drop (a poisoned lock still holds a usable count)
        let mut live = live_grants().lock().unwrap_or_else(|e| e.into_inner());
        let n = live.get(&self.key).copied().unwrap_or(1);
        if n > 1 {
            live.insert(self.key.clone(), n - 1);
            return;
        }
        live.remove(&self.key);
        if let Err(e) = container_sid().and_then(|sid| set_ace(&self.path, sid, REVOKE_ACCESS)) {
            // the agent's next start removes it (`revoke_stale_grants`)
            eprintln!("sandbox: could not remove a job's read access to {}: {e}", self.path.display());
        }
    }
}

/// Remove the container SID's ACEs from directories that no running job uses: grants a crash left behind. The agent
/// calls it at start for its model cache and runtime pack directories. Missing paths are skipped.
pub fn revoke_stale_grants(dirs: &[PathBuf]) {
    let Ok(sid) = container_sid() else { return };
    let live = live_grants().lock().unwrap_or_else(|e| e.into_inner());
    for d in dirs {
        let Ok(key) = d.canonicalize() else { continue };
        if !live.contains_key(&key) {
            let _ = set_ace(d, sid, REVOKE_ACCESS);
        }
    }
}

/// Add (`GRANT_ACCESS`) or remove (`REVOKE_ACCESS`: every explicit ACE of the SID) the container SID's read + execute
/// access on a file or directory. Directory ACEs are inheritable, and `SetNamedSecurityInfoW` propagates the change to
/// the existing children, so a revoke also removes the inherited ACEs below.
fn set_ace(path: &Path, sid: PSID, mode: ACCESS_MODE) -> io::Result<()> {
    let w = wide(path.as_os_str());
    unsafe {
        let mut old: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        win32(GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old),
            None,
            &mut sd,
        ))?;
        let inherit: ACE_FLAGS = if path.is_dir() { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { NO_INHERITANCE };
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).0,
            grfAccessMode: mode,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0 as *mut u16),
            },
        };
        let mut new: *mut ACL = std::ptr::null_mut();
        let r = SetEntriesInAclW(Some(&[ea]), Some(old), &mut new);
        if r.0 != 0 {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            return win32(r);
        }
        let r = SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new as *mut _)));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        win32(r)
    }
}

struct Pipe {
    read: HANDLE,
    write: HANDLE,
}

fn pipe(child_reads: bool) -> io::Result<Pipe> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
    unsafe {
        CreatePipe(&mut r, &mut w, Some(&sa), 0).map_err(os_err)?;
        // the parent's end must not be inheritable
        let parent_end = if child_reads { w } else { r };
        SetHandleInformation(parent_end, HANDLE_FLAG_INHERIT.0, windows::Win32::Foundation::HANDLE_FLAGS(0))
            .map_err(os_err)?;
    }
    Ok(Pipe { read: r, write: w })
}

fn env_block(vars: &[(String, String)]) -> Vec<u16> {
    let mut v: Vec<(String, String)> = vars.to_vec();
    v.sort_by_key(|a| a.0.to_uppercase());
    v.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));
    let mut out = Vec::new();
    for (k, val) in v {
        out.extend(OsStr::new(&format!("{k}={val}")).encode_wide());
        out.push(0);
    }
    out.push(0);
    out
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut s = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                s.push_str(&"\\".repeat(backslashes * 2 + 1));
                s.push('"');
                backslashes = 0;
            }
            _ => {
                s.push_str(&"\\".repeat(backslashes));
                s.push(c);
                backslashes = 0;
            }
        }
    }
    s.push_str(&"\\".repeat(backslashes * 2));
    s.push('"');
    s
}

struct Handles {
    process: HANDLE,
    job: Option<HANDLE>,
    /// The job's directory grants: removed once the process has ended (after `wait`, or when these handles drop).
    grants: Mutex<Vec<JobGrant>>,
}
unsafe impl Send for Handles {}
unsafe impl Sync for Handles {}

impl Drop for Handles {
    fn drop(&mut self) {
        unsafe {
            if let Some(j) = self.job {
                let _ = CloseHandle(j); // kill-on-close
            }
            let _ = CloseHandle(self.process);
        }
        // `grants` drops after this body: the process is gone, so its read access is removed
    }
}

struct WinProcess {
    h: std::sync::Arc<Handles>,
}

impl SandboxProcess for WinProcess {
    fn wait(&mut self) -> io::Result<i32> {
        unsafe {
            if WaitForSingleObject(self.h.process, INFINITE) != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let mut code = 0u32;
            GetExitCodeProcess(self.h.process, &mut code).map_err(os_err)?;
            // the job is over: its directories are no longer readable by the container SID
            self.h.grants.lock().unwrap_or_else(|e| e.into_inner()).clear();
            Ok(code as i32)
        }
    }
    fn kill_handle(&self) -> KillHandle {
        let h = self.h.clone();
        KillHandle::new(move || unsafe {
            match h.job {
                Some(j) => {
                    let _ = TerminateJobObject(j, 1);
                }
                None => {
                    let _ = windows::Win32::System::Threading::TerminateProcess(h.process, 1);
                }
            }
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Lpac,
    AppContainer,
    Plain,
}

fn create(exe: &Path, args: &[String], cfg: &SandboxConfig, mode: Mode) -> io::Result<Spawned> {
    let sid = if mode == Mode::Plain { None } else { Some(container_sid()?) };
    let mut grants = Vec::new();
    if let Some(sid) = sid {
        lock_container_storage(sid)?;
        grant_exe(exe, sid)?;
        // per job: removed when the process ends; on any error below, dropping `grants` removes them again
        for d in &cfg.readable_dirs {
            grants.push(JobGrant::new(d)?);
        }
    }
    let stdin = pipe(true)?;
    let stdout = pipe(false)?;
    let stderr = pipe(false)?;
    let child_handles = [stdin.read, stdout.write, stderr.write];

    let mut cmdline: Vec<u16> = {
        let mut s = quote_arg(&exe.to_string_lossy());
        for a in args {
            s.push(' ');
            s.push_str(&quote_arg(a));
        }
        wide(OsStr::new(&s))
    };
    let app = wide(exe.as_os_str());
    let cwd = exe.parent().map(|p| wide(p.as_os_str()));
    let env = env_block(&base_env(cfg));

    unsafe {
        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(None, 4, None, &mut size);
        let mut attr_buf = vec![0u8; size];
        let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);
        InitializeProcThreadAttributeList(Some(attrs), 4, None, &mut size).map_err(os_err)?;

        let caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid.unwrap_or_default(),
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let lpac = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        let upd = |id: usize, ptr: *const std::ffi::c_void, len: usize| {
            UpdateProcThreadAttribute(attrs, 0, id, Some(ptr), len, None, None).map_err(os_err)
        };
        let result = (|| -> io::Result<PROCESS_INFORMATION> {
            upd(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                child_handles.as_ptr() as *const _,
                size_of::<HANDLE>() * child_handles.len(),
            )?;
            if sid.is_some() {
                upd(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps as *const _ as *const _, size_of::<SECURITY_CAPABILITIES>())?;
                upd(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy as *const _ as *const _, size_of::<u32>())?;
            }
            if mode == Mode::Lpac {
                upd(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &lpac as *const _ as *const _, size_of::<u32>())?;
            }
            let si = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdInput: stdin.read,
                    hStdOutput: stdout.write,
                    hStdError: stderr.write,
                    ..Default::default()
                },
                lpAttributeList: attrs,
            };
            let mut pi = PROCESS_INFORMATION::default();
            CreateProcessW(
                PCWSTR(app.as_ptr()),
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | DETACHED_PROCESS
                    | CREATE_UNICODE_ENVIRONMENT
                    // The user's own programs always win the CPU
                    | if mode == Mode::Plain { Default::default() } else { BELOW_NORMAL_PRIORITY_CLASS },
                Some(env.as_ptr() as *const _),
                cwd.as_ref().map(|c| PCWSTR(c.as_ptr())).unwrap_or(PCWSTR::null()),
                &si.StartupInfo,
                &mut pi,
            )
            .map_err(os_err)?;
            Ok(pi)
        })();
        DeleteProcThreadAttributeList(attrs);
        // the child's ends are now owned by the child (or the call failed)
        for h in child_handles {
            let _ = CloseHandle(h);
        }
        let pi = match result {
            Ok(pi) => pi,
            Err(e) => {
                for h in [stdin.write, stdout.read, stderr.read] {
                    let _ = CloseHandle(h);
                }
                return Err(e);
            }
        };

        let job = if mode == Mode::Plain { None } else { Some(make_job(cfg.memory_limit_bytes, cfg.cpu_rate_pct)?) };
        if let Some(j) = job {
            if let Err(e) = AssignProcessToJobObject(j, pi.hProcess) {
                let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
                let _ = CloseHandle(j);
                return Err(os_err(e));
            }
        }
        ResumeThread(pi.hThread);
        let _ = CloseHandle(pi.hThread);

        let level = match mode {
            Mode::Lpac => SandboxLevel::WindowsLpac,
            Mode::AppContainer => SandboxLevel::WindowsAppcontainer,
            Mode::Plain => SandboxLevel::None,
        };
        Ok(Spawned {
            stdin: Box::new(File::from_raw_handle(stdin.write.0 as _)),
            stdout: Box::new(File::from_raw_handle(stdout.read.0 as _)),
            stderr: Box::new(File::from_raw_handle(stderr.read.0 as _)),
            process: Box::new(WinProcess { h: std::sync::Arc::new(Handles { process: pi.hProcess, job, grants: Mutex::new(grants) }) }),
            level,
        })
    }
}

fn make_job(memory_limit: u64, cpu_rate_pct: Option<u8>) -> io::Result<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).map_err(os_err)?;
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        info.ProcessMemoryLimit = memory_limit as usize;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        let ok2 = SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui as *const _ as *const _,
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );
        // Hard CPU cap for the whole job, in 1/100 of a percent of all processors' cycles
        let ok3 = match cpu_rate_pct {
            Some(pct) => {
                let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    ..Default::default()
                };
                cpu.Anonymous.CpuRate = u32::from(pct.clamp(1, 100)) * 100;
                SetInformationJobObject(
                    job,
                    JobObjectCpuRateControlInformation,
                    &cpu as *const _ as *const _,
                    size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                )
            }
            None => Ok(()),
        };
        if let Err(e) = ok.and(ok2).and(ok3) {
            let _ = CloseHandle(job);
            return Err(os_err(e));
        }
        Ok(job)
    }
}

/// Delete the job sandbox's AppContainer profiles (current and pre-rename) and their folders. Run on uninstall;
/// a missing profile is not an error.
pub fn remove_profiles() {
    for name in std::iter::once(PROFILE_NAME).chain(OLD_PROFILE_NAMES) {
        unsafe {
            let _ = DeleteAppContainerProfile(PCWSTR(wide(OsStr::new(name)).as_ptr()));
        }
    }
}

pub fn spawn(exe: &Path, args: &[String], cfg: &SandboxConfig) -> io::Result<Spawned> {
    if !cfg.lpac {
        return create(exe, args, cfg, Mode::AppContainer);
    }
    match create(exe, args, cfg, Mode::Lpac) {
        Ok(s) => Ok(s),
        Err(_) => create(exe, args, cfg, Mode::AppContainer),
    }
}

pub fn spawn_plain(exe: &Path, args: &[String], cfg: &SandboxConfig) -> io::Result<Spawned> {
    create(exe, args, cfg, Mode::Plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    use windows::Win32::Security::{EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER};

    /// Does `path`'s DACL hold an allow ACE (explicit or inherited) for the container SID?
    fn container_can_read(path: &Path) -> bool {
        let sid = container_sid().unwrap();
        let w = wide(path.as_os_str());
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            win32(GetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(&mut dacl), None, &mut sd))
                .unwrap();
            let mut found = false;
            for i in 0..(*dacl).AceCount {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                GetAce(dacl, u32::from(i), &mut ace).unwrap();
                // ACCESS_ALLOWED_ACE_TYPE
                if (*(ace as *const ACE_HEADER)).AceType == 0 {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    let ace_sid = PSID(std::ptr::addr_of!((*a).SidStart) as *mut _);
                    if EqualSid(ace_sid, sid).is_ok() {
                        found = true;
                    }
                }
            }
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            found
        }
    }

    #[test]
    fn container_profile_and_exe_grant_work() {
        let sid = container_sid().expect("container sid");
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.bin");
        std::fs::write(&f, b"x").unwrap();
        grant_exe(&f, sid).expect("grant file");
        assert!(container_can_read(&f));
    }

    /// A job's directory grant lives exactly as long as the job: the directory and the files in it are readable by
    /// the container while a job holds the grant, and not afterwards. Two overlapping jobs share one ACE.
    #[test]
    fn job_grants_are_removed_after_the_last_job() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("weights.bin");
        std::fs::write(&f, b"w").unwrap();
        assert!(!container_can_read(dir.path()) && !container_can_read(&f));
        let a = JobGrant::new(dir.path()).unwrap();
        assert!(container_can_read(dir.path()), "granted to the job");
        assert!(container_can_read(&f), "inherited by the files in it");
        let b = JobGrant::new(dir.path()).unwrap();
        drop(a);
        assert!(container_can_read(&f), "still used by the second job");
        drop(b);
        assert!(!container_can_read(dir.path()), "removed after the last job");
        assert!(!container_can_read(&f), "and from the files below it");
    }

    /// Grants a crash left behind are removed at the next start; a directory a running job uses is left alone.
    #[test]
    fn stale_grants_are_revoked() {
        let stale = tempfile::tempdir().unwrap();
        let busy = tempfile::tempdir().unwrap();
        set_ace(stale.path(), container_sid().unwrap(), GRANT_ACCESS).unwrap();
        let running = JobGrant::new(busy.path()).unwrap();
        assert!(container_can_read(stale.path()));
        revoke_stale_grants(&[stale.path().to_path_buf(), busy.path().to_path_buf(), stale.path().join("missing")]);
        assert!(!container_can_read(stale.path()));
        assert!(container_can_read(busy.path()), "a running job keeps its grant");
        drop(running);
        assert!(!container_can_read(busy.path()));
    }

    #[test]
    fn quoting_follows_msvcrt_rules() {
        assert_eq!(quote_arg("a"), "a");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("c:\\dir with space\\"), "\"c:\\dir with space\\\\\"");
        assert_eq!(quote_arg(""), "\"\"");
    }
}
