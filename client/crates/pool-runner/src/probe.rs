//! Sandbox self-test (`pool-runner probe ...`). It tries what a hostile model or a compromised parser would
//! try (network, reading a user file, writing a file, starting a process) and reports each outcome as
//! JSON. Tests run it inside the sandbox and assert that every attempt fails, and run it outside the
//! sandbox as a control to prove the probes themselves work.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Attempt {
    pub target: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeReport {
    pub net_connect: Vec<Attempt>,
    pub dns: Option<Attempt>,
    pub file_read: Vec<Attempt>,
    pub file_write: Vec<Attempt>,
    pub spawn: Option<Attempt>,
    pub harden: crate::harden::HardenReport,
    /// Opening the agent's control channel (named pipe on Windows, Unix socket elsewhere).
    #[serde(default)]
    pub ipc_connect: Vec<Attempt>,
    /// Listing a directory of the user (home, Documents, the agent's data dir).
    #[serde(default)]
    pub dir_list: Vec<Attempt>,
    /// Writing into the process's own temp dir (an AppContainer gets a private one).
    #[serde(default)]
    pub temp_write: Option<Attempt>,
    /// Allocating and touching `--alloc-mb` MiB (`ok` = the allocation succeeded).
    #[serde(default)]
    pub alloc: Option<Attempt>,
    /// CPU time used by a `--spin-ms` busy loop, to check the job's CPU cap.
    #[serde(default)]
    pub cpu: Option<CpuUse>,
    /// Loading a DLL / shared library by full path (the GPU backend pack must load inside the sandbox).
    #[serde(default)]
    pub dll_load: Vec<Attempt>,
    /// Creating a CUDA device (`cuda` builds).
    #[serde(default)]
    pub cuda: Option<Attempt>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CpuUse {
    pub wall_ms: u64,
    pub cpu_ms: u64,
}

impl ProbeReport {
    /// True when no escape attempt succeeded.
    pub fn all_blocked(&self) -> bool {
        self.net_connect.iter().all(|a| !a.ok)
            && self.dns.as_ref().is_none_or(|a| !a.ok)
            && self.file_read.iter().all(|a| !a.ok)
            && self.file_write.iter().all(|a| !a.ok)
            && self.spawn.as_ref().is_none_or(|a| !a.ok)
            && self.ipc_connect.iter().all(|a| !a.ok)
            && self.dir_list.iter().all(|a| !a.ok)
            && self.temp_write.as_ref().is_none_or(|a| !a.ok)
    }
}

fn attempt(target: &str, r: std::io::Result<()>) -> Attempt {
    match r {
        Ok(()) => Attempt { target: target.into(), ok: true, error: None },
        Err(e) => Attempt { target: target.into(), ok: false, error: Some(e.to_string()) },
    }
}

#[derive(Debug, Default)]
pub struct ProbeArgs {
    pub connect: Vec<String>,
    pub dns: Option<String>,
    pub read: Vec<String>,
    pub write_dir: Vec<String>,
    pub spawn: bool,
    pub model_dir: Option<String>,
    pub ipc: Vec<String>,
    pub list: Vec<String>,
    pub write_temp: bool,
    pub alloc_mb: Option<u64>,
    pub spin_ms: Option<u64>,
    pub load_dll: Vec<String>,
    pub cuda: bool,
    /// Control run only (tests): skip the runner's self-hardening so the probes can show they work.
    /// `run` (jobs) always hardens; this flag exists only in probe mode.
    pub no_harden: bool,
}

impl ProbeArgs {
    pub fn parse(args: &[String]) -> Self {
        let mut p = Self::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut v = || it.next().cloned().unwrap_or_default();
            match a.as_str() {
                "--connect" => p.connect.push(v()),
                "--dns" => p.dns = Some(v()),
                "--read" => p.read.push(v()),
                "--write-dir" => p.write_dir.push(v()),
                "--spawn" => p.spawn = true,
                "--model-dir" => p.model_dir = Some(v()),
                "--ipc" => p.ipc.push(v()),
                "--list" => p.list.push(v()),
                "--write-temp" => p.write_temp = true,
                "--alloc-mb" => p.alloc_mb = v().parse().ok(),
                "--spin-ms" => p.spin_ms = v().parse().ok(),
                "--load-dll" => p.load_dll.push(v()),
                "--cuda" => p.cuda = true,
                "--no-harden" => p.no_harden = true,
                _ => {}
            }
        }
        p
    }
}

/// Run `f`, turning a panic into an error. (Inside the Windows LPAC sandbox, Winsock itself fails to
/// initialize and std panics on WSAStartup: that is a blocked network, not a probe failure.)
fn guarded(f: impl FnOnce() -> std::io::Result<()> + std::panic::UnwindSafe) -> std::io::Result<()> {
    std::panic::catch_unwind(f).unwrap_or_else(|p| {
        let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()));
        Err(std::io::Error::other(format!("panicked: {}", msg.unwrap_or_else(|| "network stack unavailable".into()))))
    })
}

/// Windows: initialise Winsock ourselves first. In the LPAC sandbox WSAStartup fails (10107) and std then panics,
/// which `guarded` can only catch in unwinding builds; release builds abort (`panic = "abort"`), so the probe
/// would die instead of reporting the block (seen when the end-to-end suite ran the release runner).
#[cfg(windows)]
fn network_stack() -> std::io::Result<()> {
    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAStartup(version: u16, data: *mut u8) -> i32;
    }
    let mut data = [0u8; 1024]; // WSADATA is 408 bytes on x64
    // SAFETY: `data` is writable and larger than WSADATA; WSAStartup only writes into it.
    let rc = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("network stack unavailable (WSAStartup {rc})")))
    }
}

#[cfg(not(windows))]
fn network_stack() -> std::io::Result<()> {
    Ok(())
}

pub fn run(args: &ProbeArgs) -> ProbeReport {
    let harden = if args.no_harden {
        crate::harden::HardenReport::default()
    } else {
        crate::harden::apply(std::path::Path::new(args.model_dir.as_deref().unwrap_or(".")))
    };
    let mut rep = ProbeReport { harden, ..Default::default() };
    for c in &args.connect {
        let c2 = c.clone();
        let r = network_stack().and_then(|()| guarded(move || {
            c2.parse::<SocketAddr>()
                .map_err(std::io::Error::other)
                .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)))
                .and_then(|mut s| s.write_all(b"x"))
        }));
        rep.net_connect.push(attempt(c, r));
    }
    if let Some(host) = &args.dns {
        let h2 = host.clone();
        let r = network_stack().and_then(|()| guarded(move || {
            (h2.as_str(), 443)
                .to_socket_addrs()
                .and_then(|mut a| a.next().map(|_| ()).ok_or_else(|| std::io::Error::other("no address")))
        }));
        rep.dns = Some(attempt(host, r));
    }
    for f in &args.read {
        let r = std::fs::File::open(f).and_then(|mut fh| {
            let mut s = Vec::new();
            fh.read_to_end(&mut s).map(|_| ())
        });
        rep.file_read.push(attempt(f, r));
    }
    for d in &args.write_dir {
        let path = std::path::Path::new(d).join(format!("pool-runner-escape-{}.txt", std::process::id()));
        let r = std::fs::write(&path, b"escaped");
        if r.is_ok() {
            let _ = std::fs::remove_file(&path);
        }
        rep.file_write.push(attempt(d, r));
    }
    if args.spawn {
        let cmd = if cfg!(windows) { ("cmd.exe", vec!["/c", "exit", "0"]) } else { ("/bin/sh", vec!["-c", "true"]) };
        let r = std::process::Command::new(cmd.0)
            .args(&cmd.1)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .and_then(|s| if s.success() { Ok(()) } else { Err(std::io::Error::other("child failed")) });
        rep.spawn = Some(attempt(cmd.0, r));
    }
    for target in &args.ipc {
        rep.ipc_connect.push(attempt(target, ipc_connect(target)));
    }
    for d in &args.list {
        let r = std::fs::read_dir(d).and_then(|mut it| it.next().transpose().map(|_| ()));
        rep.dir_list.push(attempt(d, r));
    }
    if args.write_temp {
        let path = std::env::temp_dir().join(format!("pool-runner-temp-{}.bin", std::process::id()));
        let r = std::fs::write(&path, b"customer bytes would land here");
        if r.is_ok() {
            let _ = std::fs::remove_file(&path);
        }
        rep.temp_write = Some(attempt(&path.to_string_lossy(), r));
    }
    if let Some(mb) = args.alloc_mb {
        rep.alloc = Some(attempt(&format!("{mb} MiB"), alloc_and_touch(mb)));
    }
    for d in &args.load_dll {
        rep.dll_load.push(attempt(d, load_dll(d)));
    }
    if args.cuda {
        #[cfg(feature = "cuda")]
        let r = candle_core::Device::new_cuda(0).map(|_| ()).map_err(|e| std::io::Error::other(e.to_string()));
        #[cfg(not(feature = "cuda"))]
        let r: std::io::Result<()> = Err(std::io::Error::other("not a cuda build"));
        rep.cuda = Some(attempt("cuda:0", r));
    }
    if let Some(ms) = args.spin_ms {
        rep.cpu = Some(spin(ms));
    }
    rep
}

/// Open the agent's control endpoint: a named pipe path on Windows (`\\.\pipe\...`), a socket path elsewhere.
fn ipc_connect(target: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new().read(true).write(true).open(target).map(|_| ())
    }
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(target).and_then(|mut s| s.write_all(b"{}\n"))
    }
}

/// Reserve and touch `mb` MiB, page by page, so a commit or address-space cap shows up as a failed allocation.
fn alloc_and_touch(mb: u64) -> std::io::Result<()> {
    let n = usize::try_from(mb << 20).map_err(std::io::Error::other)?;
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(n).map_err(|e| std::io::Error::other(format!("allocation refused: {e}")))?;
    v.resize(n, 1);
    let sum: u64 = v.iter().step_by(4096).map(|b| u64::from(*b)).sum();
    std::hint::black_box(sum);
    Ok(())
}

/// Busy-loop for `ms` of wall time and report the CPU time this process got.
fn spin(ms: u64) -> CpuUse {
    let t0 = std::time::Instant::now();
    let c0 = cpu_time_ms();
    let mut x: u64 = 1;
    while t0.elapsed() < Duration::from_millis(ms) {
        for _ in 0..10_000 {
            x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
    }
    CpuUse { wall_ms: t0.elapsed().as_millis() as u64, cpu_ms: cpu_time_ms().saturating_sub(c0) }
}

#[cfg(windows)]
fn cpu_time_ms() -> u64 {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime(u32, u32);
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(p: isize, c: *mut FileTime, e: *mut FileTime, k: *mut FileTime, u: *mut FileTime) -> i32;
    }
    let (mut c, mut e, mut k, mut u) = (FileTime::default(), FileTime::default(), FileTime::default(), FileTime::default());
    // SAFETY: four valid out-pointers; the pseudo-handle needs no closing.
    if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) } == 0 {
        return 0;
    }
    let t = |f: FileTime| (u64::from(f.1) << 32 | u64::from(f.0)) / 10_000; // 100 ns -> ms
    t(k) + t(u)
}

#[cfg(unix)]
fn cpu_time_ms() -> u64 {
    // SAFETY: getrusage only writes into `r`.
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) } != 0 {
        return 0;
    }
    let ms = |t: libc::timeval| t.tv_sec as u64 * 1000 + t.tv_usec as u64 / 1000;
    ms(r.ru_utime) + ms(r.ru_stime)
}

#[cfg(windows)]
fn load_dll(path: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    }
    let w: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: NUL-terminated wide path; LOAD_WITH_ALTERED_SEARCH_PATH (8)
    let h = unsafe { LoadLibraryExW(w.as_ptr(), 0, 8) };
    if h == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn load_dll(path: &str) -> std::io::Result<()> {
    let c = std::ffi::CString::new(path).map_err(std::io::Error::other)?;
    // SAFETY: valid C string; RTLD_NOW
    let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        Err(std::io::Error::other("dlopen failed"))
    } else {
        Ok(())
    }
}
