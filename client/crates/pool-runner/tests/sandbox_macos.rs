//! macOS-specific sandbox checks for the `sandbox-exec` runner (the cross-platform probes are in `sandbox.rs`, the
//! agent's control socket and data dir in pool-core's `sandbox_isolation.rs`).
//!
//! Each probe first runs **without** the sandbox as a control (so a failure inside the sandbox means the sandbox
//! blocked it, not that the probe is broken), then inside it. Covered here:
//! * the user's folders: home, `~/Documents`, `~/Desktop`, `~/Library` (keychains, mail, messages), `/Users/Shared`;
//! * writes: home, `/tmp`, the per-user `$TMPDIR`, the read-only model dir itself;
//! * network: loopback TCP, a Unix socket, the public internet, DNS;
//! * other processes: their arguments and environment (`KERN_PROCARGS2`), signals;
//! * Mach services that would leak user data or act for the user: pasteboard, keychain, window server, TCC, ...
//!
//! `~/Documents` and `~/Desktop` are TCC-protected: the control run does not touch them (it would raise a privacy
//! prompt for the terminal). Inside the sandbox they must fail like every other user path.
#![cfg(target_os = "macos")]

use std::io::Read;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use pool_runner::probe::ProbeReport;
use pool_sandbox::{spawn_sandboxed, spawn_unsandboxed, SandboxConfig, SandboxLevel};

fn runner() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pool-runner"))
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap())
}

/// The per-user temp dir (`/var/folders/.../T/`), which `std::env::temp_dir` returns only if TMPDIR is set.
fn user_temp_dir() -> PathBuf {
    let mut buf = vec![0u8; 1024];
    // SAFETY: buf is writable for its length.
    let n = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
    assert!(n > 0 && n <= buf.len());
    buf.truncate(n - 1);
    PathBuf::from(String::from_utf8(buf).unwrap())
}

const MACH: &[&str] = &[
    "com.apple.pasteboard.1",               // clipboard
    "com.apple.SecurityServer",             // keychain
    "com.apple.securityd.xpc",              // keychain (XPC)
    "com.apple.windowserver.active",        // screen contents, synthetic input
    "com.apple.tccd",                       // privacy database
    "com.apple.tccd.system",
    "com.apple.coreservices.launchservicesd", // open URLs / apps
    "com.apple.lsd.mapdb",
    "com.apple.FileCoordination",
    "com.apple.dock.server",
    "com.apple.pboard",
    "com.apple.audio.audiohald",            // microphone
    "com.apple.cmio.registerassistantservice", // camera
    "com.apple.mDNSResponder",              // DNS
    "com.apple.nsurlsessiond",              // background downloads
];

struct Fixture {
    _area: tempfile::TempDir,
    _model: tempfile::TempDir,
    _sock_dir: tempfile::TempDir,
    _unix: UnixListener,
    secret: PathBuf,
    model: PathBuf,
    args: Vec<String>,
}

fn fixture() -> Fixture {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in tcp.incoming().flatten() {
            drop(s);
        }
    });
    let area = tempfile::Builder::new().prefix("pool-macos-probe").tempdir_in(home().join(".cache")).unwrap();
    let secret = area.path().join("api-token.txt");
    std::fs::write(&secret, b"user secret").unwrap();
    let model = tempfile::tempdir().unwrap();
    std::fs::write(model.path().join("model.safetensors"), b"weights").unwrap();
    let sock_dir = tempfile::Builder::new().prefix("pool-sock").tempdir_in(home().join(".cache")).unwrap();
    let sock = sock_dir.path().join("s");
    let unix = UnixListener::bind(&sock).unwrap();
    let me = std::process::id().to_string();
    let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let mut args: Vec<String> = vec!["probe".into(), "--model-dir".into(), s(model.path())];
    let mut push = |k: &str, v: String| {
        args.push(k.into());
        args.push(v);
    };
    push("--connect", addr.to_string());
    push("--ipc", s(&sock));
    push("--read", s(&secret));
    push("--list", s(&home()));
    push("--list", s(area.path()));
    push("--write-dir", s(area.path()));
    push("--write-dir", s(&home()));
    push("--write-dir", "/tmp".into());
    push("--write-dir", s(&user_temp_dir()));
    push("--write-dir", s(model.path()));
    push("--procargs", me.clone());
    push("--signal", me);
    push("--stat", s(&secret));
    for m in MACH {
        push("--mach", (*m).into());
    }
    args.push("--spawn".into());
    let model_path = model.path().to_path_buf();
    Fixture { _area: area, _model: model, _sock_dir: sock_dir, _unix: unix, secret, model: model_path, args }
}

fn run(args: &[String], model: &std::path::Path, sandboxed: bool) -> (ProbeReport, SandboxLevel) {
    let cfg = SandboxConfig { readable_dirs: vec![model.to_path_buf()], ..Default::default() };
    let mut s = if sandboxed { spawn_sandboxed(&runner(), args, &cfg) } else { spawn_unsandboxed(&runner(), args, &cfg) }
        .expect("spawn runner");
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let (mut out, mut err) = (String::new(), String::new());
    s.stdout.read_to_string(&mut out).unwrap();
    s.stderr.read_to_string(&mut err).unwrap();
    let code = s.process.wait().unwrap();
    assert_eq!(code, 0, "probe exited {code}: stdout={out} stderr={err}");
    (serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("bad probe output {out:?}: {e}")), s.level)
}

#[test]
fn macos_sandbox_blocks_user_data_network_processes_and_services() {
    // The test's own environment carries a "secret": a sandboxed job must not be able to read it via sysctl.
    std::env::set_var("POOL_TEST_PARENT_SECRET", "s3cr3t");
    let fx = fixture();

    // Control run: every probe works outside the sandbox.
    let mut ctl_args = fx.args.clone();
    ctl_args.push("--no-harden".into());
    let (ctl, level) = run(&ctl_args, &fx.model, false);
    assert_eq!(level, SandboxLevel::None);
    assert!(ctl.net_connect.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.ipc_connect.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.file_read.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.dir_list.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.file_write.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.procargs.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.signal.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.stat.iter().all(|a| a.ok), "control: {ctl:#?}");
    assert!(ctl.spawn.as_ref().unwrap().ok, "control: {ctl:#?}");
    let reachable: Vec<_> = ctl.mach_lookup.iter().filter(|a| a.ok).map(|a| a.target.clone()).collect();
    assert!(reachable.iter().any(|n| n == "com.apple.pasteboard.1"), "control mach lookups: {:#?}", ctl.mach_lookup);

    // Sandboxed: TCC-protected folders and the user's Library are added (not touched by the control run).
    let mut args = fx.args.clone();
    for d in ["Documents", "Desktop", "Downloads", "Library/Keychains", "Library/Mail", "Library/Messages"] {
        args.extend(["--list".into(), home().join(d).to_string_lossy().into_owned()]);
    }
    args.extend(["--list".into(), "/Users/Shared".into(), "--list".into(), "/Volumes".into()]);
    args.extend(["--connect".into(), "1.1.1.1:443".into(), "--dns".into(), "example.com".into()]);
    let (rep, level) = run(&args, &fx.model, true);
    eprintln!("sandbox level {level:?}\n{rep:#?}");
    assert_eq!(level, SandboxLevel::MacosSandboxExec);
    for a in rep.net_connect.iter().chain(&rep.ipc_connect).chain(rep.dns.iter()) {
        assert!(!a.ok, "network/IPC reachable from the sandbox: {}", a.target);
    }
    for a in rep.file_read.iter().chain(&rep.dir_list).chain(&rep.file_write) {
        assert!(!a.ok, "user path accessible from the sandbox: {}", a.target);
    }
    assert!(!rep.file_write.iter().any(|a| a.target == fx.model.to_string_lossy() && a.ok), "model dir is writable");
    for a in &rep.stat {
        assert!(!a.ok, "the sandboxed job can read metadata (existence, size, times) of user file {}", a.target);
    }
    for a in &rep.signal {
        assert!(!a.ok, "the sandboxed job can signal pid {}", a.target);
    }
    for a in &rep.mach_lookup {
        assert!(!a.ok, "the sandboxed job can reach Mach service {}", a.target);
    }
    assert!(!rep.spawn.as_ref().unwrap().ok, "child process started in the sandbox");
    // procargs is checked by `known_gap_same_user_process_environment_is_readable` below
    let mut rep = rep;
    rep.procargs.clear();
    assert!(rep.all_blocked(), "{rep:#?}");
    let _ = &fx.secret;
}

/// **Known gap (MAC-REPORT.md, rated high):** `sandbox-exec` does not mediate `KERN_PROCARGS2`. A sandboxed job can
/// read the arguments and environment variables of every process of the same user (only other users' processes
/// are refused), whatever the profile says: denying `sysctl-read` by name or `process-info*` changes nothing. The
/// job cannot send them anywhere over the network, but a compromised runner could hide them in a job result.
/// Closing it needs the runner under another user or the signed App Sandbox helper (release setup).
/// This test asserts the gap exists so that it is visible; when it starts failing, the gap is closed: turn the
/// assertion around.
#[test]
fn known_gap_same_user_process_environment_is_readable() {
    std::env::set_var("POOL_TEST_PARENT_SECRET", "s3cr3t");
    let fx = fixture();
    let me = std::process::id().to_string();
    let args: Vec<String> = vec!["probe".into(), "--model-dir".into(), fx.model.to_string_lossy().into(), "--procargs".into(), me];
    let (rep, level) = run(&args, &fx.model, true);
    assert_eq!(level, SandboxLevel::MacosSandboxExec);
    assert!(
        rep.procargs[0].ok,
        "KERN_PROCARGS2 of a same-user process is now blocked inside the sandbox: the known gap is closed, update this test \
         and MAC-REPORT.md: {rep:#?}"
    );
}

/// macOS applies no memory rlimit, so the cap is the agent's footprint watchdog: a job that stays under the cap runs
/// to completion; one that goes over it is killed (it cannot fail its allocation gracefully like on Windows/Linux).
#[test]
fn memory_cap_kills_a_runner_over_the_cap() {
    let model = tempfile::tempdir().unwrap();
    let cap = 512u64 << 20;
    let cfg = SandboxConfig { readable_dirs: vec![model.path().to_path_buf()], memory_limit_bytes: cap, ..Default::default() };
    let go = |mb: u64, sandboxed: bool| {
        let args: Vec<String> =
            vec!["probe".into(), "--model-dir".into(), model.path().to_string_lossy().into(), "--alloc-mb".into(), mb.to_string()];
        let mut s = if sandboxed { spawn_sandboxed(&runner(), &args, &cfg) } else { spawn_unsandboxed(&runner(), &args, &cfg) }.unwrap();
        drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
        let mut out = String::new();
        s.stdout.read_to_string(&mut out).unwrap();
        (s.process.wait().unwrap(), out)
    };
    let (code, out) = go(128, true);
    assert_eq!(code, 0, "128 MiB fits a 512 MiB cap: {out}");
    assert!(out.contains(r#""alloc":{"target":"128 MiB","ok":true"#), "{out}");
    let (code, out) = go(2048, true);
    assert_ne!(code, 0, "2 GiB must not survive a 512 MiB cap: {out}");
    assert!(out.is_empty(), "the runner must be killed before it reports: {out}");
    let (code, _) = go(2048, false);
    assert_eq!(code, 0, "control: the same allocation works without the sandbox");
}

/// GPU jobs (`SandboxConfig::gpu`, `metal` builds): Metal works inside the sandbox, and the GPU allowances open
/// nothing else: every escape probe still fails. Without the allowances no Metal device is visible and the runner
/// reports it (no crash), so the job falls back to the CPU.
#[cfg(feature = "metal")]
#[test]
fn metal_gpu_jobs_keep_every_other_rule() {
    let fx = fixture();
    let mut args = fx.args.clone();
    args.push("--metal".into());
    let run_gpu = |gpu: bool| {
        let cfg = SandboxConfig { readable_dirs: vec![fx.model.clone()], gpu, ..Default::default() };
        let mut s = spawn_sandboxed(&runner(), &args, &cfg).expect("spawn runner");
        drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
        let (mut out, mut err) = (String::new(), String::new());
        s.stdout.read_to_string(&mut out).unwrap();
        s.stderr.read_to_string(&mut err).unwrap();
        assert_eq!(s.process.wait().unwrap(), 0, "probe exited: {out} {err}");
        serde_json::from_str::<ProbeReport>(out.trim()).unwrap()
    };
    let mut gpu = run_gpu(true);
    eprintln!("GPU sandbox: {gpu:#?}");
    assert!(gpu.metal.as_ref().unwrap().ok, "Metal must work in a GPU job's sandbox: {:?}", gpu.metal);
    for a in &gpu.stat {
        assert!(!a.ok, "GPU sandbox: metadata of {}", a.target);
    }
    gpu.procargs.clear(); // the known gap, see known_gap_same_user_process_environment_is_readable
    assert!(gpu.all_blocked(), "the GPU allowances opened something else: {gpu:#?}");
    let cpu = run_gpu(false);
    let m = cpu.metal.unwrap();
    assert!(!m.ok, "without the GPU allowances Metal must not be reachable: {m:?}");
}
