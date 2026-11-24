//! Sandbox tests that need the agent's own pieces (pool-runner's `tests/sandbox.rs` covers network, user files,
//! writes and child processes):
//!
//! 1. The sandboxed runner cannot reach the **agent**: not its control pipe/socket (the real `control` endpoint with
//!    its per-user DACL / 0600 socket), not its data dir (control token, device key, state), not a listing of the
//!    user's home. Its own temp dir is not writable either. A control run without the sandbox shows every probe
//!    works.
//! 2. The memory cap applies (Job Object process memory on Windows, `RLIMIT_DATA` on Linux; macOS: see `memory_cap_applies`).
//! 3. The CPU cap applies (Windows Job Object hard cap; Linux has only `nice`, see the doc).
//! 4. A source audit: the only code that writes files is the reviewed list below (state, token, keys, logs, the
//!    verified model cache). Nothing on the job path (lease, jobs, session, runner client, runner) writes a file.

use std::io::Read;
use std::path::{Path, PathBuf};

use pool_runner::probe::ProbeReport;
use pool_sandbox::{spawn_sandboxed, spawn_unsandboxed, SandboxConfig, SandboxLevel};

fn runner_exe() -> PathBuf {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "pool-runner", "--bin", "pool-runner"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(status.success());
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(if cfg!(windows) { "pool-runner.exe" } else { "pool-runner" })
}

/// A dir in the user's own area (like the real data dir under LOCALAPPDATA / ~/.local/share).
fn user_dir(prefix: &str) -> tempfile::TempDir {
    let base = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap().join(".cache");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new().prefix(prefix).tempdir_in(base).unwrap()
}

fn probe(args: &[String], cfg: &SandboxConfig, sandboxed: bool) -> (ProbeReport, SandboxLevel) {
    let mut full = vec!["probe".to_string()];
    full.extend(args.iter().cloned());
    if !sandboxed {
        full.push("--no-harden".into());
    }
    let mut s = if sandboxed { spawn_sandboxed(&runner_exe(), &full, cfg) } else { spawn_unsandboxed(&runner_exe(), &full, cfg) }
        .expect("spawn runner");
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let mut out = String::new();
    let mut err = String::new();
    s.stdout.read_to_string(&mut out).unwrap();
    s.stderr.read_to_string(&mut err).unwrap();
    let code = s.process.wait().unwrap();
    assert_eq!(code, 0, "probe exited {code}: {out} {err}");
    (serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("bad probe output {out:?} ({e}); stderr {err}")), s.level)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandboxed_runner_cannot_reach_the_agent_or_its_data() {
    isolation(true).await;
}

/// Jobs that use the GPU backend pack run in a regular AppContainer (LPAC refuses to load DirectML / ONNX
/// Runtime). The same escape probes must still all fail there; only on Windows is there a difference.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regular_appcontainer_for_gpu_jobs_is_still_isolated() {
    isolation(false).await;
}

async fn isolation(lpac: bool) {
    let data = user_dir("pool-m7-data");
    // what a real data dir holds: the control token, a device key file, the state
    std::fs::write(data.path().join("state.json"), br#"{"device_id":"x"}"#).unwrap();
    std::fs::write(data.path().join("device_key.sealed"), b"sealed key bytes").unwrap();
    // the agent's real control endpoint (Windows: per-user DACL pipe; Unix: 0600 socket in the 0700 data dir)
    #[cfg(windows)]
    let (endpoint, _listener) = {
        let name = format!(r"\\.\pipe\vouch-core-m7test-{}-{lpac}", std::process::id());
        let l = pool_core::control::bind_named(data.path(), &name).unwrap();
        // one listening instance per probe (control run + sandboxed run), each with the agent's per-user DACL;
        // with a single instance the control run intermittently saw it busy
        let extra: Vec<_> = (0..2).map(|_| pool_core::control::acl::create_pipe(&name, false).unwrap()).collect();
        (name, (l, extra))
    };
    #[cfg(unix)]
    let (endpoint, _listener) = {
        let l = pool_core::control::bind(data.path()).unwrap();
        (data.path().join(pool_core::control::endpoint_name()).to_string_lossy().into_owned(), l)
    };
    let home = std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap();
    let model_dir = tempfile::tempdir().unwrap();
    let d = data.path().to_string_lossy().into_owned();
    let args: Vec<String> = [
        "--ipc", &endpoint,
        "--read", &format!("{d}/control.token"),
        "--read", &format!("{d}/device_key.sealed"),
        "--read", &format!("{d}/state.json"),
        "--list", &home,
        "--list", &d,
        "--write-dir", &d,
        "--write-temp",
        "--model-dir", &model_dir.path().to_string_lossy(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let cfg = SandboxConfig { readable_dirs: vec![model_dir.path().to_path_buf()], lpac, ..Default::default() };

    // control run: every probe works without the sandbox
    let (ctl, _) = probe(&args, &cfg, false);
    assert!(ctl.ipc_connect[0].ok, "control run must reach the agent endpoint: {ctl:?}");
    assert!(ctl.file_read.iter().all(|a| a.ok), "{ctl:?}");
    assert!(ctl.dir_list.iter().all(|a| a.ok), "{ctl:?}");
    assert!(ctl.temp_write.as_ref().unwrap().ok, "{ctl:?}");

    let (rep, level) = probe(&args, &cfg, true);
    eprintln!("sandbox level {level:?}\n{rep:#?}");
    assert_ne!(level, SandboxLevel::None);
    #[cfg(windows)]
    assert_eq!(level, if lpac { SandboxLevel::WindowsLpac } else { SandboxLevel::WindowsAppcontainer });
    assert!(!rep.ipc_connect[0].ok, "the runner reached the agent's control endpoint: {rep:?}");
    #[cfg(target_os = "linux")]
    rep.harden.job_allowed().expect("Linux hardening must be complete for jobs to run");
    for a in rep.file_read.iter().chain(&rep.dir_list).chain(&rep.file_write) {
        assert!(!a.ok, "sandboxed runner could access {}: {rep:?}", a.target);
    }
    assert!(!rep.temp_write.as_ref().unwrap().ok, "the runner can write its temp dir: {rep:?}");
    assert!(rep.all_blocked());
}

/// Every job runs under the same sandbox identity (on Windows one AppContainer SID), so a directory granted to one job
/// must not stay readable for the next: a job reads its own model dir, never the one an earlier job was given (T-218
/// design review). Checked in both the LPAC and the regular AppContainer (ONNX Runtime jobs), and on every OS.
#[test]
fn a_job_cannot_read_the_model_dir_of_an_earlier_job() {
    let a = user_dir("pool-t219-model-a");
    let b = user_dir("pool-t219-model-b");
    std::fs::write(a.path().join("weights.bin"), b"model a").unwrap();
    std::fs::write(b.path().join("weights.bin"), b"model b").unwrap();
    let read = |target: &Path, job_dir: &Path, lpac: bool| {
        let args: Vec<String> =
            ["--read", &target.to_string_lossy(), "--model-dir", &job_dir.to_string_lossy()].iter().map(|s| s.to_string()).collect();
        let cfg = SandboxConfig { readable_dirs: vec![job_dir.to_path_buf()], lpac, ..Default::default() };
        probe(&args, &cfg, true).0.file_read[0].ok
    };
    let (fa, fb) = (a.path().join("weights.bin"), b.path().join("weights.bin"));
    for lpac in [true, false] {
        assert!(read(&fa, a.path(), lpac), "a job reads its own model dir (lpac {lpac})");
        assert!(!read(&fa, b.path(), lpac), "the next job read the earlier job's model dir (lpac {lpac})");
        assert!(read(&fb, b.path(), lpac), "(lpac {lpac})");
        assert!(!read(&fb, a.path(), lpac), "(lpac {lpac})");
    }
}

/// Windows (Job Object) and Linux (`RLIMIT_DATA`): an allocation over the cap fails inside the runner. macOS applies
/// no memory rlimit; there the agent's footprint watchdog kills the runner instead, tested in pool-runner's
/// `tests/sandbox_macos.rs` (`memory_cap_kills_a_runner_over_the_cap`).
#[cfg(not(target_os = "macos"))]
#[test]
fn memory_cap_applies() {
    let model_dir = tempfile::tempdir().unwrap();
    let cap = 512u64 << 20;
    let cfg = SandboxConfig { readable_dirs: vec![model_dir.path().to_path_buf()], memory_limit_bytes: cap, ..Default::default() };
    let md = model_dir.path().to_string_lossy().into_owned();
    let run = |mb: u64, sandboxed: bool| {
        let args = vec!["--alloc-mb".to_string(), mb.to_string(), "--model-dir".into(), md.clone()];
        probe(&args, &cfg, sandboxed).0.alloc.unwrap()
    };
    assert!(run(64, true).ok, "a small allocation works inside the cap");
    let big = run(1024, true);
    assert!(!big.ok, "1 GiB must not fit a 512 MiB cap: {big:?}");
    assert!(run(1024, false).ok, "control: the same allocation works without the sandbox");
}

#[cfg(windows)]
#[test]
fn cpu_cap_applies() {
    let model_dir = tempfile::tempdir().unwrap();
    let md = model_dir.path().to_string_lossy().into_owned();
    let args = vec!["--spin-ms".to_string(), "2000".into(), "--model-dir".into(), md];
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
    let free = SandboxConfig { readable_dirs: vec![model_dir.path().to_path_buf()], ..Default::default() };
    let ctl = probe(&args, &free, true).0.cpu.unwrap();
    assert!(ctl.cpu_ms as f64 > 0.5 * ctl.wall_ms as f64, "uncapped spin should get most of a core: {ctl:?}");
    // 1 % of all processors: at most ncpu % of one core
    let capped = SandboxConfig { cpu_rate_pct: Some(1), ..free };
    let c = probe(&args, &capped, true).0.cpu.unwrap();
    let allowed = (0.01 * ncpu).min(1.0) * c.wall_ms as f64;
    eprintln!("uncapped {ctl:?}; capped at 1% of {ncpu} CPUs {c:?} (allowed ~{allowed:.0} ms)");
    assert!((c.cpu_ms as f64) < allowed * 2.0 + 200.0, "CPU cap not applied: {c:?}");
}

/// Disk-write audit at the source level: these are the only places that write files. Anything new must be reviewed
/// (customer inputs and outputs are memory-only: lease.rs, jobs.rs, session.rs, runner_client.rs, the runner).
#[test]
fn only_reviewed_code_writes_files() {
    let reviewed: &[(&str, &str)] = &[
        ("pool-core/src/agent.rs", "creates the data dir"),
        ("pool-core/src/config.rs", "state.json (atomic temp + rename)"),
        ("pool-core/src/control.rs", "control.token"),
        ("pool-core/src/identity/mod.rs", "device key rotation (rename)"),
        ("pool-core/src/identity/software.rs", "sealed software device key"),
        ("pool-core/src/main.rs", "logs/core.log (no job data is logged: see the robustness test disk audit)"),
        ("pool-core/src/registry.rs", "the vault-signed model cache"),
        ("pool-runner/src/accel.rs", "no write: OpenOptions only for a read-only O_NOFOLLOW open of the runtime pack files (Linux)"),
        ("pool-runner/src/probe.rs", "sandbox self-test write attempts"),
        ("pool-runner/src/testutil.rs", "test fixtures"),
    ];
    let patterns = ["fs::write", "File::create", "OpenOptions", "fs::copy", "fs::rename", "create_dir", "tokio::fs"];
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut writers = Vec::new();
    for krate in ["pool-core/src", "pool-runner/src", "pool-sandbox/src", "pool-proto/src"] {
        let mut stack = vec![crates.join(krate)];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let src = std::fs::read_to_string(&p).unwrap();
                // test modules may write fixtures
                let code = src.split("#[cfg(test)]").next().unwrap();
                if patterns.iter().any(|pat| code.contains(pat)) {
                    let rel = p.strip_prefix(crates).unwrap().to_string_lossy().replace('\\', "/");
                    writers.push(rel);
                }
            }
        }
    }
    writers.sort();
    let mut allowed: Vec<String> = reviewed.iter().map(|(f, _)| f.to_string()).collect();
    allowed.sort();
    let unreviewed: Vec<_> = writers.iter().filter(|w| !allowed.contains(w)).collect();
    assert!(unreviewed.is_empty(), "file writes in unreviewed code: {unreviewed:?}");
    for job_path in ["pool-core/src/lease.rs", "pool-core/src/jobs.rs", "pool-core/src/session.rs", "pool-core/src/runner_client.rs", "pool-runner/src/lib.rs", "pool-runner/src/input.rs", "pool-runner/src/ipc.rs"] {
        assert!(!writers.iter().any(|w| w == job_path), "{job_path} writes files");
    }
}

/// The agent grants the macOS GPU sandbox rules only to a runner that reports a Metal build; the default runner (no
/// `metal` feature) never gets them, whatever the user's GPU setting.
#[test]
fn default_runner_gets_no_gpu_grant() {
    assert!(!pool_core::runner_client::runner_supports_metal(&runner_exe()));
}
