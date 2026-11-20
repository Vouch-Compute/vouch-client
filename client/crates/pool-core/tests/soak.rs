//! Soak: the real agent and real sandboxed runner process job after job for `POOL_SOAK_SECS` (default 120 s),
//! with a reconnect every 100 jobs, a pause/resume every 150 jobs and a pre-empted job every 75 jobs. Memory and
//! handles are sampled; the run fails on growth after warm-up, on leaked runner processes, on a growing lease-nonce
//! book, or on any job whose result the server's checks would refuse.
//!
//!   POOL_SOAK_SECS=3600 cargo test -p pool-core --test soak -- --ignored --nocapture

mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mock_server::{uuid, Hub, Mock, IDLE_S};
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};

#[allow(dead_code)] // fields are read through Debug
#[derive(Debug, Clone, Copy, Default)]
struct Sample {
    secs: u64,
    jobs: u64,
    rss_mb: f64,
    handles: u64,
    leases_tracked: usize,
}

#[cfg(windows)]
fn usage() -> (f64, u64) {
    #[repr(C)]
    #[derive(Default)]
    struct Pmc {
        cb: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(p: isize, c: *mut Pmc, cb: u32) -> i32;
        fn GetProcessHandleCount(p: isize, n: *mut u32) -> i32;
    }
    let mut c = Pmc { cb: std::mem::size_of::<Pmc>() as u32, ..Default::default() };
    let mut h = 0u32;
    // SAFETY: valid out-pointers; pseudo-handle.
    unsafe {
        K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
        GetProcessHandleCount(GetCurrentProcess(), &mut h);
    }
    // private bytes: what a leak grows
    (c.pagefile as f64 / (1 << 20) as f64, u64::from(h))
}

#[cfg(unix)]
fn usage() -> (f64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kb = status.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count() as u64).unwrap_or(0);
    (kb / 1024.0, fds)
}

fn runner_processes() -> usize {
    if cfg!(windows) {
        let out = std::process::Command::new("tasklist").args(["/FI", "IMAGENAME eq pool-runner.exe", "/NH"]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.to_ascii_lowercase().starts_with("pool-runner.exe")).count()
    } else {
        let out = std::process::Command::new("pgrep").args(["-x", "pool-runner"]).output();
        out.map(|o| String::from_utf8_lossy(&o.stdout).lines().count()).unwrap_or(0)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running soak; run explicitly with --ignored"]
async fn soak() {
    let secs: u64 = std::env::var("POOL_SOAK_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let data = tempfile::tempdir().unwrap();
    let _ = tracing_subscriber::fmt().with_env_filter("warn").with_test_writer().try_init();
    let (m, agent) = mock_server::start(data.path()).await;
    m.prune.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let jobs = Arc::new(Mutex::new(0u64));
    let preempted = Arc::new(Mutex::new(0u64));
    let failure = Arc::new(Mutex::new(None::<String>));

    // enough connection scripts for the whole run: each runs up to 100 jobs, then asks for a reconnect
    for _ in 0..10_000 {
        let (jobs, preempted, ag) = (jobs.clone(), preempted.clone(), agent.clone());
        m.scripts.lock().unwrap().push_back(Box::new(move |mut hub: Hub, m: Arc<Mock>| {
            Box::pin(async move {
                hub.handshake(&m).await?;
                hub.ensure_cached(&m).await?;
                for _ in 0..100 {
                    if Instant::now() > deadline {
                        return Ok(());
                    }
                    let n = *jobs.lock().unwrap() + 1;
                    if n.is_multiple_of(75) {
                        // a job the user interrupts: Abandon(PREEMPTED), then the device is idle again
                        let (j, l) = (uuid(), uuid());
                        hub.send(m.offer(&j)).await?;
                        let NB::Accept(_) = hub.recv(false).await? else { return Err("expected Accept".into()) };
                        let input = br#"{"inputs":["slow"]}"#.to_vec();
                        m.add_lease(&l, input.clone(), 1_500);
                        hub.send(m.grant(&m.envelope(&l, &j, &input))).await?;
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        IDLE_S.store(0, Ordering::SeqCst);
                        match hub.recv(false).await? {
                            NB::Abandon(a) if a.reason == pb::AbandonReason::Preempted as i32 => {}
                            other => return Err(format!("expected Abandon(PREEMPTED), got {other:?}")),
                        }
                        IDLE_S.store(3600, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(1_200)).await;
                        *preempted.lock().unwrap() += 1;
                    }
                    if n.is_multiple_of(150) {
                        // pause from the app (control dispatcher): offers are declined; resume: work again
                        pool_core::control::dispatch(&ag, "pause", serde_json::json!({"minutes": 1})).await?;
                        tokio::time::sleep(Duration::from_millis(1_500)).await;
                        let j = uuid();
                        hub.send(m.offer(&j)).await?;
                        match hub.recv(false).await? {
                            NB::Decline(d) if d.job_id == j => {}
                            other => return Err(format!("expected Decline while paused, got {other:?}")),
                        }
                        pool_core::control::dispatch(&ag, "resume", serde_json::Value::Null).await?;
                        tokio::time::sleep(Duration::from_millis(1_500)).await;
                    }
                    let input = format!(r#"{{"inputs":["soak job {n}","{}"]}}"#, "x".repeat((n % 50) as usize)).into_bytes();
                    hub.job(&m, input).await?;
                    *jobs.lock().unwrap() = n;
                }
                hub.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 1 })).await?;
                Ok(())
            })
        }));
    }

    let run = tokio::spawn(agent.clone().run());
    let t0 = Instant::now();
    let mut samples: Vec<Sample> = vec![];
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if let Some(e) = m.results.lock().unwrap().iter().find_map(|r| r.clone().err()) {
            *failure.lock().unwrap() = Some(e);
            break;
        }
        let done = *jobs.lock().unwrap();
        let (rss_mb, handles) = usage();
        let s = Sample { secs: t0.elapsed().as_secs(), jobs: done, rss_mb, handles, leases_tracked: agent.tracked_leases() };
        if samples.len().is_multiple_of(12) {
            eprintln!("{s:?}");
        }
        samples.push(s);
        if Instant::now() > deadline + Duration::from_secs(20) {
            break;
        }
    }
    run.abort();
    if let Some(e) = failure.lock().unwrap().clone() {
        panic!("soak failed after {:?}: {e}; problems {:?}", t0.elapsed(), m.problems.lock().unwrap());
    }
    assert!(m.problems.lock().unwrap().is_empty(), "{:?}", m.problems.lock().unwrap());
    let total = *jobs.lock().unwrap();
    let last = *samples.last().unwrap();
    // warm-up: the first sample after a quarter of the run (allocator pools, model cache, TLS etc. settled)
    let warm = samples[samples.len() / 4];
    let peak_rss = samples.iter().map(|s| s.rss_mb).fold(0.0, f64::max);
    eprintln!(
        "SOAK {secs}s: {total} jobs, {} pre-empted, {} connections; private/RSS {:.1} MB after warm-up -> {:.1} MB at end (peak {:.1}); handles/fds {} -> {}; leases tracked at end {}",
        preempted.lock().unwrap(),
        m.connections.load(Ordering::SeqCst),
        warm.rss_mb,
        last.rss_mb,
        peak_rss,
        warm.handles,
        last.handles,
        last.leases_tracked
    );
    assert!(total >= 20, "too few jobs: {total}");
    assert!(last.rss_mb < warm.rss_mb + 64.0, "memory grew {:.1} -> {:.1} MB", warm.rss_mb, last.rss_mb);
    assert!(last.handles < warm.handles + 200, "handles/fds grew {} -> {}", warm.handles, last.handles);
    assert!(last.leases_tracked <= 2, "lease nonce book grows: {}", last.leases_tracked);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(runner_processes(), 0, "runner processes left behind");
}
