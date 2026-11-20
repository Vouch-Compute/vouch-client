//! `pool-core` binary.
//!
//!   pool-core                 agent + local control channel for the Vouch Compute app (default)
//!   pool-core --headless      agent + control channel, logs to stderr (P1 worker mode)
//!   pool-core version
//!   pool-core sandbox-probe [probe args]   dev builds only: run `pool-runner probe` in the job sandbox (e2e)
//!   pool-core uninstall-cleanup [--delete-data]   run by the uninstaller (sandbox profile; device keys on request)
//!
//! Data dir: `POOL_DATA_DIR` or the per-user local app data dir. Config: `<data>/config.json` and
//! `POOL_ENGINE_WS_URL`, `POOL_VAULT_URL`, `POOL_WEB_URL`, `POOL_RUNNER_PATH`; release builds ignore the endpoint
//! values and always use the release hosts.

use pool_core::{agent::Agent, config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("version") {
        println!("pool-core {} (protocol {}; {})", env!("CARGO_PKG_VERSION"), pool_proto::PROTOCOL_VERSION, pool_proto::BUILD_INFO);
        return Ok(());
    }
    // no crash dump may carry hardware identifiers or job data
    pool_core::hwids::disable_crash_dumps();
    if args.first().map(String::as_str) == Some("sandbox-probe") {
        return sandbox_probe(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("uninstall-cleanup") {
        return uninstall_cleanup(args.iter().any(|a| a == "--delete-data")).await;
    }
    let headless = args.iter().any(|a| a == "--headless");
    let data_dir = config::default_data_dir();
    std::fs::create_dir_all(data_dir.join("logs"))?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if headless {
        // colours only on a terminal: a supervisor or test harness that captures stderr gets plain lines
        tracing_subscriber::fmt().with_env_filter(filter).with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())).init();
    } else {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(data_dir.join("logs").join("core.log"))?;
        tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(std::sync::Mutex::new(log)).init();
    }
    let cfg = config::Config::load(&data_dir);
    #[cfg(feature = "dev-trust")]
    if !cfg.dev_trust_roots.is_empty() && std::env::var_os(pool_proto::trust::DEV_ROOTS_ENV).is_none() {
        // edition 2021: set before any thread reads the environment; inherited by the sandboxed runner
        std::env::set_var(pool_proto::trust::DEV_ROOTS_ENV, cfg.dev_trust_roots.join(","));
    }
    tracing::info!("pool-core {} starting; data dir {}; {}", env!("CARGO_PKG_VERSION"), data_dir.display(), pool_proto::BUILD_INFO);
    // single instance: bind the control endpoint before starting any session
    let listener = match pool_core::control::bind(&data_dir) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("{e}; exiting");
            eprintln!("{e}");
            return Ok(());
        }
    };
    let agent = Agent::new(data_dir, cfg)?;
    tracing::info!("device key storage: {:?}", agent.key_storage());
    let a = agent.clone();
    tokio::select! {
        _ = agent.run() => {}
        r = pool_core::control::serve(a, listener) => { r?; }
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

/// Run by the uninstaller (the agent is already stopped). Always removes the job sandbox's OS profile. With
/// `--delete-data` (the user ticked "delete the application data") it first removes this device from the account
/// with a signed `self_revoke` (best effort, at most 5 s, never fails the uninstall), and only then deletes this
/// user's device keys from the TPM; the data folder itself is removed by the uninstaller. Exits 0 in every case.
async fn uninstall_cleanup(delete_data: bool) -> anyhow::Result<()> {
    pool_sandbox::remove_os_profiles();
    if !delete_data {
        return Ok(());
    }
    let data_dir = config::default_data_dir();
    let cfg = config::Config::load(&data_dir);
    let limit = std::time::Duration::from_secs(5);
    // strictly before the keys are deleted: the revocation is signed with the device key
    let revoke = tokio::time::timeout(limit, pool_core::agent::uninstall_self_revoke(&data_dir, &cfg, limit)).await;
    match revoke {
        Ok(Ok(true)) => println!("this device was removed from the account"),
        Ok(Ok(false)) => println!("this computer was not registered; nothing to remove from the account"),
        Ok(Err(e)) => println!("could not remove this device from the account ({e}); remove it on the website"),
        Err(_) => println!("the account server did not answer in time; remove this device on the website"),
    }
    #[cfg(windows)]
    {
        let state = config::State::load(&data_dir);
        let mut names = vec![pool_core::identity::TPM_KEY_NAME, pool_core::identity::TPM_AIK_NAME];
        if let Some(n) = state.tpm_key_name.as_deref() {
            names.push(n);
        }
        let n = pool_core::identity::tpm::delete_persisted_keys(&names);
        println!("removed {n} device key(s)");
    }
    Ok(())
}

/// Dev builds only (e2e): start `pool-runner probe...` through `pool-sandbox` with the same profile, limits and
/// readable dirs a job gets (`runner_client`), and print `{"level", "report"}`. The live e2e suite runs it while
/// the agent is executing a real job, next to an inspection of that job's runner process, to show the sandbox
/// still blocks network and file access. Release builds refuse it.
fn sandbox_probe(args: &[String]) -> anyhow::Result<()> {
    if !cfg!(feature = "dev-trust") {
        anyhow::bail!("sandbox-probe is only available in dev builds");
    }
    use std::io::Read;
    let cfg = config::Config::load(&config::default_data_dir());
    let mut readable = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--model-dir" {
            if let Some(d) = it.next() {
                readable.push(std::path::PathBuf::from(d));
            }
        }
    }
    let sc = pool_sandbox::SandboxConfig {
        readable_dirs: readable,
        memory_limit_bytes: 8 << 30,
        cpu_rate_pct: Some(pool_core::runner_client::RUNNER_CPU_CAP_PCT),
        // dev diagnostics: POOL_SANDBOX_NO_LPAC=1 probes a regular AppContainer (GPU diagnosis)
        lpac: std::env::var("POOL_SANDBOX_NO_LPAC").as_deref() != Ok("1"),
        env: vec![],
        // dev diagnostics: POOL_SANDBOX_GPU=1 probes with the macOS GPU (Metal) allowances
        gpu: std::env::var("POOL_SANDBOX_GPU").as_deref() == Ok("1"),
    };
    let mut probe_args = vec!["probe".to_string()];
    probe_args.extend(args.iter().filter(|a| *a != "--no-harden").cloned());
    let mut s = pool_sandbox::spawn_sandboxed(&cfg.runner_exe(), &probe_args, &sc)?;
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let mut stderr = std::mem::replace(&mut s.stderr, Box::new(std::io::empty()));
    let drain = std::thread::spawn(move || {
        let mut e = String::new();
        let _ = stderr.read_to_string(&mut e);
        e
    });
    let mut out = String::new();
    s.stdout.read_to_string(&mut out)?;
    let code = s.process.wait()?;
    let err = drain.join().unwrap_or_default();
    let report: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or(serde_json::Value::Null);
    println!("{}", serde_json::json!({ "level": format!("{:?}", s.level), "exit": code, "report": report, "stderr": err.chars().take(2000).collect::<String>() }));
    Ok(())
}
