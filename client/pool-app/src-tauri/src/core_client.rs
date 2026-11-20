//! Client for pool-core's local control channel (named pipe on Windows, Unix socket elsewhere).
//! Mirrors `pool_core::control` (endpoint name, data dir, token file); kept separate so the app links
//! none of the agent's code.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The bundle identifier: dev builds use their own, so a dev build never shares a data dir with a
/// release. Must match `pool_proto::BUNDLE_ID` of the agent built alongside (same dev/release channel).
pub const BUNDLE_ID: &str = match crate::updater::CHANNEL {
    crate::updater::Channel::Dev => "com.vouchcompute.app.dev",
    crate::updater::Channel::Release => "com.vouchcompute.app",
};

/// `<local data dir>/<bundle id>` (Windows `%LOCALAPPDATA%\com.vouchcompute.app`), mirroring pool-core.
pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("POOL_DATA_DIR") {
        return d.into();
    }
    directories::BaseDirs::new()
        .map(|b| b.data_local_dir().join(BUNDLE_ID))
        .unwrap_or_else(|| std::env::temp_dir().join(BUNDLE_ID))
}

fn endpoint_name() -> String {
    use sha2::Digest;
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into());
    let digest = sha2::Sha256::digest(user.as_bytes());
    let tag: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    if cfg!(windows) {
        format!(r"\\.\pipe\vouch-core-{tag}")
    } else {
        format!("vouch-core-{tag}.sock")
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Methods the UI may call (everything read-only or a local setting; no wallet write exists).
pub const ALLOWED: &[&str] = &[
    "status", "settings.get", "settings.set", "pause", "resume", "benchmark.now", "signin.start", "signin.status",
    "signout", "estimate", "wallets", "earnings", "device", "reconnect",
    // 2.1.0 (M9-C): hardware-identifier consent, enrollment choice, device actions, recovery, identity repair
    "hw_consent.get", "hw_consent.set", "enroll", "device.control", "recovery.prove", "identity.repair",
];

async fn roundtrip<S>(stream: S, line: String) -> Result<Value, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    w.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(r).lines();
    let resp = lines.next_line().await.map_err(|e| e.to_string())?.ok_or("agent closed the connection")?;
    let v: Value = serde_json::from_str(&resp).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(v.get("error").and_then(Value::as_str).unwrap_or("agent error").to_string())
    }
}

pub async fn call(method: &str, params: Value) -> Result<Value, String> {
    let token = std::fs::read_to_string(data_dir().join("control.token")).map_err(|_| "agent not running".to_string())?;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let line = format!("{}\n", json!({ "id": id, "token": token.trim(), "method": method, "params": params }));
    #[cfg(windows)]
    {
        let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(endpoint_name())
            .map_err(|_| "agent not running".to_string())?;
        roundtrip(pipe, line).await
    }
    #[cfg(unix)]
    {
        let s = tokio::net::UnixStream::connect(data_dir().join(endpoint_name()))
            .await
            .map_err(|_| "agent not running".to_string())?;
        roundtrip(s, line).await
    }
}

/// Start the agent (bundled sidecar next to the app binary) if it is not reachable, then wait for it.
pub async fn ensure_running() -> Result<(), String> {
    if call("status", Value::Null).await.is_ok() {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("no exe dir")?;
    let core = dir.join(if cfg!(windows) { "pool-core.exe" } else { "pool-core" });
    let mut cmd = std::process::Command::new(&core);
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn().map_err(|e| format!("could not start the Vouch Compute agent ({}): {e}", core.display()))?;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if call("status", Value::Null).await.is_ok() {
            return Ok(());
        }
    }
    Err("the Vouch Compute agent did not start".into())
}
