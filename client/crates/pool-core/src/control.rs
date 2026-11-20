//! Local control channel for the app (the app holds no keys and runs no jobs). JSON lines over a named
//! pipe (Windows, `\\.\pipe\vouch-core-<user>`, remote clients rejected) or a Unix socket (mode 0600 in
//! the data dir, which is 0700). Every request carries the random token from `<data>/control.token`, readable only
//! by the user. No listening network port is ever opened.
//!
//! One agent per machine: the pipe's DACL grants access to the installing OS user's SID
//! only (`D:P(A;;GA;;;<SID>)`, no inherited ACEs, no Everyone/Anonymous read ACE of the default pipe DACL), so a
//! second OS user on the same computer cannot open it. A second user's enrollment is refused by the server
//! (`409 hardware_in_use`) and the app says how to fix it.
//!
//! There is deliberately no wallet-write method: `wallets` only reads.

use std::sync::Arc;

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::agent::Agent;
use crate::governor::Settings;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: u64,
    pub token: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn endpoint_name() -> String {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into());
    let tag = hex::encode(&pool_proto::sha256(user.as_bytes())[..6]);
    if cfg!(windows) {
        format!(r"\\.\pipe\vouch-core-{tag}")
    } else {
        format!("vouch-core-{tag}.sock")
    }
}

/// Create (or rotate) the control token file.
pub fn write_token(data_dir: &std::path::Path) -> std::io::Result<String> {
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    let t = hex::encode(b);
    let p = data_dir.join("control.token");
    std::fs::write(&p, &t)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(t)
}

pub async fn dispatch(agent: &Arc<Agent>, method: &str, params: Value) -> Result<Value, String> {
    let e = |x: anyhow::Error| x.to_string();
    match method {
        "status" => Ok(agent.snapshot()),
        "settings.get" => Ok(json!(agent.settings())),
        "settings.set" => {
            let s: Settings = serde_json::from_value(params).map_err(|x| format!("bad settings: {x}"))?;
            Ok(json!(agent.set_settings(s)))
        }
        "pause" => {
            let minutes = params.get("minutes").and_then(Value::as_u64).unwrap_or(60).min(7 * 24 * 60);
            let mut s = agent.settings();
            s.paused_until_ms = Some(pool_proto::now_ms() + minutes * 60_000);
            Ok(json!(agent.set_settings(s)))
        }
        "resume" => {
            let mut s = agent.settings();
            s.paused_until_ms = None;
            Ok(json!(agent.set_settings(s)))
        }
        "benchmark.now" => {
            let mut s = agent.settings();
            s.benchmark_now = params.get("enabled").and_then(Value::as_bool).unwrap_or(true);
            Ok(json!(agent.set_settings(s)))
        }
        "signin.start" => agent.signin_start().await.map(|s| json!(s)).map_err(e),
        "signin.status" => Ok(json!(agent.signin_state())),
        "signout" => {
            agent.sign_out();
            Ok(json!({}))
        }
        "estimate" => agent.estimate().await.map_err(e),
        "wallets" => agent.wallets().await.map_err(e),
        "earnings" => agent.earnings().await.map_err(e),
        "device" => agent.device_view().await.map_err(e),
        // 2.1.0: the hardware-identifier consent, shown and decided in the app
        "hw_consent.get" => Ok(agent.hw_consent_view()),
        "hw_consent.set" => {
            let accept = params.get("accept").and_then(Value::as_bool).ok_or("accept missing")?;
            let sha = params.get("text_sha256").and_then(Value::as_str).ok_or("text_sha256 missing")?;
            agent.hw_consent_set(accept, sha).await.map_err(e)
        }
        // the user's answer to "is this a reinstall of one of these computers?" (`replaces_device_id` or null)
        "enroll" => {
            let replaces = params.get("replaces_device_id").and_then(Value::as_str).map(str::to_string);
            agent.continue_enrollment(Some(replaces)).await;
            Ok(json!(agent.signin_state()))
        }
        // 2.1.0: device-key-signed DeviceControl, the app's mirror of the web's device actions
        "device.control" => {
            let action = params.get("action").and_then(Value::as_str).ok_or("action missing")?;
            if !pool_proto::objects::DEVICE_CONTROL_ACTIONS.contains(&action) {
                return Err(format!("unknown action {action}"));
            }
            // "Remove this device" is irreversible: the app must pass the typed confirmation through
            if action == "self_revoke" && params.get("confirm").and_then(Value::as_str) != Some("remove") {
                return Err("removing this device needs confirmation".into());
            }
            agent.device_control(action).await.map_err(e)
        }
        "recovery.prove" => {
            let code = params.get("code").and_then(Value::as_str).ok_or("code missing")?;
            agent.recovery_prove(code).await.map_err(e)
        }
        "identity.repair" => agent.rotate_key().await.map_err(e),
        // dev builds in dev mode only (headless e2e): pretend the user is away (`idle_s` large) or back (`0`)
        "dev.simulate" => {
            let idle = params.get("idle_s").and_then(Value::as_u64);
            agent.simulate_idle(idle).map_err(e)?;
            Ok(json!({ "idle_s": idle }))
        }
        "reconnect" => {
            agent.reconnect_now();
            Ok(json!({}))
        }
        _ => Err(format!("unknown method {method}")),
    }
}

async fn serve_conn<S>(agent: Arc<Agent>, token: Arc<String>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    loop {
        // Bounded read; before, a client could make the agent buffer an endless line before the size check
        let Some(line) = read_line_bounded(&mut reader, MAX_REQUEST_BYTES).await else { break };
        let resp = match serde_json::from_str::<Request>(&line) {
            Err(e) => Response { id: 0, ok: false, result: None, error: Some(format!("bad request: {e}")) },
            Ok(req) if !constant_time_eq(req.token.as_bytes(), token.as_bytes()) => {
                Response { id: req.id, ok: false, result: None, error: Some("unauthorized".into()) }
            }
            Ok(req) => match dispatch(&agent, &req.method, req.params).await {
                Ok(v) => Response { id: req.id, ok: true, result: Some(v), error: None },
                Err(err) => Response { id: req.id, ok: false, result: None, error: Some(err) },
            },
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        if w.write_all(&out).await.is_err() {
            break;
        }
    }
}

/// Largest control request line.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

/// One newline-terminated UTF-8 line of at most `max` bytes; `None` at EOF, on an over-long line or invalid UTF-8
/// (the connection is then closed).
pub async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, max: usize) -> Option<String> {
    use tokio::io::AsyncReadExt;
    const NL: u8 = 0x0a;
    let mut buf = Vec::new();
    let n = r.take(max as u64 + 1).read_until(NL, &mut buf).await.ok()?;
    if n == 0 || (buf.last() != Some(&NL) && buf.len() > max) {
        return None;
    }
    if buf.last() == Some(&NL) {
        buf.pop();
    }
    String::from_utf8(buf).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The bound control endpoint. Binding first doubles as the single-instance lock: a second agent fails
/// here (before it starts a session or rewrites the token file) instead of fighting the first one.
pub struct Listener {
    #[cfg(windows)]
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(windows)]
    name: String,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    token: String,
}

#[cfg(windows)]
pub fn bind(data_dir: &std::path::Path) -> anyhow::Result<Listener> {
    bind_named(data_dir, &endpoint_name())
}

#[cfg(windows)]
pub fn bind_named(data_dir: &std::path::Path, name: &str) -> anyhow::Result<Listener> {
    let server = acl::create_pipe(name, true).map_err(|e| anyhow::anyhow!("another Vouch Compute agent is already running ({e})"))?;
    Ok(Listener { server, name: name.to_string(), token: write_token(data_dir)? })
}

/// The control pipe's security descriptor: the current (installing) OS user only.
#[cfg(windows)]
pub mod acl {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `S-1-5-21-...` of the user this agent runs as (the user who installed and started it).
    pub fn current_user_sid() -> anyhow::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            let mut len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
            let _ = CloseHandle(token);
            r?;
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s = PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut s)?;
            let out = s.to_string()?;
            let _ = LocalFree(Some(HLOCAL(s.0.cast())));
            Ok(out)
        }
    }

    /// Protected DACL with one ACE: full access for the current user's SID.
    pub fn pipe_sddl() -> anyhow::Result<String> {
        Ok(format!("D:P(A;;GA;;;{})", current_user_sid()?))
    }

    /// Create a pipe instance with the per-user DACL.
    pub fn create_pipe(name: &str, first: bool) -> anyhow::Result<NamedPipeServer> {
        unsafe {
            let sddl = wide(&pipe_sddl()?);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)?;
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            let r = ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, (&mut sa as *mut SECURITY_ATTRIBUTES).cast());
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            Ok(r?)
        }
    }

    /// The DACL of an open pipe as SDDL (tests and diagnostics).
    pub fn dacl_sddl(handle: std::os::windows::io::RawHandle) -> anyhow::Result<String> {
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let err = GetSecurityInfo(HANDLE(handle), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None, Some(&mut sd));
            if err.0 != 0 {
                anyhow::bail!("GetSecurityInfo failed: {}", err.0);
            }
            let mut s = PWSTR::null();
            let r = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut s, None);
            let _ = LocalFree(Some(HLOCAL(sd.0)));
            r?;
            let out = s.to_string()?;
            let _ = LocalFree(Some(HLOCAL(s.0.cast())));
            Ok(out)
        }
    }
}

#[cfg(unix)]
pub fn bind(data_dir: &std::path::Path) -> anyhow::Result<Listener> {
    use std::os::unix::fs::PermissionsExt;
    // one agent per machine and user: the data dir (token, socket, state) is the user's alone
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    let path = data_dir.join(endpoint_name());
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        anyhow::bail!("another Vouch Compute agent is already running");
    }
    let _ = std::fs::remove_file(&path); // stale socket from a crashed agent
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Listener { listener, token: write_token(data_dir)? })
}

pub async fn serve(agent: Arc<Agent>, l: Listener) -> anyhow::Result<()> {
    let token = Arc::new(l.token);
    #[cfg(windows)]
    {
        let mut server = l.server;
        loop {
            server.connect().await?;
            let conn = server;
            // every instance carries the per-user DACL
            server = acl::create_pipe(&l.name, false)?;
            tokio::spawn(serve_conn(agent.clone(), token.clone(), conn));
        }
    }
    #[cfg(unix)]
    loop {
        let (s, _) = l.listener.accept().await?;
        tokio::spawn(serve_conn(agent.clone(), token.clone(), s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_lines_are_bounded() {
        let mut r = tokio::io::BufReader::new(&b"short\nsecond line\n"[..]);
        assert_eq!(read_line_bounded(&mut r, 64).await.as_deref(), Some("short"));
        assert_eq!(read_line_bounded(&mut r, 64).await.as_deref(), Some("second line"));
        assert_eq!(read_line_bounded(&mut r, 64).await, None);
        // an endless line is cut at the limit instead of being buffered
        let big = vec![b'x'; 10 * MAX_REQUEST_BYTES];
        let mut r = tokio::io::BufReader::new(&big[..]);
        assert_eq!(read_line_bounded(&mut r, MAX_REQUEST_BYTES).await, None);
        let mut exact = vec![b'y'; 64];
        exact.push(0x0a);
        let mut r = tokio::io::BufReader::new(&exact[..]);
        assert_eq!(read_line_bounded(&mut r, 64).await.map(|s| s.len()), Some(64));
        let mut r = tokio::io::BufReader::new(&[0xff, 0xfe, 0x0a][..]);
        assert_eq!(read_line_bounded(&mut r, 64).await, None, "invalid UTF-8");
    }

    /// The control pipe's DACL names the installing user's SID and nobody else (the default pipe DACL also
    /// grants Everyone and Anonymous read access, and admins/SYSTEM full access). A second OS user is therefore
    /// refused by the kernel when opening the pipe (`ERROR_ACCESS_DENIED`); the run with a second local account is
    /// a manual check (it needs an administrator to create the second account). The same user (the app) still connects.
    #[cfg(windows)]
    #[tokio::test]
    async fn control_pipe_is_for_the_installing_user_only() {
        use std::os::windows::io::AsRawHandle;
        let dir = tempfile::tempdir().unwrap();
        let name = format!(r"\\.\pipe\vouch-core-test-{}", std::process::id());
        let l = bind_named(dir.path(), &name).unwrap();
        let sid = acl::current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        let dacl = acl::dacl_sddl(l.server.as_raw_handle()).unwrap();
        assert!(dacl.starts_with("D:P"), "protected, nothing inherited: {dacl}");
        assert_eq!(dacl.matches("(A;").count(), 1, "exactly one allow ACE: {dacl}");
        assert!(dacl.contains(&sid), "{dacl}");
        for other in [";;;WD)", ";;;AN)", ";;;BA)", ";;;SY)", ";;;BU)", ";;;AU)"] {
            assert!(!dacl.contains(other), "{other} in {dacl}");
        }
        // a second instance can only be made with the same DACL; the installing user connects
        assert!(bind_named(dir.path(), &name).is_err(), "one agent per user");
        let client = tokio::net::windows::named_pipe::ClientOptions::new().open(&name);
        assert!(client.is_ok(), "the installing user (the app) can open the pipe");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_socket_and_data_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _l = bind(dir.path()).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join(endpoint_name())), 0o600);
        assert_eq!(mode(dir.path()), 0o700);
        assert_eq!(mode(&dir.path().join("control.token")), 0o600);
    }

    #[tokio::test]
    async fn control_requires_token_and_has_no_wallet_write() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config { prefer_tpm: false, ..Default::default() };
        let agent = Agent::with_platform(dir.path().into(), cfg, Arc::new(crate::platform::Readings::default)).unwrap();
        let token = Arc::new("t0k".to_string());
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_conn(agent.clone(), token, server));
        let (r, mut w) = tokio::io::split(client);
        let mut lines = BufReader::new(r).lines();
        for (req, ok) in [
            (json!({"id":1,"token":"bad","method":"status"}), false),
            (json!({"id":2,"token":"t0k","method":"status"}), true),
            (json!({"id":3,"token":"t0k","method":"wallets.link","params":{"address":"x"}}), false),
            // "Remove this device" needs the typed confirmation, and an unknown action is refused
            (json!({"id":5,"token":"t0k","method":"device.control","params":{"action":"self_revoke"}}), false),
            (json!({"id":6,"token":"t0k","method":"device.control","params":{"action":"delete"}}), false),
            (json!({"id":7,"token":"t0k","method":"hw_consent.get"}), true),
            (json!({"id":4,"token":"t0k","method":"settings.set","params":{"mode":"always_on","temp_cap_c":99}}), true),
        ] {
            let l = format!("{req}\n");
            w.write_all(l.as_bytes()).await.unwrap();
            let resp: Response = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(resp.ok, ok, "{resp:?}");
            if resp.id == 4 {
                assert_eq!(resp.result.unwrap()["temp_cap_c"], 85, "clamped to the allowed range");
            }
        }
    }
}
