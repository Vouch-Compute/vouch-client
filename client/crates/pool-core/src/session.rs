//! Job-server session: outbound WebSocket (`pool.node.v1`, TLS 1.3 only),
//! signed-nonce session proof bound to the TLS exporter, strict frame sequencing, offer -> accept ->
//! lease -> fetch -> run -> signed result, benchmarks, pre-emption.
//!
//! Node protocol 1.2.0: optional `Heartbeat` telemetry (self-reported, informational only), `AccountNotice`
//! banners (they never change how offers are treated), and `ServerMessage` variants this node does not know are
//! ignored instead of ending the session.

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use pool_proto::frame::{Inbound, Outbound, MAX_FRAME_BYTES};
use pool_proto::objects::{BenchmarkResult, BenchmarkSegment, HelloClaims, ResultClaims};
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use pool_proto::trust::TrustedKeySet;
// Every timestamp signed or compared with a server deadline here is on the server clock (`clock.rs`)
use crate::clock::server_now_ms as now_ms;
use pool_proto::{cose, sha256, PROTOCOL_VERSION, TLS_EXPORTER_LABEL, WS_SUBPROTOCOL};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::config::Config;
use crate::governor::{Decision, PauseReason, Settings};
use crate::identity::DeviceKey;
use crate::jobs::{JobError, JobTracker, LeaseTicket, NodeIdentity};
use crate::lease::{self, LeaseError, NonceBook};
use crate::platform::Readings;
use crate::registry::Registry;
use crate::runner_client::{Preempt, RunError, RunnerClient};
use crate::status::{BenchProgress, Connection, CurrentJob, MeasuredPerformance, Meter, StatusHub};

pub const HELLO_DEADLINE: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ transport

pub enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Open the WebSocket. `wss://` uses TLS 1.3 only (webpki roots). Plain `ws://` is allowed only for a
/// loopback host in dev builds with dev mode on (the exporter is then 32 zero bytes, which the server accepts
/// only with VAULT_ENV=dev).
///
/// Also returns the edge binding when the job server sits behind Cloudflare: a `wss://` connection to a non-loopback host
/// whose `101` upgrade response carries `CF-Ray` (see [`EdgeBinding`]).
pub async fn connect(cfg: &Config) -> anyhow::Result<(WebSocketStream<Conn>, Option<EdgeBinding>)> {
    let url = url::Url::parse(&cfg.engine_ws_url)?;
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("no host"))?.to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(443);
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    tcp.set_nodelay(true)?;
    let conn = match url.scheme() {
        "wss" => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.clone())?;
            let s = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(name, tcp).await?;
            Conn::Tls(Box::new(s))
        }
        "ws" if cfg.allow_insecure_dev() && is_loopback(&host) => Conn::Plain(tcp),
        other => anyhow::bail!("refusing {other}:// to {host}: TLS 1.3 (wss) required outside dev/loopback"),
    };
    let mut req = cfg.engine_ws_url.as_str().into_client_request()?;
    req.headers_mut().insert("Sec-WebSocket-Protocol", WS_SUBPROTOCOL.parse()?);
    let mut wscfg = WebSocketConfig::default();
    wscfg.max_message_size = Some(MAX_FRAME_BYTES);
    wscfg.max_frame_size = Some(MAX_FRAME_BYTES);
    let (ws, resp) = tokio_tungstenite::client_async_with_config(req, conn, Some(wscfg)).await?;
    let proto = resp.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok());
    if proto != Some(WS_SUBPROTOCOL) {
        anyhow::bail!("server did not select subprotocol {WS_SUBPROTOCOL}");
    }
    let edge = edge_from_upgrade(&host, ws.get_ref().is_tls(), resp.headers().get("CF-Ray").map(|v| v.as_bytes()))?;
    Ok((ws, edge))
}

/// Domain-separation label of the edge binding.
pub const EDGE_BINDING_LABEL: &[u8] = b"pool/edge-binding/v1";

/// The session binding for a job server behind Cloudflare's edge. TLS ends at the edge, so the server cannot see this
/// connection's TLS exporter; both sides instead bind the session to the edge's per-upgrade ray id:
/// `SHA-256("pool/edge-binding/v1" || 0x00 || hub_host || 0x00 || cf_ray)`. `hub_host` is always the host this
/// agent dialled (lower case), never a host named by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeBinding {
    hub_host: String,
    cf_ray: String,
}

impl EdgeBinding {
    pub fn value(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(EDGE_BINDING_LABEL);
        h.update([0u8]);
        h.update(self.hub_host.as_bytes());
        h.update([0u8]);
        h.update(self.cf_ray.as_bytes());
        h.finalize().into()
    }
}

/// Decide the binding from the upgrade response: edge binding only for a TLS connection to a non-loopback host
/// with a `CF-Ray` header; otherwise `None` (the TLS exporter is used). A `CF-Ray` that is not a plain ray id
/// (1-64 characters of `A-Z a-z 0-9 -`) is refused rather than ignored.
pub fn edge_from_upgrade(dialled_host: &str, tls: bool, cf_ray: Option<&[u8]>) -> anyhow::Result<Option<EdgeBinding>> {
    let Some(raw) = cf_ray else { return Ok(None) };
    if !tls || is_loopback(dialled_host) {
        return Ok(None);
    }
    let ok = !raw.is_empty() && raw.len() <= 64 && raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-');
    if !ok {
        anyhow::bail!("malformed CF-Ray header in the upgrade response");
    }
    Ok(Some(EdgeBinding {
        hub_host: dialled_host.to_ascii_lowercase(),
        cf_ray: String::from_utf8_lossy(raw).into_owned(),
    }))
}

/// TLS 1.3 exporter (label `EXPORTER-pool-node-hello`, context = nonce, 32 bytes) from our side of the
/// connection; 32 zero bytes on a dev `ws://` connection.
pub fn tls_exporter(ws: &WebSocketStream<Conn>, nonce: &[u8]) -> anyhow::Result<[u8; 32]> {
    match ws.get_ref() {
        Conn::Tls(s) => {
            let (_, c) = s.get_ref();
            Ok(c.export_keying_material([0u8; 32], TLS_EXPORTER_LABEL, Some(nonce))?)
        }
        Conn::Plain(_) => Ok([0u8; 32]),
    }
}

/// The value signed into `Hello.tls_exporter`: the edge binding when the job server is behind Cloudflare, else this
/// connection's TLS exporter. All zeros (the dev `ws://` value) only where dev transport is allowed.
pub fn session_binding(ws: &WebSocketStream<Conn>, nonce: &[u8], edge: Option<&EdgeBinding>, allow_zero: bool) -> anyhow::Result<[u8; 32]> {
    let v = match edge {
        Some(e) if ws.get_ref().is_tls() => e.value(),
        Some(_) => anyhow::bail!("edge binding on a non-TLS connection"),
        None => tls_exporter(ws, nonce)?,
    };
    if v == [0u8; 32] && !allow_zero {
        anyhow::bail!("all-zero channel binding outside dev");
    }
    Ok(v)
}

// ------------------------------------------------------------------ session

pub struct Deps {
    pub cfg: Config,
    pub key: Arc<dyn DeviceKey>,
    pub me: NodeIdentity,
    pub keyset: TrustedKeySet,
    pub registry: Arc<Registry>,
    pub runner: Arc<RunnerClient>,
    pub http: reqwest::Client,
    pub status: Arc<StatusHub>,
    pub decision_rx: watch::Receiver<Decision>,
    pub settings_rx: watch::Receiver<Settings>,
    /// Changes when the agent ends the session at once (device removed or key rotated).
    pub stop_rx: watch::Receiver<u64>,
    /// Challenge nonces already answered by this agent (a reused nonce is a replay: refuse).
    pub seen_nonces: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub lease_nonces: Arc<NonceBook>,
    pub platform: Arc<dyn Fn() -> Readings + Send + Sync>,
    pub worked_ms: Arc<AtomicU64>,
    /// Where the app's own benchmark measurement goes (the agent keeps it in `state.json`; display only).
    pub perf: Arc<dyn Fn(PerfUpdate) + Send + Sync>,
}

/// The app's own benchmark measurement, for the user to see (never sent to the server).
#[derive(Debug, Clone, PartialEq)]
pub enum PerfUpdate {
    /// A benchmark finished and its signed result was sent.
    Measured(MeasuredPerformance),
    /// The server confirmed it stored the result of this benchmark id.
    Received(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionEnd {
    Reconnect(Option<Duration>),
    DoNotReconnect,
    AuthFailed,
    UpdateRequired,
    Revoked,
    ProtocolError(String),
    /// Ended by the agent (device removed or key rotated): reconnect only with the new identity.
    Stopped,
}

enum Event {
    Send(NB),
    JobDone { job_id: String, body: NB, worked_ms: u64 },
    BenchDone(Option<NB>),
}

type Sink = futures_util::stream::SplitSink<WebSocketStream<Conn>, Message>;

async fn send(sink: &mut Sink, out: &mut Outbound, body: NB) -> anyhow::Result<()> {
    sink.send(Message::Binary(out.encode(body).into())).await?;
    Ok(())
}

fn decline_reason(d: &Decision) -> pb::DeclineReason {
    match d {
        Decision::Run => pb::DeclineReason::Other,
        Decision::Pause(PauseReason::Thermal) => pb::DeclineReason::Thermal,
        Decision::Pause(PauseReason::OnBattery | PauseReason::BatteryLow) => pb::DeclineReason::OnBattery,
        Decision::Pause(_) => pb::DeclineReason::UserActive,
    }
}

fn check_challenge_nonce(deps: &Deps, nonce: &[u8]) -> Result<(), String> {
    if nonce.len() != 32 {
        return Err("challenge nonce must be 32 bytes".into());
    }
    let mut seen = deps.seen_nonces.lock().unwrap();
    if seen.iter().any(|n| n == nonce) {
        return Err("challenge nonce reused (replay)".into());
    }
    seen.push_back(nonce.to_vec());
    while seen.len() > 4096 {
        seen.pop_front();
    }
    Ok(())
}

/// Build and sign the Hello for a Challenge (exposed for tests).
pub fn build_hello(deps: &Deps, nonce: &[u8], exporter: [u8; 32]) -> anyhow::Result<pb::Hello> {
    let claims = HelloClaims {
        device_id: deps.me.device_id.clone(),
        device_key_id: deps.me.device_key_id.clone(),
        nonce: nonce.try_into().map_err(|_| anyhow::anyhow!("nonce size"))?,
        tls_exporter: exporter,
        ts: now_ms(),
    };
    let sig = cose::sign1(&claims.to_value(), deps.key.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(pb::Hello {
        protocol_version: PROTOCOL_VERSION.into(),
        device_id: deps.me.device_id.clone(),
        device_key_id: deps.me.device_key_id.clone(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        os: crate::platform::os_name().into(),
        arch: crate::platform::arch().into(),
        cached_models: deps.registry.cached(),
        hello_sig: sig,
    })
}

async fn next_body<S>(stream: &mut S, inbound: &mut Inbound) -> Result<SB, SessionEnd>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    next_body_seen(stream, inbound, &mut tokio::time::Instant::now()).await
}

/// [`next_body`] that also records when any frame (including Ping/Pong) last arrived, for the silence check.
async fn next_body_seen<S>(stream: &mut S, inbound: &mut Inbound, last_rx: &mut tokio::time::Instant) -> Result<SB, SessionEnd>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let next = stream.next().await;
        *last_rx = tokio::time::Instant::now();
        match next {
            Some(Ok(Message::Binary(b))) => match inbound.decode(&b) {
                Ok((_, Some(body))) => return Ok(body),
                // 1.2.0: a server message this node does not know (a newer protocol's addition) is ignored
                Ok((seq, None)) => {
                    tracing::debug!("ignoring unknown server message (seq {seq})");
                    continue;
                }
                Err(e) => return Err(SessionEnd::ProtocolError(e.to_string())),
            },
            Some(Ok(Message::Text(_))) => return Err(SessionEnd::ProtocolError("text frame".into())),
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
            Some(Ok(Message::Close(_))) | None => return Err(SessionEnd::Reconnect(None)),
            Some(Err(e)) => return Err(SessionEnd::ProtocolError(format!("websocket: {e}"))),
        }
    }
}

fn goodbye_end(g: &pb::Goodbye) -> SessionEnd {
    match pb::GoodbyeReason::try_from(g.reason).unwrap_or(pb::GoodbyeReason::Unspecified) {
        pb::GoodbyeReason::Revoked => SessionEnd::Revoked,
        pb::GoodbyeReason::UpdateRequired => SessionEnd::UpdateRequired,
        _ if g.reconnect_after_s == 0 => SessionEnd::DoNotReconnect,
        _ => SessionEnd::Reconnect(Some(Duration::from_secs(u64::from(g.reconnect_after_s)))),
    }
}

/// Run one authenticated session until it ends.
pub async fn run(deps: Arc<Deps>, mut ws: WebSocketStream<Conn>, edge: Option<EdgeBinding>) -> SessionEnd {
    if !ws.get_ref().is_tls() && !deps.cfg.allow_insecure_dev() {
        return SessionEnd::ProtocolError("insecure transport outside dev".into());
    }
    let mut inbound = Inbound::new();
    let mut out = Outbound::new();

    // ---- Challenge -> Hello: sign nonce + TLS exporter of THIS connection with the device key
    let challenge = match tokio::time::timeout(HELLO_DEADLINE, next_body(&mut ws, &mut inbound)).await {
        Ok(Ok(SB::Challenge(c))) => c,
        Ok(Ok(_)) => return SessionEnd::ProtocolError("expected Challenge".into()),
        Ok(Err(e)) => return e,
        Err(_) => return SessionEnd::ProtocolError("no Challenge".into()),
    };
    if challenge.protocol_version != PROTOCOL_VERSION {
        return SessionEnd::UpdateRequired;
    }
    // Learn the server clock before signing anything (Hello.ts)
    let raw_offset = crate::clock::observe(challenge.server_time_ms);
    deps.status.update(|s| s.clock_offset_s = raw_offset.filter(|o| o.abs() > crate::clock::REPORT_OFFSET_MS).map(|o| o / 1000));
    if let Err(e) = check_challenge_nonce(&deps, &challenge.nonce) {
        return SessionEnd::ProtocolError(e);
    }
    let exporter = match session_binding(&ws, &challenge.nonce, edge.as_ref(), deps.cfg.allow_insecure_dev()) {
        Ok(x) => x,
        Err(e) => return SessionEnd::ProtocolError(format!("exporter: {e}")),
    };
    let hello = match build_hello(&deps, &challenge.nonce, exporter) {
        Ok(h) => h,
        Err(e) => return SessionEnd::ProtocolError(format!("hello: {e}")),
    };
    if ws.send(Message::Binary(out.encode(NB::Hello(hello)).into())).await.is_err() {
        return SessionEnd::Reconnect(None);
    }
    let welcome = loop {
        match tokio::time::timeout(HELLO_DEADLINE, next_body(&mut ws, &mut inbound)).await {
            Ok(Ok(SB::Welcome(w))) => break w,
            Ok(Ok(SB::Error(e))) if e.code == pb::ErrorCode::AuthFailed as i32 => {
                deps.status.update(|s| s.connection = Connection::AuthFailed);
                return SessionEnd::AuthFailed;
            }
            Ok(Ok(SB::Error(_))) => continue,
            Ok(Ok(SB::Goodbye(g))) => return goodbye_end(&g),
            Ok(Ok(_)) => return SessionEnd::ProtocolError("expected Welcome".into()),
            Ok(Err(e)) => return e,
            Err(_) => return SessionEnd::ProtocolError("no Welcome".into()),
        }
    };
    crate::clock::observe(welcome.server_time_ms);
    let (mut sink, mut stream) = ws.split();
    deps.status.update(|s| {
        s.connection = Connection::Connected;
        s.reconnect_attempts = 0;
        s.last_error = None;
        s.reconnect_in_s = None;
        // the server re-sends the account notices that still apply on connect
        s.notices = Default::default();
    });
    tracing::info!("session {} established", welcome.session_id);

    // ---- work loop
    let hb_secs = if welcome.heartbeat_interval_s == 0 { 30 } else { welcome.heartbeat_interval_s };
    let mut hb = tokio::time::interval(Duration::from_secs(u64::from(hb_secs)));
    hb.tick().await;
    // A silently dead connection (NAT timeout, network switch; no FIN) was never noticed: pings went into the
    // socket buffer and nothing checked for a reply. Now any frame from the server (a Pong at least) must arrive within
    // three ping intervals, or the session ends and the agent reconnects.
    let ping_every = Duration::from_secs(u64::from(hb_secs.clamp(1, 20)));
    let silence_limit = ping_every * 3;
    let mut last_rx = tokio::time::Instant::now();
    let mut ping = tokio::time::interval(ping_every);
    ping.tick().await;
    let expires_in = u64::try_from(welcome.session_expires_ms).unwrap_or(0).saturating_sub(now_ms());
    let reauth = tokio::time::sleep(Duration::from_millis(if expires_in > 120_000 { expires_in - 60_000 } else { 12 * 3600 * 1000 }));
    tokio::pin!(reauth);
    let (ev_tx, mut ev_rx) = mpsc::channel::<Event>(64);
    let mut tracker = JobTracker::new();
    let mut current: Option<(String, Preempt)> = None;
    let mut bench: Option<Preempt> = None;
    let mut revoked: HashSet<String> = HashSet::new();
    let mut bench_queue: VecDeque<pb::BenchmarkOffer> = VecDeque::new();
    let mut decision_rx = deps.decision_rx.clone();
    let mut stop_rx = deps.stop_rx.clone();
    stop_rx.mark_unchanged();

    loop {
        let silent_until = last_rx + silence_limit;
        tokio::select! {
            _ = tokio::time::sleep_until(silent_until) => {
                tracing::warn!("no frame from the hub for {silence_limit:?}: connection presumed dead, reconnecting");
                fire_all(&current, &bench);
                return SessionEnd::Reconnect(None);
            }
            body = next_body_seen(&mut stream, &mut inbound, &mut last_rx) => {
                let body = match body { Ok(b) => b, Err(e) => { fire_all(&current, &bench); return e; } };
                match body {
                    SB::Offer(o) => {
                        let job_id = o.job_id.clone();
                        let now = now_ms();
                        if tracker.on_offer(o.clone(), now).is_err() {
                            let _ = send(&mut sink, &mut out, NB::Decline(pb::Decline { job_id, reason: pb::DeclineReason::Other as i32 })).await;
                            continue;
                        }
                        let d = *decision_rx.borrow();
                        let reason = if !d.is_run() {
                            Some(decline_reason(&d))
                        } else if current.is_some() || bench.is_some() {
                            Some(pb::DeclineReason::Busy)
                        } else if deps.registry.get(&o.model_hash).is_none() {
                            Some(pb::DeclineReason::ModelNotCached)
                        } else if u64::try_from(o.deadline_ms).unwrap_or(0) <= now {
                            Some(pb::DeclineReason::Other)
                        } else {
                            None
                        };
                        let msg = match reason {
                            Some(r) => tracker.decline(&job_id, r).map(NB::Decline),
                            None => tracker.accept(&job_id, now_ms()).map(NB::Accept),
                        };
                        if let Ok(m) = msg {
                            if send(&mut sink, &mut out, m).await.is_err() { fire_all(&current, &bench); return SessionEnd::Reconnect(None); }
                        }
                    }
                    SB::LeaseGrant(g) => {
                        let ks = deps.keyset.clone();
                        match tracker.on_lease_grant(&g, &deps.me, now_ms(), |b| ks.verify_lease_envelope(b, now_ms())) {
                            Ok(ticket) => {
                                let p = Preempt::default();
                                current = Some((ticket.job_id.clone(), p.clone()));
                                deps.status.update(|s| s.job = Some(CurrentJob { model_id: ticket.envelope.model_id.clone(), since_ms: now_ms() }));
                                tokio::spawn(run_job(deps.clone(), ticket, p, ev_tx.clone()));
                            }
                            Err(JobError::EnvelopeInvalid { job_id, lease_id, why }) => {
                                tracing::warn!("lease envelope rejected for {job_id}: {why}");
                                let a = pb::Abandon { job_id, lease_id, reason: pb::AbandonReason::EnvelopeInvalid as i32 };
                                let _ = send(&mut sink, &mut out, NB::Abandon(a)).await;
                            }
                            Err(e) => tracing::warn!("ignoring lease grant (no input fetched): {e}"),
                        }
                    }
                    SB::LeaseRevoked(r) => {
                        if tracker.on_revoked(&r) {
                            revoked.insert(r.job_id.clone());
                            if let Some((id, p)) = &current { if *id == r.job_id { p.fire(); } }
                        }
                    }
                    SB::ResultReceipt(r) => tracker.on_receipt(&r),
                    SB::BenchmarkOffer(b) => {
                        // the server issues one onboarding benchmark per eligible model at once. Run them one after the
                        // other: a declined (BUSY) offer is aborted by the server and never re-issued, which left the
                        // device eligible for one model only.
                        if current.is_some() || bench.is_some() {
                            if bench_queue.len() >= 16 {
                                let resp = pb::BenchmarkResponse { benchmark_id: b.benchmark_id.clone(), accept: false, reason: pb::DeclineReason::Busy as i32 };
                                let _ = send(&mut sink, &mut out, NB::BenchmarkResponse(resp)).await;
                            } else {
                                bench_queue.push_back(b);
                            }
                            continue;
                        }
                        // Checked and prepared off the session loop: the model may still be downloading (the server
                        // sends its ModelHint right before an onboarding offer) and the bundle is an HTTP fetch.
                        let p = Preempt::default();
                        bench = Some(p.clone());
                        tokio::spawn(prepare_and_run_bench(deps.clone(), b, p, decision_rx.clone(), ev_tx.clone()));
                    }
                    SB::BenchmarkReceipt(r) => {
                        // only RECEIVED means stored; any other status leaves the benchmark as sent
                        if r.status == pb::ReceiptStatus::Received as i32 {
                            deps.status.update(|s| if let Some(b) = &mut s.benchmark { if b.benchmark_id == r.benchmark_id { b.state = "received".into(); } });
                            (deps.perf)(PerfUpdate::Received(r.benchmark_id.clone()));
                        }
                    }
                    SB::ModelHint(h) => {
                        let d = deps.clone();
                        let tx = ev_tx.clone();
                        tokio::spawn(async move {
                            let base = crate::registry::http_base(&d.cfg.engine_ws_url);
                            match d.registry.ensure(&d.http, &base, &h, &d.keyset).await {
                                Ok(_) => { let _ = tx.send(Event::Send(heartbeat(&d, false))).await; }
                                Err(e) => tracing::warn!("model {} not cached: {e}", h.model_id),
                            }
                        });
                    }
                    // banners only: offers are treated exactly as before (a paused device simply gets none)
                    SB::AccountNotice(n) => {
                        tracing::info!("account notice {}", n.kind);
                        deps.status.update(|s| s.notices.apply(n.kind));
                    }
                    SB::Error(e) => tracing::warn!("server error {}: {}", e.code, e.message),
                    SB::Goodbye(g) => { fire_all(&current, &bench); return goodbye_end(&g); }
                    SB::Challenge(_) | SB::Welcome(_) => { fire_all(&current, &bench); return SessionEnd::ProtocolError("handshake message mid-session".into()); }
                }
            }
            ev = ev_rx.recv() => {
                let start_next = matches!(ev, Some(Event::BenchDone(_)) | Some(Event::JobDone { .. }));
                match ev {
                    Some(Event::Send(b)) => { let _ = send(&mut sink, &mut out, b).await; }
                    Some(Event::JobDone { job_id, body, worked_ms }) => {
                        current = None;
                        deps.worked_ms.fetch_add(worked_ms, Ordering::Relaxed);
                        deps.status.update(|s| s.job = None);
                        if revoked.contains(&job_id) { continue; }
                        match &body {
                            NB::Result(_) => { let _ = tracker.on_result_sent(&job_id); deps.status.update(|s| s.jobs_completed += 1); }
                            _ => { tracker.on_abandon(&job_id); deps.status.update(|s| s.jobs_abandoned += 1); }
                        }
                        if send(&mut sink, &mut out, body).await.is_err() { return SessionEnd::Reconnect(None); }
                    }
                    Some(Event::BenchDone(b)) => {
                        bench = None;
                        if let Some(b) = b { let _ = send(&mut sink, &mut out, b).await; }
                    }
                    None => {}
                }
                if start_next && current.is_none() && bench.is_none() {
                    if let Some(b) = bench_queue.pop_front() {
                        let p = Preempt::default();
                        bench = Some(p.clone());
                        tokio::spawn(prepare_and_run_bench(deps.clone(), b, p, decision_rx.clone(), ev_tx.clone()));
                    }
                }
            }
            _ = hb.tick() => {
                tracker.sweep(now_ms());
                if send(&mut sink, &mut out, heartbeat(&deps, current.is_some())).await.is_err() { fire_all(&current, &bench); return SessionEnd::Reconnect(None); }
            }
            _ = ping.tick() => {
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() { fire_all(&current, &bench); return SessionEnd::Reconnect(None); }
            }
            changed = decision_rx.changed() => {
                if changed.is_err() { fire_all(&current, &bench); return SessionEnd::DoNotReconnect; }
                let d = *decision_rx.borrow();
                if d.preempts() || matches!(d, Decision::Pause(PauseReason::Thermal | PauseReason::OnBattery | PauseReason::BatteryLow)) {
                    fire_all(&current, &bench);
                }
                let _ = send(&mut sink, &mut out, heartbeat(&deps, current.is_some())).await;
            }
            _ = &mut reauth => { fire_all(&current, &bench); return SessionEnd::Reconnect(Some(Duration::from_secs(0))); }
            _ = stop_rx.changed() => {
                fire_all(&current, &bench);
                let _ = sink.send(Message::Close(None)).await;
                return SessionEnd::Stopped;
            }
        }
    }
}

impl Conn {
    pub fn is_tls(&self) -> bool {
        matches!(self, Conn::Tls(_))
    }
}

fn fire_all(current: &Option<(String, Preempt)>, bench: &Option<Preempt>) {
    if let Some((_, p)) = current {
        p.fire();
    }
    if let Some(p) = bench {
        p.fire();
    }
}

/// `Heartbeat.governor_state` (1.2.0) for a governor decision.
pub fn governor_state(d: &Decision) -> i32 {
    use pool_proto::governor_state as g;
    match d {
        Decision::Run => g::RUNNING,
        Decision::Pause(PauseReason::UserActive | PauseReason::Fullscreen) => g::IDLE_WAIT,
        Decision::Pause(PauseReason::Thermal) => g::THERMAL,
        Decision::Pause(PauseReason::OnBattery | PauseReason::BatteryLow) => g::BATTERY,
        Decision::Pause(PauseReason::OutsideSchedule | PauseReason::DailyCapReached) => g::SCHEDULE,
        Decision::Pause(PauseReason::PausedByUser) => g::USER_PAUSED,
    }
}

/// Heartbeat with the 1.2.0 telemetry: self-reported and informational only (the server shows it in the admin fleet view
/// and never uses it for scheduling, pay or verification).
pub fn heartbeat_message(d: Decision, r: &Readings, power_pct: u8, busy: bool, cached: Vec<pb::CachedModel>) -> pb::Heartbeat {
    let temp = [r.gpu_temp_c, r.cpu_temp_c].into_iter().flatten().filter(|t| t.is_finite()).fold(None, |m: Option<f32>, t| Some(m.map_or(t, |m| m.max(t))));
    pb::Heartbeat {
        load: if busy { 1.0 } else { 0.0 },
        temp_ok: d != Decision::Pause(PauseReason::Thermal),
        on_ac: r.on_ac.unwrap_or(true),
        accepting_work: d.is_run(),
        cached_models: cached,
        temp_c: temp.map(|t| t.round().clamp(-50.0, 150.0) as i32),
        gpu_util_pct: r.gpu_util_pct.map(|u| u.min(100)),
        power_limit_pct: Some(u32::from(power_pct.clamp(10, 100))),
        governor_state: Some(governor_state(&d)),
    }
}

fn heartbeat(deps: &Deps, busy: bool) -> NB {
    let d = *deps.decision_rx.borrow();
    let r = (deps.platform)();
    let power = deps.settings_rx.borrow().power_pct;
    NB::Heartbeat(heartbeat_message(d, &r, power, busy, deps.registry.cached()))
}

/// The shape a conforming output for this lease has: content type plus the context the server checks the schema with
/// (security review R2: the published shape and content rules only, never a comparison of the output with other data).
#[derive(Debug, Clone, PartialEq)]
pub struct OutputShape {
    pub content_type: &'static str,
    /// Transcripts: chunk duration in seconds (the server meters `total_samples * 1000 // 16000` ms).
    pub duration_s: Option<f64>,
    /// Embeddings: inputs in the batch.
    pub n_inputs: Option<usize>,
}

pub fn output_shape(env: &pool_proto::objects::LeaseEnvelope, input: &[u8]) -> OutputShape {
    if env.input_format == pool_proto::CANONICAL_AUDIO_FORMAT {
        let duration_s = pool_runner::input::validate_flac_header(input)
            .ok()
            .map(|i| (i.total_samples * 1000 / u64::from(i.sample_rate)) as f64 / 1000.0);
        OutputShape { content_type: pool_proto::TRANSCRIPT_FORMAT, duration_s, n_inputs: None }
    } else {
        let n_inputs = pool_runner::input::parse_embed_batch(input).ok().map(|v| v.len());
        OutputShape { content_type: pool_proto::EMBED_RESULT_FORMAT, duration_s: None, n_inputs }
    }
}

pub fn check_runner_output(shape: &OutputShape, model_id: &str, format: &str, output: &[u8]) -> anyhow::Result<()> {
    if format != shape.content_type {
        anyhow::bail!("runner produced {format}, the lease needs {}", shape.content_type);
    }
    let ctx = pool_proto::outputs::OutputContext { model_id, duration_s: shape.duration_s, n_inputs: shape.n_inputs };
    pool_proto::outputs::check_output(format, output, ctx)?;
    Ok(())
}

async fn run_job(deps: Arc<Deps>, t: LeaseTicket, preempt: Preempt, tx: mpsc::Sender<Event>) {
    let started = now_ms();
    let abandon = |reason: pb::AbandonReason| {
        NB::Abandon(pb::Abandon { job_id: t.job_id.clone(), lease_id: t.lease_id.clone(), reason: reason as i32 })
    };
    let body = async {
        // Input is fetched only here, with a ticket that exists only after Accept + verified envelope.
        let input = match lease::fetch_input(&deps.http, deps.key.as_ref(), &deps.lease_nonces, &t).await {
            Ok(i) => i,
            Err(LeaseError::InputRejected(e)) => {
                tracing::warn!("input rejected: {e}");
                return abandon(pb::AbandonReason::InputRejected);
            }
            Err(e) => {
                tracing::warn!("input fetch failed: {e}");
                return abandon(pb::AbandonReason::Error);
            }
        };
        let Some(model) = deps.registry.get(&t.envelope.model_hash) else {
            return abandon(pb::AbandonReason::Error);
        };
        let input_sha256 = sha256(&input);
        let shape = output_shape(&t.envelope, &input);
        let t_start = now_ms();
        let language = t.envelope.language.as_deref();
        let out = match deps.runner.run(&deps.keyset.raw, &model, &t.envelope.input_format, input, language, preempt.clone()).await {
            Ok(o) => o,
            Err(RunError::Preempted) => return abandon(pb::AbandonReason::Preempted),
            Err(RunError::BundleInvalid(e)) => {
                // the cached copy no longer matches the signed manifest (tampered or corrupted on disk): refuse the
                // job, evict the copy and announce the smaller cache, so it is re-downloaded and re-verified
                tracing::warn!("model bundle refused by the runner: {e}");
                deps.status.update(|s| s.last_error = Some(format!("model bundle refused: {e}")));
                deps.registry.evict(&t.envelope.model_hash);
                let _ = tx.send(Event::Send(heartbeat(&deps, true))).await;
                return abandon(pb::AbandonReason::Error);
            }
            Err(RunError::InputRejected(e)) => {
                tracing::warn!("runner rejected input: {e}");
                return abandon(pb::AbandonReason::InputRejected);
            }
            Err(e) => {
                tracing::warn!("runner failed: {e}");
                deps.status.update(|s| s.last_error = Some(e.to_string()));
                return abandon(pb::AbandonReason::Error);
            }
        };
        deps.status.update(|s| {
            s.sandbox = Some(format!("{:?}", out.sandbox));
            // What really ran the last job (GPU or CPU), shown in the app; diagnostic, never billed
            s.backend = out.backend.clone();
        });
        let t_end = now_ms();
        if preempt.fired() {
            return abandon(pb::AbandonReason::Preempted);
        }
        // Closed output objects (cddl 1.1.0): the server rejects anything else unpaid, so a non-conforming
        // object is abandoned (re-leased elsewhere) instead of being PUT.
        if let Err(e) = check_runner_output(&shape, &t.envelope.model_id, &out.format, &out.output) {
            tracing::warn!("runner output does not conform: {e}");
            deps.status.update(|s| s.last_error = Some(e.to_string()));
            return abandon(pb::AbandonReason::Error);
        }
        let output_sha256 = match lease::put_output(&deps.http, deps.key.as_ref(), &deps.lease_nonces, &t, &out.format, out.output).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("output PUT failed: {e}");
                return abandon(pb::AbandonReason::Error);
            }
        };
        let claims = ResultClaims {
            job_id: t.job_id.clone(),
            lease_id: t.lease_id.clone(),
            model_hash: t.envelope.model_hash,
            input_sha256,
            output_sha256,
            t_start,
            t_end,
            units_device: out.units_device_milli,
        };
        match cose::sign1(&claims.to_value(), deps.key.as_ref()) {
            Ok(sig) => NB::Result(pb::Result { job_id: t.job_id.clone(), lease_id: t.lease_id.clone(), result_sig: sig }),
            Err(_) => abandon(pb::AbandonReason::Error),
        }
    }
    .await;
    // The lease is over for this node (result or abandon): drop its proof nonces
    deps.lease_nonces.forget(&t.lease_id);
    let _ = tx.send(Event::JobDone { job_id: t.job_id.clone(), body, worked_ms: now_ms().saturating_sub(started) }).await;
}

pub struct BenchJob {
    pub offer: pb::BenchmarkOffer,
    pub workload: pool_proto::objects::BenchmarkWorkload,
    pub model: crate::registry::CachedModel,
    pub bundle: Vec<u8>,
    pub duration_s: u64,
}

/// How long an offer for a model that is not cached yet waits for its download (ModelHint) to start and finish.
pub const BENCH_MODEL_WAIT: Duration = Duration::from_secs(120);
/// While the model is still downloading, the offer waits longer (bge-m3 is 2.3 GB), but never past the signed
/// workload's `expires_at`, and never longer than this.
pub const BENCH_DOWNLOAD_WAIT: Duration = Duration::from_secs(3 * 3600);

async fn prepare_and_run_bench(
    deps: Arc<Deps>,
    b: pb::BenchmarkOffer,
    preempt: Preempt,
    decision_rx: watch::Receiver<Decision>,
    tx: mpsc::Sender<Event>,
) {
    match handle_bench_offer(&deps, &b, false, &decision_rx, &preempt).await {
        Ok((resp, Some(job))) if !preempt.fired() => {
            let _ = tx.send(Event::Send(NB::BenchmarkResponse(resp))).await;
            run_bench(deps, job, preempt, tx).await;
        }
        Ok(_) => {
            let d = *decision_rx.borrow();
            let r = if d.is_run() { pb::DeclineReason::Other } else { decline_reason(&d) };
            let resp = pb::BenchmarkResponse { benchmark_id: b.benchmark_id.clone(), accept: false, reason: r as i32 };
            let _ = tx.send(Event::BenchDone(Some(NB::BenchmarkResponse(resp)))).await;
        }
        Err(resp) => {
            let _ = tx.send(Event::BenchDone(Some(NB::BenchmarkResponse(resp)))).await;
        }
    }
}

/// Wait (bounded) for a model that a ModelHint is still downloading; `None` if it never arrives. Without a download
/// in progress the wait is [`BENCH_MODEL_WAIT`]; while one is running, until it ends, the workload expires
/// (`expires_at`, server clock) or [`BENCH_DOWNLOAD_WAIT`] has passed.
async fn wait_for_model(deps: &Deps, model_hash: &[u8], expires_at: u64, preempt: &Preempt) -> Option<crate::registry::CachedModel> {
    let start = tokio::time::Instant::now();
    loop {
        if let Some(m) = deps.registry.get(model_hash) {
            return Some(m);
        }
        let waited = start.elapsed();
        let limit = if deps.registry.is_downloading(model_hash) { BENCH_DOWNLOAD_WAIT } else { BENCH_MODEL_WAIT };
        if preempt.fired() || waited >= limit || now_ms() >= expires_at {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn handle_bench_offer(
    deps: &Arc<Deps>,
    b: &pb::BenchmarkOffer,
    busy: bool,
    decision_rx: &watch::Receiver<Decision>,
    preempt: &Preempt,
) -> Result<(pb::BenchmarkResponse, Option<BenchJob>), pb::BenchmarkResponse> {
    let decline = |r: pb::DeclineReason| pb::BenchmarkResponse { benchmark_id: b.benchmark_id.clone(), accept: false, reason: r as i32 };
    let now = now_ms();
    let w = deps.keyset.verify_benchmark_workload(&b.workload, now).map_err(|_| decline(pb::DeclineReason::Other))?;
    if w.benchmark_id != b.benchmark_id || w.device_id != deps.me.device_id || w.device_key_id != deps.me.device_key_id || w.expires_at <= now {
        return Err(decline(pb::DeclineReason::Other));
    }
    // A dev server may sign workloads under 1200 s (VAULT_DEV_BENCHMARK_MIN_DURATION_S); only dev builds in dev
    // mode accept them. Release builds already refuse them when decoding the workload.
    if w.min_duration_s < pool_proto::objects::MIN_BENCHMARK_DURATION_S && !deps.cfg.allow_insecure_dev() {
        return Err(decline(pb::DeclineReason::Other));
    }
    let d = *decision_rx.borrow();
    let now_requested = deps.settings_rx.borrow().benchmark_now;
    if busy {
        return Err(decline(pb::DeclineReason::Busy));
    }
    if !d.is_run() && !(now_requested && !matches!(d, Decision::Pause(PauseReason::Thermal | PauseReason::OnBattery | PauseReason::BatteryLow))) {
        return Err(decline(decline_reason(&d)));
    }
    let model = wait_for_model(deps, &w.model_hash, w.expires_at, preempt).await.ok_or_else(|| decline(pb::DeclineReason::ModelNotCached))?;
    let url = if b.bundle_url.starts_with('/') { format!("{}{}", crate::registry::http_base(&deps.cfg.engine_ws_url), b.bundle_url) } else { b.bundle_url.clone() };
    // One retry. A declined onboarding benchmark is never re-issued by the server, and the first GET can fail on a
    // pooled keep-alive connection the server has just closed (seen intermittently in a test).
    let fetch = || async { deps.http.get(&url).send().await?.error_for_status()?.bytes().await };
    let bundle = match fetch().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("benchmark bundle fetch failed ({e}); retrying once");
            tokio::time::sleep(Duration::from_millis(500)).await;
            fetch().await.map_err(|e| {
                tracing::warn!("benchmark bundle fetch failed again ({e}); declining");
                decline(pb::DeclineReason::Other)
            })?
        }
    }
    .to_vec();
    if sha256(&bundle) != w.bundle_sha256 || pool_runner::input::validate(&model.manifest.input_format, &bundle).is_err() {
        return Err(decline(pb::DeclineReason::Other));
    }
    let duration_s = match deps.cfg.bench_duration_override_s {
        Some(s) if deps.cfg.allow_insecure_dev() => s,
        _ => w.min_duration_s,
    };
    Ok((
        pb::BenchmarkResponse { benchmark_id: b.benchmark_id.clone(), accept: true, reason: 0 },
        Some(BenchJob { offer: b.clone(), workload: w, model, bundle, duration_s }),
    ))
}

/// Segments in a BenchmarkResult. The server requires exactly 20 contiguous segments spanning the signed duration
/// and assigns each the same units.
pub const BENCHMARK_SEGMENTS: u64 = 20;

/// Run the server's signed sustained benchmark: run the bundle input back to back for the signed duration, then sign
/// BenchmarkResult. The window starts when the first run has finished (so every segment has an output to name)
/// and is reported as [`BENCHMARK_SEGMENTS`] contiguous equal time slices of `duration_s / 20`; each slice
/// carries the hash of the last run that finished by its end and the device units of the runs that finished in
/// it. The device is busy with the workload for the whole window. Never self-reports performance as truth: the server
/// assigns the units and derives the rate from the signed timing.
async fn run_bench(deps: Arc<Deps>, job: BenchJob, preempt: Preempt, tx: mpsc::Sender<Event>) {
    let id = job.offer.benchmark_id.clone();
    let model_id = job.model.manifest.model_id.clone();
    let unit = crate::status::unit_for(&job.model.manifest.input_format);
    deps.status.update(|s| {
        s.benchmark = Some(BenchProgress {
            benchmark_id: id.clone(),
            state: "running".into(),
            started_ms: now_ms(),
            duration_s: job.duration_s,
            segments: 0,
            model_id: model_id.clone(),
            measured: None,
        })
    });
    // The app's own view of the rate (display only): units the runtime reported for the runs that finished inside
    // the measured window, over the time from the window start to the end of the last of them.
    // Pauses for the power slider are left out, so the number is this computer's speed while it works.
    let mut meter = Meter::default();
    let mut last_end = 0u64;
    let mut slept_ms = 0u64;
    let mut slept_at_end = 0u64;
    let mut backend: Option<String> = None;
    let slice_ms = (job.duration_s * 1000).div_ceil(BENCHMARK_SEGMENTS).max(1);
    let mut t_start = 0u64;
    let mut segments: Vec<BenchmarkSegment> = Vec::new();
    let mut last_output = [0u8; 32];
    let mut seg_units: Option<u64> = None;
    let result = loop {
        if preempt.fired() {
            break None;
        }
        let s0 = now_ms();
        match deps.runner.run(&deps.keyset.raw, &job.model, &job.model.manifest.input_format, job.bundle.clone(), None, preempt.clone()).await {
            Ok(o) => {
                let now = now_ms();
                if t_start == 0 {
                    t_start = now; // warm-up run done: the measured window starts here
                } else {
                    // slices that ended before this run finished name the previous output
                    while (segments.len() as u64) < BENCHMARK_SEGMENTS && now >= t_start + slice_ms * (segments.len() as u64 + 1) {
                        let k = segments.len() as u64;
                        segments.push(BenchmarkSegment {
                            seq: k,
                            t_start: t_start + slice_ms * k,
                            t_end: t_start + slice_ms * (k + 1),
                            output_sha256: last_output,
                            units_device: seg_units.take(),
                        });
                    }
                    if let Some(u) = o.units_device_milli {
                        seg_units = Some(seg_units.unwrap_or(0) + u);
                    }
                    meter.add(o.units_device_milli);
                    last_end = now;
                    slept_at_end = slept_ms;
                }
                if o.backend.is_some() {
                    backend = o.backend.clone();
                }
                last_output = sha256(&o.output);
                let n = segments.len() as u64;
                let measured = meter.measured(unit, last_end.saturating_sub(t_start).saturating_sub(slept_at_end), backend.clone());
                deps.status.update(|s| {
                    if let Some(b) = &mut s.benchmark {
                        b.segments = n;
                        if measured.is_some() {
                            b.measured = measured.clone();
                        }
                    }
                    if backend.is_some() {
                        s.backend = backend.clone();
                    }
                });
                if n >= BENCHMARK_SEGMENTS {
                    break Some(());
                }
                // power slider: duty cycle between runs
                let pct = u64::from(deps.settings_rx.borrow().power_pct.clamp(10, 100));
                if pct < 100 {
                    let busy = now_ms() - s0;
                    let pause = busy * (100 - pct) / pct;
                    let p0 = now_ms();
                    tokio::time::sleep(Duration::from_millis(pause)).await;
                    if t_start != 0 {
                        // the time really slept (timers overshoot), so the shown speed is not understated
                        slept_ms += now_ms().saturating_sub(p0);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("benchmark run failed: {e}");
                break None;
            }
        }
    };
    let body = match result {
        Some(()) => {
            let r = BenchmarkResult {
                benchmark_id: id.clone(),
                device_key_id: deps.me.device_key_id.clone(),
                nonce: job.workload.nonce,
                workload_sha256: sha256(&job.offer.workload),
                t_start,
                t_end: now_ms().max(t_start + slice_ms * BENCHMARK_SEGMENTS),
                segments,
                hw_claims: crate::platform::hw_claims(),
            };
            cose::sign1(&r.to_value(), deps.key.as_ref())
                .ok()
                .map(|sig| NB::BenchmarkResult(pb::BenchmarkResult { benchmark_id: id.clone(), result_sig: sig }))
        }
        None => None,
    };
    let state = if body.is_some() { "sent" } else { "stopped" };
    if body.is_some() {
        if let Some(m) = meter.measured(unit, last_end.saturating_sub(t_start).saturating_sub(slept_at_end), backend.clone()) {
            (deps.perf)(PerfUpdate::Measured(MeasuredPerformance { model_id, benchmark_id: id.clone(), measured: m, finished_ms: now_ms(), received: false }));
        }
    }
    // A stopped benchmark is reported as a BenchmarkResponse{accept: false}
    // after the earlier accept; USER_ACTIVE when the user came back (pre-emption), OTHER on a runner failure.
    let body = body.or_else(|| {
        let reason = if preempt.fired() { pb::DeclineReason::UserActive } else { pb::DeclineReason::Other };
        Some(NB::BenchmarkResponse(pb::BenchmarkResponse { benchmark_id: id.clone(), accept: false, reason: reason as i32 }))
    });
    deps.status.update(|s| if let Some(b) = &mut s.benchmark { b.state = state.into() });
    let _ = tx.send(Event::BenchDone(body)).await;
}

#[cfg(test)]
mod edge_binding_tests {
    use super::*;

    const RAY: &[u8] = b"8e3b2c1d4f5a6b7c-AMS";

    /// Known answer (Python: hashlib.sha256(b"pool/edge-binding/v1\x00api.vouchcompute.com\x00" + ray)), shared
    /// with the job server and the account server.
    #[test]
    fn value_matches_the_published_construction() {
        let e = edge_from_upgrade("api.vouchcompute.com", true, Some(RAY)).unwrap().unwrap();
        assert_eq!(hex::encode(e.value()), "931cb866de58f7080352c0693e2cd0640f0a7b2e889300c476cacdd48a665270");
    }

    #[test]
    fn only_the_dialled_host_lower_case_is_bound() {
        let upper = edge_from_upgrade("API.VouchCompute.com", true, Some(RAY)).unwrap().unwrap();
        let lower = edge_from_upgrade("api.vouchcompute.com", true, Some(RAY)).unwrap().unwrap();
        assert_eq!(upper.value(), lower.value());
        let other = edge_from_upgrade("api.vouchcompute.com.evil.example", true, Some(RAY)).unwrap().unwrap();
        assert_ne!(other.value(), lower.value());
        let other_ray = edge_from_upgrade("api.vouchcompute.com", true, Some(b"8e3b2c1d4f5a6b7d-AMS")).unwrap().unwrap();
        assert_ne!(other_ray.value(), lower.value());
    }

    #[test]
    fn no_edge_binding_without_cf_ray_for_loopback_or_without_tls() {
        assert_eq!(edge_from_upgrade("api.vouchcompute.com", true, None).unwrap(), None);
        assert_eq!(edge_from_upgrade("127.0.0.1", true, Some(RAY)).unwrap(), None);
        assert_eq!(edge_from_upgrade("localhost", true, Some(RAY)).unwrap(), None);
        assert_eq!(edge_from_upgrade("::1", true, Some(RAY)).unwrap(), None);
        assert_eq!(edge_from_upgrade("api.vouchcompute.com", false, Some(RAY)).unwrap(), None);
    }

    #[test]
    fn malformed_cf_ray_is_refused() {
        let long = vec![b'a'; 65];
        for bad in [&b""[..], b"8e3b 2c1d", b"8e3b\x002c1d", b"ray\r\nx", "räy".as_bytes(), &long] {
            assert!(edge_from_upgrade("api.vouchcompute.com", true, Some(bad)).is_err(), "{bad:?}");
        }
        assert!(edge_from_upgrade("api.vouchcompute.com", true, Some(&[b'a'; 64])).is_ok());
    }

    #[test]
    fn the_binding_is_never_all_zero() {
        let e = edge_from_upgrade("api.vouchcompute.com", true, Some(RAY)).unwrap().unwrap();
        assert_ne!(e.value(), [0u8; 32]);
    }
}
