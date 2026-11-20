//! Node protocol 1.2.0 against a mock server the server:
//! * every `AccountNotice` kind becomes the matching banner state, and none of them changes how offers are treated
//!   (after each notice an Offer for an uncached model still gets its normal Decline, so the session is alive);
//! * a `ServerMessage` variant no contract defines yet is ignored (the session survives, sequencing continues);
//! * `Heartbeat` carries the optional telemetry, and a 1.1.0 server reads the same heartbeat with its own types;
//! * notices are reset when a new session starts (the server re-sends what still applies).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as AxMsg, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use pool_core::agent::Agent;
use pool_core::config::Config;
use pool_core::platform::Readings;
use pool_core::status::Notices;
use pool_proto::account_notice as k;
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use prost::Message as _;

#[derive(Default)]
struct Mock {
    keyset: Mutex<Vec<u8>>,
    connections: AtomicUsize,
    result: Mutex<Option<Result<Vec<String>, String>>>,
}

static AGENT: OnceLock<Arc<Agent>> = OnceLock::new();

struct Hub {
    ws: WebSocket,
    seq: u64,
}

impl Hub {
    async fn send(&mut self, body: SB) -> Result<(), String> {
        self.seq += 1;
        let bytes = pb::ServerMessage { seq: self.seq, body: Some(body) }.encode_to_vec();
        self.ws.send(AxMsg::Binary(bytes.into())).await.map_err(|e| e.to_string())
    }
    /// A server message variant that no contract version defines (field 99): a newer server's addition.
    async fn send_future_variant(&mut self) -> Result<(), String> {
        self.seq += 1;
        let mut v = pb::ServerMessage { seq: self.seq, body: None }.encode_to_vec();
        prost::encoding::encode_key(99, prost::encoding::WireType::LengthDelimited, &mut v);
        prost::encoding::encode_varint(2, &mut v);
        v.extend_from_slice(&[0x08, 0x01]);
        self.ws.send(AxMsg::Binary(v.into())).await.map_err(|e| e.to_string())
    }
    async fn recv_raw(&mut self) -> Result<Vec<u8>, String> {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(20), self.ws.recv())
                .await
                .map_err(|_| "timeout waiting for node message".to_string())?
                .ok_or("connection closed")?
                .map_err(|e| e.to_string())?;
            if let AxMsg::Binary(b) = m {
                return Ok(b.to_vec());
            }
        }
    }
    async fn recv(&mut self, want_heartbeat: bool) -> Result<NB, String> {
        loop {
            let raw = self.recv_raw().await?;
            let body = pb::NodeMessage::decode(&raw[..]).map_err(|e| e.to_string())?.body.ok_or("empty body")?;
            if matches!(body, NB::Heartbeat(_)) && !want_heartbeat {
                continue;
            }
            return Ok(body);
        }
    }
}

fn notices() -> Notices {
    AGENT.get().unwrap().status.get().notices
}

async fn script(ws: WebSocket, first: bool) -> Result<Vec<String>, String> {
    let mut h = Hub { ws, seq: 0 };
    let mut log = vec![];
    h.send(SB::Challenge(pb::Challenge { nonce: rand32(), server_time_ms: pool_proto::now_ms() as i64, protocol_version: "pool.node.v1".into() }))
        .await?;
    let NB::Hello(_) = h.recv(false).await? else { return Err("expected Hello".into()) };
    h.send(SB::Welcome(pb::Welcome {
        session_id: uuid::Uuid::new_v4().to_string(),
        session_expires_ms: pool_proto::now_ms() as i64 + 3_600_000,
        heartbeat_interval_s: 1,
        server_time_ms: pool_proto::now_ms() as i64,
    }))
    .await?;
    if !first {
        // a new session starts with no banners: the server re-sends what still applies
        tokio::time::sleep(Duration::from_millis(300)).await;
        if notices() != Notices::default() {
            return Err(format!("notices not reset on a new session: {:?}", notices()));
        }
        h.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 0 })).await?;
        return Ok(vec!["reset_on_reconnect".into()]);
    }
    // heartbeat telemetry, read by a 1.2.0 server and by a 1.1.0 server
    loop {
        let raw = h.recv_raw().await?;
        let m = pb::NodeMessage::decode(&raw[..]).map_err(|e| e.to_string())?;
        if let Some(NB::Heartbeat(hb)) = m.body {
            // the governor needs a tick or two to leave its initial "waiting for idle" state
            if hb.governor_state != Some(pool_proto::governor_state::RUNNING) {
                continue;
            }
            if (hb.temp_c, hb.gpu_util_pct, hb.power_limit_pct, hb.governor_state)
                != (Some(72), Some(93), Some(100), Some(pool_proto::governor_state::RUNNING))
            {
                return Err(format!("telemetry {hb:?}"));
            }
            let old = pool_proto::pb_v110::NodeMessage::decode(&raw[..]).map_err(|e| e.to_string())?;
            let Some(pool_proto::pb_v110::node_message::Body::Heartbeat(o)) = old.body else { return Err("1.1.0 decode".into()) };
            if !(o.accepting_work && o.temp_ok) {
                return Err(format!("1.1.0 view {o:?}"));
            }
            log.push("telemetry_ok".into());
            break;
        }
    }
    // each notice kind -> banner; offers are treated exactly as before
    type Check = fn(&Notices) -> bool;
    let steps: [(i32, Check); 6] = [
        (k::PAUSED_BY_USER, |n| n.paused_by.as_deref() == Some("user")),
        (k::RESUMED, |n| n.paused_by.is_none()),
        (k::PAUSED_BY_TALLY, |n| n.paused_by.as_deref() == Some("tally")),
        (k::RECOVERY_IN_PROGRESS, |n| n.recovery_in_progress),
        (k::REVERIFY_REQUIRED, |n| n.reverify_required),
        (99, |n| n.reverify_required && n.recovery_in_progress), // an unknown kind changes nothing
    ];
    for (kind, check) in steps {
        h.send(SB::AccountNotice(pb::AccountNotice { kind })).await?;
        h.send_future_variant().await?;
        let job_id = uuid::Uuid::new_v4().to_string();
        h.send(SB::Offer(pb::Offer { job_id: job_id.clone(), model_id: "m".into(), model_hash: vec![9; 32], est_units: 1, deadline_ms: pool_proto::now_ms() as i64 + 60_000 }))
            .await?;
        match h.recv(false).await? {
            NB::Decline(d) if d.job_id == job_id && d.reason == pb::DeclineReason::ModelNotCached as i32 => {}
            other => return Err(format!("after notice {kind}: {other:?}")),
        }
        let n = notices();
        if !check(&n) {
            return Err(format!("notice {kind} -> {n:?}"));
        }
        log.push(format!("notice_{kind}_ok"));
    }
    h.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 1 })).await?;
    Ok(log)
}

fn rand32() -> Vec<u8> {
    let mut b = vec![0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b
}

async fn ws_route(ws: WebSocketUpgrade, State(m): State<Arc<Mock>>) -> impl IntoResponse {
    ws.protocols(["pool.node.v1"]).on_upgrade(move |socket| async move {
        let n = m.connections.fetch_add(1, Ordering::SeqCst);
        let r = script(socket, n == 0).await;
        let mut res = m.result.lock().unwrap();
        match (res.take(), r) {
            (None, r) => *res = Some(r),
            (Some(Ok(mut a)), Ok(b)) => {
                a.extend(b);
                *res = Some(Ok(a));
            }
            (Some(Err(e)), _) | (_, Err(e)) => *res = Some(Err(e)),
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_notices_telemetry_and_unknown_variants() {
    let vault = pool_runner::testutil::vault(); // installs dev trust roots
    let m = Arc::new(Mock::default());
    *m.keyset.lock().unwrap() = vault.keyset_bytes(1);
    let app = Router::new()
        .route("/node/v1/connect", get(ws_route))
        .route("/v1/keys", get(|State(m): State<Arc<Mock>>| async move { m.keyset.lock().unwrap().clone() }))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let data = tempfile::tempdir().unwrap();
    let cfg = Config {
        engine_ws_url: format!("ws://{addr}/node/v1/connect"),
        vault_url: format!("http://{addr}"),
        dev: true,
        prefer_tpm: false,
        ..Config::default()
    };
    let platform: Arc<dyn Fn() -> Readings + Send + Sync> = Arc::new(|| Readings {
        idle_s: Some(3600),
        on_ac: Some(true),
        gpu_temp_c: Some(71.6),
        cpu_temp_c: Some(64.0),
        gpu_util_pct: Some(93),
        ..Default::default()
    });
    let agent = Agent::with_platform(data.path().into(), cfg, platform).unwrap();
    AGENT.set(agent.clone()).ok().unwrap();
    agent.set_enrollment(&uuid::Uuid::new_v4().to_string(), "capped");
    let run = tokio::spawn(agent.clone().run());
    let deadline = Instant::now() + Duration::from_secs(60);
    let outcome = loop {
        {
            let r = m.result.lock().unwrap();
            if m.connections.load(Ordering::SeqCst) >= 2 && matches!(&*r, Some(Ok(l)) if l.iter().any(|x| x == "reset_on_reconnect")) {
                break r.clone().unwrap();
            }
            if let Some(Err(e)) = &*r {
                break Err(e.clone());
            }
        }
        if Instant::now() > deadline {
            break Err(format!("timeout; status {:?}", agent.status.get()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    run.abort();
    let log = outcome.unwrap();
    for want in ["telemetry_ok", "notice_1_ok", "notice_2_ok", "notice_3_ok", "notice_4_ok", "notice_5_ok", "notice_99_ok", "reset_on_reconnect"] {
        assert!(log.iter().any(|x| x == want), "missing {want}: {log:?}");
    }
}
