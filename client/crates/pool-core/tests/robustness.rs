//! Robustness: the real agent (real sandboxed runner) against the scripted mock job server, one connection per phase.
//!
//! 1. **Clock skew.** The contributor's clock is 90 s ahead of the server. Previously the Hello timestamp was 90 s
//!    off (the server refuses > 60 s), every offer looked expired (declined), and t_start/t_end fell outside the server's 5 s
//!    window (unpaid). Now the agent signs on the server clock: the session, the job and the server's time checks pass,
//!    and the app shows the offset.
//! 2. **Network loss mid-job.** The server drops the TCP connection while the job's input download is in flight: the
//!    job is abandoned (no output upload, no Result), the agent reconnects with backoff and works again.
//! 3. **Silent dead connection.** The server stops reading (no Pong, no frames) without closing: the agent notices
//!    within three ping intervals and reconnects (previously it stayed "Connected" until the OS TCP timeout).
//! 4. **Server version skew.** A server speaking another protocol version gets no Hello; the agent shows "update
//!    required" and does not hammer the server; a manual reconnect recovers once the server is compatible again.
//! 5. **Consent.** The agent never got the hardware-identifier consent: no frame or upload it sent contains any of
//!    this machine's MAC addresses (bytes or text) or its SMBIOS UUID, board/disk serials or install id.
//! 6. **Disk-write audit.** Every job input carries a random sentinel. With TRACE logging to a file in the data dir,
//!    no file in the data dir, the temp dirs or the runner's container folder ever contains a sentinel.

mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use mock_server::{uuid, Hub, Mock};
use pool_core::status::Connection;
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};

macro_rules! script {
    (|$hub:ident, $m:ident| $body:block) => {
        Box::new(move |mut $hub: Hub, $m: Arc<Mock>| -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> {
            Box::pin(async move {
                let _ = &mut $hub;
                $body
            })
        }) as mock_server::Script
    };
}

fn sentinel() -> String {
    format!("SENTINEL-{}", uuid().replace('-', ""))
}

fn input_with(s: &str) -> Vec<u8> {
    format!(r#"{{"inputs":["customer text {s} must never touch the disk","second {s}"]}}"#).into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clock_skew_network_loss_silence_version_skew_and_disk_audit() {
    let started = SystemTime::now();
    let data = tempfile::tempdir().unwrap();
    // TRACE logs into the data dir, like the agent's own logs/core.log
    let log = std::fs::File::create(data.path().join("trace.log")).unwrap();
    let _ = tracing_subscriber::fmt().with_env_filter("trace").with_writer(Arc::new(log)).with_ansi(false).try_init();
    let (m, agent) = mock_server::start(data.path()).await;
    let sentinels: Vec<String> = (0..4).map(|_| sentinel()).collect();
    let lost_lease = Arc::new(std::sync::Mutex::new(String::new()));

    // ---- connection 1: the local clock is 90 s ahead of the server; then the network drops mid-job
    m.skew_ms.store(-90_000, Ordering::SeqCst);
    let (s0, s1, ll) = (sentinels[0].clone(), sentinels[1].clone(), lost_lease.clone());
    m.scripts.lock().unwrap().push_back(script!(|hub, m| {
        hub.handshake(&m).await?;
        hub.ensure_cached(&m).await?;
        hub.job(&m, input_with(&s0)).await?;
        // job 2: the input download takes 4 s; the TCP connection drops 0.5 s into it
        let (j, l) = (uuid(), uuid());
        *ll.lock().unwrap() = l.clone();
        hub.send(m.offer(&j)).await?;
        match hub.recv(false).await? {
            NB::Accept(a) if a.job_id == j => {}
            other => return Err(format!("expected Accept(j2), got {other:?}")),
        }
        let input = input_with(&s1);
        m.add_lease(&l, input.clone(), 4_000);
        hub.send(m.grant(&m.envelope(&l, &j, &input))).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(hub); // abrupt: no Goodbye
        Ok(())
    }));

    // ---- connection 2: clock fixed; one job; then the server goes silent without closing
    let s2 = sentinels[2].clone();
    let silence_started = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let ss = silence_started.clone();
    m.scripts.lock().unwrap().push_back(script!(|hub, m| {
        m.skew_ms.store(0, Ordering::SeqCst);
        hub.handshake_hb(&m, 2).await?; // ping every 2 s -> silence limit 6 s
        hub.job(&m, input_with(&s2)).await?;
        *ss.lock().unwrap() = Some(Instant::now());
        // stop reading: no Pong, no frames; hold the socket open
        tokio::time::sleep(Duration::from_secs(20)).await;
        drop(hub);
        Ok(())
    }));

    // ---- connection 3: a server that speaks another protocol version
    let silence_detected = Arc::new(std::sync::Mutex::new(None::<Duration>));
    let sd = silence_detected.clone();
    let ss2 = silence_started.clone();
    m.scripts.lock().unwrap().push_back(script!(|hub, m| {
        *sd.lock().unwrap() = ss2.lock().unwrap().map(|t| t.elapsed());
        let nonce: Vec<u8> = (0..32).map(|_| mock_server::rand_byte()).collect();
        hub.send(SB::Challenge(pb::Challenge { nonce, server_time_ms: m.now() as i64, protocol_version: "pool.node.v2".into() })).await?;
        match hub.recv_within(true, Duration::from_secs(3)).await {
            Ok(NB::Hello(_)) => Err("the agent answered a v2 Challenge with a v1 Hello".into()),
            _ => Ok(()),
        }
    }));

    let run = tokio::spawn(agent.clone().run());
    let r = mock_server::wait_results(&m, 3, Duration::from_secs(180)).await;
    assert_eq!(r.len(), 3, "phases 1-3 did not finish: {r:?}; problems {:?}; status {:?}", m.problems.lock().unwrap(), agent.status.get());
    for (i, x) in r.iter().enumerate() {
        assert!(x.is_ok(), "phase {}: {x:?}; problems {:?}", i + 1, m.problems.lock().unwrap());
    }

    // 1. the offset was learned and shown (about -90 s)
    // (connection 2 reset it to ~0; the status keeps the last reported value only when > 5 s)
    // 2. the lost job was abandoned: never uploaded
    let lost = lost_lease.lock().unwrap().clone();
    assert_eq!(m.leases.lock().unwrap()[&lost].puts, 0, "output uploaded for a job whose session was lost");
    // 3. silence detected within the limit (6 s) plus reconnect backoff
    let took = silence_detected.lock().unwrap().expect("silence phase did not run");
    eprintln!("silent connection replaced after {took:?}");
    assert!(took < Duration::from_secs(15), "dead connection noticed only after {took:?}");
    // 4. version skew: update required, and no reconnect storm
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(agent.status.get().connection, Connection::UpdateRequired);
    let conns = m.connections.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(m.connections.load(Ordering::SeqCst), conns, "the agent kept reconnecting to an incompatible hub");

    // ---- connection 4: compatible again after a manual reconnect (the update path); clock 30 s behind
    let s3 = sentinels[3].clone();
    m.scripts.lock().unwrap().push_back(script!(|hub, m| {
        m.skew_ms.store(30_000, Ordering::SeqCst);
        hub.handshake(&m).await?;
        hub.job(&m, input_with(&s3)).await?;
        hub.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 0 })).await?;
        Ok(())
    }));
    agent.reconnect_now();
    let r = mock_server::wait_results(&m, 4, Duration::from_secs(60)).await;
    assert_eq!(r.len(), 4, "phase 4 did not run: {:?}", agent.status.get());
    assert!(r[3].is_ok(), "phase 4: {:?}", r[3]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let st = agent.status.get();
    assert_eq!(st.clock_offset_s.map(|s| (25..=35).contains(&s)), Some(true), "clock offset shown: {:?}", st.clock_offset_s);
    assert!(m.problems.lock().unwrap().is_empty(), "{:?}", m.problems.lock().unwrap());
    run.abort();

    // 5. consent: this agent never accepted the hardware-identifier consent, so no frame or upload carries any of
    //    this machine's MAC addresses (raw bytes or text), or its SMBIOS UUID / serials
    let hw = pool_core::hwids::collect();
    let mut needles: Vec<Vec<u8>> = vec![];
    for n in &hw.nics {
        for mac in [n.mac, n.permanent_mac].into_iter().flatten() {
            if mac == [0; 6] {
                continue;
            }
            needles.push(mac.to_vec());
            let hexs: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
            needles.push(hexs.join(":").into_bytes());
            needles.push(hexs.join("-").into_bytes());
            needles.push(hexs.join(":").to_uppercase().into_bytes());
            needles.push(hexs.join("-").to_uppercase().into_bytes());
        }
    }
    for id in [&hw.smbios_uuid, &hw.board_serial, &hw.disk_serial, &hw.os_install_id].into_iter().flatten() {
        if id.len() >= 6 {
            needles.push(id.as_bytes().to_vec());
        }
    }
    let frames = mock_server::RAW.lock().unwrap().clone();
    let bodies = m.raw.lock().unwrap().clone();
    eprintln!("consent audit: {} identifiers checked in {} frames and {} uploads", needles.len(), frames.len(), bodies.len());
    assert!(!frames.is_empty());
    for blob in frames.iter().chain(&bodies) {
        for n in &needles {
            assert!(!blob.windows(n.len()).any(|w| w == n.as_slice()), "a hardware identifier left the device without consent");
        }
    }
    assert_ne!(agent.hw_consent_view()["decision"], serde_json::json!("accepted"), "the test agent must not have consent");

    // 6. disk-write audit
    let mut roots = vec![data.path().to_path_buf(), std::env::temp_dir()];
    if let Ok(la) = std::env::var("LOCALAPPDATA") {
        roots.push(std::path::PathBuf::from(la).join("Packages").join("vouchcompute.runner.v1"));
    }
    if cfg!(unix) {
        roots.push("/tmp".into());
        roots.push("/var/tmp".into());
    }
    let trace = std::fs::read_to_string(data.path().join("trace.log")).unwrap_or_default();
    assert!(trace.len() > 10_000, "TRACE logging was captured ({} bytes)", trace.len());
    for s in &sentinels {
        let hits = mock_server::files_containing(&roots, started, s.as_bytes());
        assert!(hits.is_empty(), "customer input {s} found on disk: {hits:?}");
    }
}
