//! Session rules of the job server, confirmed against the real agent and the scripted mock job server:
//!
//! (a) Heartbeats keep flowing (the server closes a session silent for 3 intervals + 10 s) during a long job, during a
//!     benchmark and while the user has paused the device.
//! (b) A `ResultReceipt{REJECTED_MALFORMED}` (the server's answer to a Result more than 300 s after the lease ended) is
//!     final: no retry, no crash, the next job works.
//! (c) A WebSocket close 1013 before the Challenge ("the server busy") backs off exponentially: the attempt counter grows
//!     with each refusal (previously it was reset by every successful upgrade, so the agent reconnected every 1-2 s),
//!     and resets after a real session.
//! (d) A late Accept answered with `ServerError{UNKNOWN_JOB}` + `LeaseRevoked{lease_id: ""}` clears the accepted
//!     offer: the node is not left busy, a stray grant for that job is never fetched, the next offer is accepted.

mod mock_server;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mock_server::{uuid, Hub, Mock};
use pool_core::status::Connection;
use pool_proto::objects::BenchmarkWorkload;
use pool_proto::pb::{self, node_message::Body as NB, server_message::Body as SB};
use pool_proto::{now_ms, sha256};

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

/// Collect node messages for `span`; returns (heartbeats, other messages).
async fn collect(hub: &mut Hub, span: Duration) -> Result<(Vec<pb::Heartbeat>, Vec<NB>), String> {
    let end = Instant::now() + span;
    let (mut hbs, mut other) = (vec![], vec![]);
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match hub.recv_within(true, left).await {
            Ok(NB::Heartbeat(h)) => hbs.push(h),
            Ok(x) => other.push(x),
            Err(e) if e.contains("timeout") => break,
            Err(e) => return Err(e),
        }
    }
    Ok((hbs, other))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_cr_m7e_04() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").with_test_writer().try_init();
    let data = tempfile::tempdir().unwrap();
    let (m, agent) = mock_server::start_cfg(data.path(), |c| c.bench_duration_override_s = Some(8)).await;

    // (c) five busy refusals before the Challenge
    for _ in 0..5 {
        m.scripts.lock().unwrap().push_back(script!(|hub, _m| { hub.close_with(1013).await }));
    }
    // (a), (b), (d) on one session with a 2 s heartbeat interval
    let ag = agent.clone();
    m.scripts.lock().unwrap().push_back(script!(|hub, m| {
        hub.handshake_hb(&m, 2).await?;
        hub.ensure_cached(&m).await?;

        // (d) late Accept -> UNKNOWN_JOB + LeaseRevoked{lease_id: ""}
        let j = uuid();
        hub.send(m.offer(&j)).await?;
        match hub.recv(false).await? {
            NB::Accept(a) if a.job_id == j => {}
            other => return Err(format!("(d) expected Accept, got {other:?}")),
        }
        hub.send(SB::Error(pb::ServerError { code: pb::ErrorCode::UnknownJob as i32, message: "accept after the deadline".into() })).await?;
        hub.send(SB::LeaseRevoked(pb::LeaseRevoked { job_id: j.clone(), lease_id: String::new(), reason: pb::RevokeReason::Cancelled as i32 })).await?;
        // a stray grant for the revoked offer is never acted on
        let stray = uuid();
        let input = br#"{"inputs":["never fetched"]}"#.to_vec();
        m.add_lease(&stray, input.clone(), 0);
        hub.send(m.grant(&m.envelope(&stray, &j, &input))).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        // the node is not busy: the next offer is accepted and completes
        hub.job(&m, br#"{"inputs":["after the late accept"]}"#.to_vec()).await.map_err(|e| format!("(d) next job: {e}"))?;
        if m.leases.lock().unwrap()[&stray].gets != 0 {
            return Err("(d) the revoked offer's grant was fetched".into());
        }

        // (b) REJECTED_MALFORMED receipt: final, no retry, no crash
        hub.job_with_receipt(&m, br#"{"inputs":["late result"]}"#.to_vec(), pb::ReceiptStatus::RejectedMalformed).await?;
        let (_, other) = collect(&mut hub, Duration::from_secs(4)).await?;
        if other.iter().any(|x| matches!(x, NB::Result(_))) {
            return Err(format!("(b) the node re-sent a Result after REJECTED_MALFORMED: {other:?}"));
        }
        hub.job(&m, br#"{"inputs":["still working"]}"#.to_vec()).await.map_err(|e| format!("(b) next job: {e}"))?;

        // (a1) heartbeats during a long job (input download held 7 s)
        let (j, l) = (uuid(), uuid());
        hub.send(m.offer(&j)).await?;
        let NB::Accept(_) = hub.recv(false).await? else { return Err("(a1) expected Accept".into()) };
        let input = br#"{"inputs":["slow job"]}"#.to_vec();
        m.add_lease(&l, input.clone(), 7_000);
        hub.send(m.grant(&m.envelope(&l, &j, &input))).await?;
        let t = Instant::now();
        let mut hbs = 0;
        loop {
            match hub.recv(true).await? {
                NB::Heartbeat(_) => hbs += 1,
                NB::Result(_) => break,
                other => return Err(format!("(a1) unexpected {other:?}")),
            }
        }
        let took = t.elapsed();
        if hbs < 3 {
            return Err(format!("(a1) only {hbs} heartbeats during a {took:?} job (interval 2 s)"));
        }
        eprintln!("(a1) {hbs} heartbeats during a {took:?} job");

        // (a2) heartbeats during a benchmark (dev override: 8 s)
        let bench_input = br#"{"inputs":["benchmark text one","benchmark text two"]}"#.to_vec();
        *m.bench_bundle.lock().unwrap() = bench_input.clone();
        let w = BenchmarkWorkload {
            benchmark_id: uuid(),
            device_id: m.device_id.lock().unwrap().clone(),
            device_key_id: m.device_key_id.lock().unwrap().clone(),
            model_id: m.model_id.lock().unwrap().clone(),
            model_hash: *m.model_hash.lock().unwrap(),
            bundle_sha256: sha256(&bench_input),
            nonce: [9; 32],
            min_duration_s: 1200,
            issued_at: now_ms(),
            expires_at: now_ms() + 600_000,
        };
        let wb = pool_runner::testutil::vault().sign_workload(&w);
        hub.send(SB::BenchmarkOffer(pb::BenchmarkOffer { benchmark_id: w.benchmark_id.clone(), workload: wb, bundle_url: "/bench/bundle".into(), est_duration_s: 1200 })).await?;
        let t = Instant::now();
        let mut hbs = 0;
        let mut accepted = false;
        loop {
            match hub.recv(true).await? {
                NB::Heartbeat(_) => hbs += 1,
                NB::BenchmarkResponse(r) if r.accept => accepted = true,
                NB::BenchmarkResult(_) => break,
                other => return Err(format!("(a2) unexpected {other:?}")),
            }
        }
        if !accepted || hbs < 3 {
            return Err(format!("(a2) accepted={accepted}, {hbs} heartbeats during a {:?} benchmark", t.elapsed()));
        }
        eprintln!("(a2) {hbs} heartbeats during a {:?} benchmark", t.elapsed());

        // (a3) heartbeats while paused by the user (and they say so)
        pool_core::control::dispatch(&ag, "pause", serde_json::json!({"minutes": 5})).await?;
        let (hbs, _) = collect(&mut hub, Duration::from_secs(7)).await?;
        pool_core::control::dispatch(&ag, "resume", serde_json::Value::Null).await?;
        let last = hbs.last().cloned().ok_or("(a3) no heartbeat while paused")?;
        if hbs.len() < 3 || last.accepting_work || last.governor_state != Some(pool_proto::governor_state::USER_PAUSED) {
            return Err(format!("(a3) {} heartbeats while paused, last {last:?}", hbs.len()));
        }
        eprintln!("(a3) {} heartbeats in 7 s while paused", hbs.len());
        hub.send(SB::Goodbye(pb::Goodbye { reason: pb::GoodbyeReason::ServerShutdown as i32, reconnect_after_s: 0 })).await?;
        Ok(())
    }));

    let run = tokio::spawn(agent.clone().run());
    // (c) after each busy close, read the backoff state, then skip the wait
    let mut attempts = vec![];
    for k in 1..=5 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let st = agent.status.get();
            if m.results.lock().unwrap().len() >= k && st.reconnect_in_s.is_some() && st.connection != Connection::Connecting {
                attempts.push(st.reconnect_attempts);
                break;
            }
            assert!(Instant::now() < deadline, "busy close {k} not handled: {st:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        agent.reconnect_now();
    }
    eprintln!("(c) backoff attempts after 1013 closes: {attempts:?}");
    assert_eq!(attempts, vec![1, 2, 3, 4, 5], "the backoff must grow while the hub refuses before the Challenge");

    let r = mock_server::wait_results(&m, 6, Duration::from_secs(180)).await;
    run.abort();
    assert_eq!(r.len(), 6, "session phase did not finish: {:?}", agent.status.get());
    for (i, x) in r.iter().enumerate() {
        assert!(x.is_ok(), "connection {}: {x:?}; problems {:?}", i + 1, m.problems.lock().unwrap());
    }
    assert!(m.problems.lock().unwrap().is_empty(), "{:?}", m.problems.lock().unwrap());
    assert_eq!(agent.status.get().reconnect_attempts, 0, "a real session resets the backoff");
    let _ = m.connections.load(Ordering::SeqCst);
}
