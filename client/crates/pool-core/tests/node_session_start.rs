//! T-225 follow-up: a registered Mac stayed offline. The agent rejected the server's KeySet before ever dialling the job
//! server, logged only `Reconnect(None)`, and the app could not say why. Separately, concurrent token refreshes made
//! the account server see a used refresh token come back and revoke the sign-in.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;

use pool_core::status::ConnectProblem;

async fn wait_problem(agent: &pool_core::agent::Agent, want: Option<ConnectProblem>, err: &str) -> pool_core::status::Status {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = agent.status.get();
        if s.connect_problem == want && s.last_error.as_deref().is_some_and(|e| e.contains(err)) {
            return s;
        }
        assert!(Instant::now() < deadline, "timeout waiting for {want:?} / {err}; status {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A KeySet signed by a root this app doesn't have: no session is attempted, and the status says why (the app asks for
/// an update). An unreadable KeySet (a captive portal) or one the server can't serve is not that: no update prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyset_this_app_cannot_verify_is_reported() {
    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    // a well-formed KeySet from a server whose roots this build doesn't trust
    *v.keyset.lock().unwrap() = Some(pool_proto::testkit::FakeVault::new().keyset_bytes(1));
    tokio::spawn(agent.clone().run());
    let s = wait_problem(&agent, Some(ConnectProblem::UntrustedKeys), "signing keys").await;
    assert_ne!(s.connection, pool_core::status::Connection::Connected);

    *v.keyset.lock().unwrap() = Some(b"<html>hotel wi-fi login</html>".to_vec());
    agent.reconnect_now();
    wait_problem(&agent, None, "KeySet was refused").await;

    *v.keyset.lock().unwrap() = None; // 404
    agent.reconnect_now();
    wait_problem(&agent, None, "404").await;
}

/// Many account reads at once when the access token has expired: one refresh, never the same refresh token twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_refresh_once() {
    let data = tempfile::tempdir().unwrap();
    // access tokens that are always stale: every read refreshes, one after the other
    let (v, url) = spawn_vault().await;
    *v.access_ttl_s.lock().unwrap() = Some(0);
    let agent = new_agent(data.path(), &url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, pool_core::agent::SignIn::Done)).await;
    let calls: Vec<_> = (0..8).map(|_| {
        let a = agent.clone();
        tokio::spawn(async move { a.access_token().await })
    }).collect();
    for c in calls {
        c.await.unwrap().expect("no read fails: the refresh token is never reused");
    }
    assert!(!v.revoked.load(Ordering::SeqCst), "the server saw a used refresh token come back");
    let before = v.refreshes.load(Ordering::SeqCst);

    // a token that lives: concurrent reads share one refresh
    *v.access_ttl_s.lock().unwrap() = Some(300);
    agent.access_token().await.unwrap();
    let after_one = v.refreshes.load(Ordering::SeqCst);
    assert_eq!(after_one, before + 1);
    let calls: Vec<_> = (0..8).map(|_| {
        let a = agent.clone();
        tokio::spawn(async move { a.access_token().await })
    }).collect();
    for c in calls {
        c.await.unwrap().unwrap();
    }
    assert_eq!(v.refreshes.load(Ordering::SeqCst), after_one, "cached");
}

/// A registered computer whose sign-in the server refuses: the token is forgotten so the app offers "Sign in", the
/// registration stays, and signing in again keeps the same device (no new registration).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_sign_in_on_a_registered_computer_keeps_the_device() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    *v.access_ttl_s.lock().unwrap() = Some(0);
    let agent = new_agent(data.path(), &url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, pool_core::agent::SignIn::Done)).await;
    let id = agent.device_id().unwrap();
    let registrations = v.registrations.load(Ordering::SeqCst);

    v.refresh_refused.store(true, Ordering::SeqCst);
    let e = agent.access_token().await.unwrap_err();
    assert!(e.downcast_ref::<pool_core::agent::SignInExpired>().is_some(), "{e}");
    let snap = agent.snapshot();
    assert_eq!(snap["signed_in"], false);
    assert_eq!(agent.device_id().as_deref(), Some(id.as_str()), "the registration stays");

    v.refresh_refused.store(false, Ordering::SeqCst);
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, pool_core::agent::SignIn::Done)).await;
    assert_eq!(agent.device_id().as_deref(), Some(id.as_str()));
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations, "no new registration");
    assert_eq!(agent.snapshot()["signed_in"], true);
}
