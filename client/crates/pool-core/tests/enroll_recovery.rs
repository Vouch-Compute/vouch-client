//! T-225: an app updated over a sign-in whose enrollment never finished.
//!
//! The 0.1.0 Mac app signed in, the server refused its enrollment (`422 attestation_invalid`, before Macs could
//! enroll), and the consent stayed given. 0.2.0 started over that saved state: signed in, consented, no device id, and
//! a sign-in state of `Idle` in memory. Nothing called enrollment again, while the app showed "Creating this computer's
//! key". These tests start from that saved state and check the agent recovers on its own, says when the saved sign-in
//! is no longer valid, and that "Cancel" and "Start over" are safe at any point.

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;
use pool_core::agent::{SignIn, SignInExpired};
use serde_json::Value as J;

/// Sign in and get refused at enrollment as 0.1.0 was, then rewrite `state.json` with only the fields 0.1.0 knew.
async fn refused_0_1_0_install(dir: &std::path::Path, url: &str, v: &V) {
    *v.refuse.lock().unwrap() = Some((422, "attestation_invalid".into()));
    let agent = new_agent(dir, url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    let SignIn::Blocked { code, .. } = wait_signin(&agent, |s| matches!(s, SignIn::Blocked { .. })).await else { unreachable!() };
    assert_eq!(code, "attestation_invalid");
    assert!(agent.device_id().is_none());
    drop(agent);
    let p = dir.join("state.json");
    let mut st: J = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let o = st.as_object_mut().unwrap();
    o.remove("software_key");
    o.remove("performance");
    o.remove("enroll_stop");
    assert!(o["refresh_token_sealed"].is_string() && o["device_id"].is_null() && o["hw_consent"]["accepted"] == true, "{st}");
    std::fs::write(&p, serde_json::to_vec(&st).unwrap()).unwrap();
    *v.refuse.lock().unwrap() = None;
}

async fn wait_for(agent: &pool_core::agent::Agent, what: &str, done: impl Fn(&SignIn) -> bool) -> SignIn {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = agent.signin_state();
        if done(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "timeout waiting for {what}; state {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The owner's case: the update starts, finds "signed in, not registered", and registers without any click.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_over_a_refused_enrollment_registers_on_start() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;
    let registrations = v.registrations.load(Ordering::SeqCst);

    let agent = new_agent(data.path(), &url);
    // what 0.2.0 showed as "Creating this computer's key" forever: signed in, not enrolled, nothing running
    let snap = agent.snapshot();
    assert_eq!((snap["signed_in"].as_bool(), snap["device_id"].is_null()), (Some(true), true));
    assert_eq!(snap["status"]["connection"], "not_enrolled");
    assert_eq!(agent.signin_state(), SignIn::Idle);

    tokio::spawn(agent.clone().run());
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    assert!(agent.device_id().is_some());
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations + 1, "registered once");
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
}

/// The saved sign-in expired or was revoked: the user is sent back to sign-in, in words, and nothing is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_saved_sign_in_asks_to_sign_in_again() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;
    v.refresh_refused.store(true, Ordering::SeqCst);
    let challenges = v.challenges.load(Ordering::SeqCst);

    let agent = new_agent(data.path(), &url);
    agent.resume_enrollment().await;
    assert_eq!(agent.signin_state(), SignIn::error_code("signin_expired", &SignInExpired.to_string()));
    let snap = agent.snapshot();
    assert_eq!(snap["signed_in"], false, "the unusable token is forgotten");
    assert_eq!(snap["status"]["connection"], "not_signed_in");
    assert_eq!(v.challenges.load(Ordering::SeqCst), challenges, "no enrollment attempt without a valid sign-in");
    let st = agent.state_snapshot();
    assert!(st.hw_consent.is_some_and(|c| c.accepted), "the consent stays");

    // signing in again then registers as usual
    v.refresh_refused.store(false, Ordering::SeqCst);
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    assert!(agent.device_id().is_some());
}

/// "Cancel" mid-way: the attempt stops before registering, and its late result does not overwrite the state. A retry
/// then works, and a slow attempt is superseded by the retry, never run twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_and_retry_mid_enrollment() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;
    let registrations = v.registrations.load(Ordering::SeqCst);
    let agent = new_agent(data.path(), &url);

    v.challenge_delay_ms.store(1500, Ordering::SeqCst);
    let a = agent.clone();
    let first = tokio::spawn(async move { a.continue_enrollment(Some(None)).await });
    wait_for(&agent, "enrolling", |s| matches!(s, SignIn::Enrolling)).await;
    assert_eq!(agent.cancel_enrollment(), SignIn::Idle);
    first.await.unwrap();
    assert_eq!(agent.signin_state(), SignIn::Idle, "the cancelled attempt's result is ignored");
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations, "nothing registered after Cancel");
    assert!(agent.device_id().is_none());

    // a retry while a slow attempt runs: the older one stops, one registration
    let a = agent.clone();
    let slow = tokio::spawn(async move { a.continue_enrollment(Some(None)).await });
    wait_for(&agent, "enrolling", |s| matches!(s, SignIn::Enrolling)).await;
    v.challenge_delay_ms.store(0, Ordering::SeqCst);
    agent.continue_enrollment(Some(None)).await;
    slow.await.unwrap();
    assert_eq!(agent.signin_state(), SignIn::Done);
    assert!(agent.device_id().is_some());
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations + 1, "registered once");
}

/// "Start over": clears the saved sign-in of a computer that is not registered (also mid-enrollment), keeps the consent
/// and the key, and is refused once the computer is registered, which keeps everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_over_clears_only_an_unregistered_sign_in() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;
    let registrations = v.registrations.load(Ordering::SeqCst);
    let agent = new_agent(data.path(), &url);
    let kid = agent.key().device_key_id();

    v.challenge_delay_ms.store(1500, Ordering::SeqCst);
    let a = agent.clone();
    let running = tokio::spawn(async move { a.continue_enrollment(Some(None)).await });
    wait_for(&agent, "enrolling", |s| matches!(s, SignIn::Enrolling)).await;
    agent.reset_signin().await.unwrap();
    running.await.unwrap();
    assert_eq!(agent.signin_state(), SignIn::Idle);
    let snap = agent.snapshot();
    assert_eq!((snap["signed_in"].as_bool(), snap["status"]["connection"].as_str()), (Some(false), Some("not_signed_in")));
    let st = agent.state_snapshot();
    assert!(st.refresh_token_sealed.is_none() && st.device_id.is_none());
    assert!(st.hw_consent.is_some_and(|c| c.accepted), "the consent stays");
    assert_eq!(agent.key().device_key_id(), kid, "the key stays");
    let on_disk = std::fs::read_to_string(data.path().join("state.json")).unwrap();
    assert!(!on_disk.contains("refresh_token_sealed\": \""), "cleared on disk: {on_disk}");
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations);
    // resuming at start does nothing without a sign-in
    agent.resume_enrollment().await;
    assert_eq!(agent.signin_state(), SignIn::Idle);

    // a registered computer: "Start over" is refused and nothing changes
    v.challenge_delay_ms.store(0, Ordering::SeqCst);
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    let before = agent.state_snapshot();
    assert!(agent.reset_signin().await.is_err());
    assert_eq!(agent.state_snapshot(), before);
    assert!(agent.device_id().is_some());
}

/// A cancelled or refused enrollment is remembered: the next start shows it and sends nothing on its own. "Try again"
/// (a new attempt from the app) clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_or_refused_enrollment_is_not_resent_at_start() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;

    // the user cancels mid-way, then the app restarts
    let agent = new_agent(data.path(), &url);
    v.challenge_delay_ms.store(1500, Ordering::SeqCst);
    let a = agent.clone();
    let running = tokio::spawn(async move { a.continue_enrollment(Some(None)).await });
    wait_for(&agent, "enrolling", |s| matches!(s, SignIn::Enrolling)).await;
    agent.cancel_enrollment();
    running.await.unwrap();
    drop(agent);
    v.challenge_delay_ms.store(0, Ordering::SeqCst);
    let challenges = v.challenges.load(Ordering::SeqCst);
    let agent = new_agent(data.path(), &url);
    agent.resume_enrollment().await;
    assert_eq!(agent.signin_state(), SignIn::Idle, "the app offers to register; nothing runs");
    assert_eq!(v.challenges.load(Ordering::SeqCst), challenges);

    // the server refuses (device limit), then the app restarts: the refusal is shown again, no new request
    *v.refuse.lock().unwrap() = Some((409, "device_limit".into()));
    agent.continue_enrollment(Some(None)).await;
    assert!(matches!(agent.signin_state(), SignIn::Blocked { ref code, .. } if code == "device_limit"));
    drop(agent);
    let registrations = v.registrations.load(Ordering::SeqCst);
    let agent = new_agent(data.path(), &url);
    agent.resume_enrollment().await;
    let SignIn::Blocked { code, message } = agent.signin_state() else { panic!("{:?}", agent.signin_state()) };
    assert_eq!(code, "device_limit");
    assert!(message.contains("device limit"), "{message}");
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations, "not sent again on its own");

    // Try again from the app clears it and registers
    *v.refuse.lock().unwrap() = None;
    agent.continue_enrollment(Some(None)).await;
    assert_eq!(agent.signin_state(), SignIn::Done);
    assert!(agent.state_snapshot().enroll_stop.is_none());
}

/// "Start over" while the registration request is already on its way: it waits for the answer, so a computer the server
/// registered is never left half-forgotten; it is then refused because the computer is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_over_waits_for_a_registration_already_sent() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    refused_0_1_0_install(data.path(), &url, &v).await;
    let agent = new_agent(data.path(), &url);
    v.register_delay_ms.store(1500, Ordering::SeqCst);
    let registrations = v.registrations.load(Ordering::SeqCst);
    let a = agent.clone();
    let running = tokio::spawn(async move { a.continue_enrollment(Some(None)).await });
    // wait until the registration request is on its way (the mock counts it after its delay, so poll the challenge)
    let deadline = Instant::now() + Duration::from_secs(10);
    while v.challenges.load(Ordering::SeqCst) == 0 || v.nonce.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(agent.reset_signin().await.is_err(), "registered meanwhile: refused");
    running.await.unwrap();
    assert!(agent.device_id().is_some());
    assert!(agent.state_snapshot().refresh_token_sealed.is_some(), "a registered computer keeps its sign-in");
    assert_eq!(v.registrations.load(Ordering::SeqCst), registrations + 1);
}
