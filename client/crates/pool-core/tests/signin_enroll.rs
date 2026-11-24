//! Sign-in (RFC 8628 device grant), enrollment and the 2.1.0 device flows against a mock server that checks what
//! the server 2.1.0 checks:
//! * `nonce_sig`: COSE_Sign1 by the new key over the closed `EnrollClaims` map;
//! * `hw_ids`: COSE `HwIdentifiers` by the new key, closed map, masked MACs; `hw_consent` = the in-app text's hash;
//!   nothing before the consent;
//! * `DeviceControl`: exact deterministic closed map by the device's current key, `ts` within ±60 s, single-use
//!   nonce (a replay is refused);
//! * `RecoveryProof`, vouched key rotation, "Replace existing device", `409 hardware_in_use`;
//! * weekly hardware reports that survive a restart.
//!
//! Also checks the app's token is never asked for wallet scopes.

mod common;

use std::sync::atomic::Ordering;

use common::*;
use pool_core::agent::SignIn;
use pool_proto::{keys, now_ms};
use serde_json::{json, Value as J};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_grant_then_enrollment() {
    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    assert!(v.polls.load(Ordering::SeqCst) >= 2, "polled through authorization_pending");
    let problems = v.problems.lock().unwrap().clone();
    assert!(problems.is_empty(), "{problems:?}");
    let scope = v.scope.lock().unwrap().clone();
    assert!(!scope.contains("wallet") && !scope.contains("payout"), "no wallet scope requested: {scope}");
    // Device-link fields, self-asserted, within the openapi limits
    let form = v.device_form.lock().unwrap().clone();
    assert_eq!(form.get("os").map(String::as_str), Some(pool_core::platform::os_name()));
    assert_eq!(form.get("arch").map(String::as_str), Some(pool_core::platform::arch()));
    assert_eq!(form.get("agent_version").map(String::as_str), Some(env!("CARGO_PKG_VERSION")));
    let name = form.get("device_name").expect("device_name sent");
    assert!(!name.is_empty() && name.chars().count() <= 64, "{name}");
    assert!(form.contains_key("client_id"));
    // dev mode: the server's dev attestation blob, never in a release build
    let reg = v.registered.lock().unwrap().clone().unwrap();
    if pool_core::platform::os_name() != "linux" {
        let blob = keys::b64_decode(reg["key_attestation"]["blob"].as_str().unwrap()).unwrap();
        let doc: J = serde_json::from_slice(&blob).unwrap();
        assert_eq!(doc["dev_software_key"], true);
    }
    assert!(reg.get("replaces_device_id").is_none());
    // refresh token is stored sealed, never in plain text
    let state = std::fs::read_to_string(data.path().join("state.json")).unwrap();
    assert!(!state.contains("rt-1"), "refresh token must be sealed at rest");
    assert!(state.contains("refresh_token_sealed"));
    assert!(agent.state_snapshot().hw_report_last_sent_ms.is_some(), "enrollment counts as the first report");
}

/// T-213 / CR-T213-01, the Mac path (and Linux, and Windows without a usable TPM): a release-mode agent with a software
/// key links against vault's T-213 rules: `key_attestation {format: "none", blob: null}`, signed `hw_ids` with at
/// least two medium identifiers, and the server's answer (`trust_ceiling: capped`, Probation) is kept. The software-key
/// choice is saved only after the server accepted the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn software_key_link_follows_the_t213_contract() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    v.t213.store(true, Ordering::SeqCst);
    let agent = release_mode_agent(data.path(), &url);
    assert!(!agent.cfg.allow_insecure_dev(), "release behaviour: no dev attestation blob");
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    let problems = v.problems.lock().unwrap().clone();
    assert!(problems.is_empty(), "{problems:?}");
    let reg = v.registered.lock().unwrap().clone().unwrap();
    assert_eq!(reg["key_attestation"], json!({"format": "none", "blob": null}));
    assert_eq!(reg["os"], pool_core::platform::os_name());
    assert_eq!(reg["hw_claims"]["key_storage"], "software-dev");
    let st = agent.state_snapshot();
    assert_eq!(st.trust_ceiling.as_deref(), Some("capped"));
    assert!(st.software_key, "the enrolled software key is the one loaded from now on");
    assert!(agent.device_id().is_some());
    // the app shows the capped note from the snapshot (trust ceiling and key storage)
    let snap = agent.snapshot();
    assert_eq!((snap["trust_ceiling"].as_str(), snap["key_storage"].as_str()), (Some("capped"), Some("software_dev")));
}

/// T-213: too few hardware identifiers for a software key: vault answers `422 hw_ids_required`, and the app says so in
/// plain words instead of a generic failure; nothing is saved as enrolled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_few_hardware_identifiers_are_explained() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    v.t213.store(true, Ordering::SeqCst);
    let agent = release_mode_agent(data.path(), &url);
    let base = fixture_collector();
    agent.set_hw_collector(std::sync::Arc::new(move || {
        let mut raw = base();
        raw.board_serial = None;
        raw.gpu_uuids.clear();
        raw
    }));
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    let SignIn::Blocked { code, message } = wait_signin(&agent, |s| matches!(s, SignIn::Blocked { .. })).await else { unreachable!() };
    assert_eq!(code, "hw_ids_required");
    assert_eq!(message, "This computer did not report enough hardware details to register.");
    assert!(agent.device_id().is_none());
    assert!(!agent.state_snapshot().software_key, "nothing saved before the server accepted the key");
}

/// No consent, no identifiers and no enrollment; refusing shows the honest message; accepting continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusing_the_hardware_consent_blocks_enrollment() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    let agent = new_agent(data.path(), &url);
    agent.signin_start().await.unwrap();
    wait_signin(&agent, |s| matches!(s, SignIn::ConsentRequired)).await;
    assert_eq!(v.registrations.load(Ordering::SeqCst), 0, "nothing registered before consent");
    consent(&agent, false).await;
    let SignIn::Blocked { message, .. } = agent.signin_state() else { panic!("{:?}", agent.signin_state()) };
    assert_eq!(message, pool_core::hwids::REFUSED_MESSAGE);
    assert!(agent.enroll(None).await.is_err(), "enroll() itself refuses without consent");
    assert_eq!((v.registrations.load(Ordering::SeqCst), v.hw_reports.load(Ordering::SeqCst)), (0, 0), "no identifiers sent");
    // a stale text hash is refused (the app must show the current text)
    assert!(agent.hw_consent_set(true, &"0".repeat(64)).await.is_err());
    consent(&agent, true).await;
    wait_signin(&agent, |s| matches!(s, SignIn::Done)).await;
    assert_eq!(v.registrations.load(Ordering::SeqCst), 1);
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
}

/// A second OS user (or account) on a machine already enrolled elsewhere gets the fix, in plain words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hardware_in_use_says_how_to_fix_it() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    *v.refuse.lock().unwrap() = Some((409, "hardware_in_use".into()));
    let agent = new_agent(data.path(), &url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    let s = wait_signin(&agent, |s| matches!(s, SignIn::Blocked { .. })).await;
    let SignIn::Blocked { code, message } = s else { unreachable!() };
    assert_eq!(code, "hardware_in_use");
    assert!(message.contains("already registered to another Vouch Compute account") && message.contains("Remove it from that account first"), "{message}");
    assert!(agent.device_id().is_none());
}

/// "Replace existing device": the account has a Windows/Linux/macOS device like this one; the user picks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_existing_device() {
    let data = tempfile::tempdir().unwrap();
    let (v, url) = spawn_vault().await;
    let old = "1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e";
    *v.listed.lock().unwrap() = vec![
        json!({"device_id": old, "name": "Gaming PC", "os": pool_core::platform::os_name(), "status": "active", "last_seen_day": "2026-11-01"}),
        json!({"device_id": "2b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e", "name": "Old", "os": pool_core::platform::os_name(), "status": "revoked"}),
        json!({"device_id": "3b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e", "name": "Phone", "os": "android", "status": "active"}),
    ];
    let agent = new_agent(data.path(), &url);
    consent(&agent, true).await;
    agent.signin_start().await.unwrap();
    let SignIn::ChooseReplace { candidates } = wait_signin(&agent, |s| matches!(s, SignIn::ChooseReplace { .. })).await else { unreachable!() };
    assert_eq!(candidates.len(), 1, "same OS, not revoked: {candidates:?}");
    assert_eq!((candidates[0].device_id.as_str(), candidates[0].name.as_str()), (old, "Gaming PC"));
    assert_eq!(v.registrations.load(Ordering::SeqCst), 0, "waits for the user's answer");
    agent.continue_enrollment(Some(Some(old.into()))).await;
    assert_eq!(agent.signin_state(), SignIn::Done);
    assert_eq!(v.registered.lock().unwrap().as_ref().unwrap()["replaces_device_id"], old);
}

/// Pause / resume / self-revoke are exact device-key-signed DeviceControl maps; a replayed control is refused
/// by the server; self-revoke wipes the device key (the sealed software key file; the TPM key in the TPM test) and the
/// device-link token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_control_and_self_revoke_wipe() {
    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    let old_kid = agent.key().device_key_id();
    agent.device_control("pause").await.unwrap();
    agent.device_control("resume").await.unwrap();
    let (actions, first_raw): (Vec<String>, Vec<u8>) = {
        let c = v.controls.lock().unwrap();
        (c.iter().map(|x| x.0.clone()).collect(), c[0].1.clone())
    };
    assert_eq!(actions, ["pause", "resume"]);
    // replay of a used control (same nonce): refused by the server
    let id = agent.device_id().unwrap();
    let url = format!("{}/v1/devices/{id}/control", agent.cfg.vault_url);
    let r = reqwest::Client::new().post(&url).json(&json!({"control": keys::b64(&first_raw)})).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 409, "replayed nonce refused");
    // every control carries a fresh nonce
    let (_, a) = agent.device_control_cose("pause").unwrap();
    let (_, b) = agent.device_control_cose("pause").unwrap();
    assert_ne!(a, b);
    // "Remove this device": the server revokes, the app wipes the key and the token
    let key_file = pool_core::identity::software_key_path(data.path());
    assert!(key_file.exists());
    agent.device_control("self_revoke").await.unwrap();
    assert!(!key_file.exists() || agent.key().device_key_id() != old_kid, "old sealed key removed");
    assert_ne!(agent.key().device_key_id(), old_kid, "a fresh key for any later enrollment");
    assert!(agent.device_id().is_none());
    let st = agent.state_snapshot();
    assert!(st.refresh_token_sealed.is_none() && st.device_id.is_none() && st.device_key_id.is_none());
    let state = std::fs::read_to_string(data.path().join("state.json")).unwrap();
    assert!(!state.contains("refresh_token_sealed\": \""), "token wiped on disk: {state}");
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
}

/// The weekly report runs on the persisted schedule, so it survives restarts, and never without consent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn weekly_hw_report_survives_restart_and_needs_consent() {
    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    assert!(!agent.hw_report_tick().await.unwrap(), "just enrolled: not due");
    let url = agent.cfg.vault_url.clone();
    drop(agent);
    // eight days pass while the computer is off
    let p = data.path().join("state.json");
    let mut st: J = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    st["hw_report_last_sent_ms"] = json!(now_ms() - 8 * 24 * 3600 * 1000);
    std::fs::write(&p, serde_json::to_vec(&st).unwrap()).unwrap();
    let agent = new_agent(data.path(), &url);
    assert!(agent.hw_report_tick().await.unwrap(), "due after the restart");
    assert_eq!(v.hw_reports.load(Ordering::SeqCst), 1);
    assert!(!agent.hw_report_tick().await.unwrap(), "and not again this week");
    // withdrawn consent: no report even when due
    consent(&agent, false).await;
    let mut st: J = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    st["hw_report_last_sent_ms"] = json!(now_ms() - 8 * 24 * 3600 * 1000);
    std::fs::write(&p, serde_json::to_vec(&st).unwrap()).unwrap();
    let agent = new_agent(data.path(), &url);
    assert!(!agent.hw_report_tick().await.unwrap());
    assert_eq!(v.hw_reports.load(Ordering::SeqCst), 1);
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
}

/// "Recover my account" (`RecoveryProof`) and "Repair device identity" (vouched key rotation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_proof_and_key_rotation() {
    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    let case = "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e";
    let ch = [0x33u8; 32];
    agent.recovery_prove(&format!("{case}.{}", keys::b64url(&ch))).await.unwrap();
    assert_eq!(v.recovery.lock().unwrap().clone().unwrap(), json!({"case_id": case, "challenge": hex::encode(ch)}));
    assert!(agent.recovery_prove("garbage").await.is_err());
    // re-key: both keys sign, the server switches, the app uses the new key from now on
    let old = agent.key().device_key_id();
    let r = agent.rotate_key().await.unwrap();
    let new = agent.key().device_key_id();
    assert_ne!(old, new);
    assert_eq!(r["device_key_id"], new);
    assert_eq!(agent.state_snapshot().device_key_id.as_deref(), Some(new.as_str()));
    assert!(agent.device_id().is_some(), "same device, new key");
    assert_eq!(v.rotations.load(Ordering::SeqCst), 1);
    // the rotated key persists across a restart and still controls the device
    let url = agent.cfg.vault_url.clone();
    drop(agent);
    let agent = new_agent(data.path(), &url);
    assert_eq!(agent.key().device_key_id(), new);
    agent.device_control("pause").await.unwrap();
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
}
