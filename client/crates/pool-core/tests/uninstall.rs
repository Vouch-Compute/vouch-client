//! Uninstall with "delete the application data": the device is removed from the account with a `self_revoke`
//! signed by its existing key before the keys are deleted. Best effort and bounded: nothing to revoke is not an
//! error and creates no key, and a server that never answers is cut off at the limit.

mod common;

use std::time::{Duration, Instant};

use pool_core::config::Config;

fn cfg(vault_url: &str) -> Config {
    Config { vault_url: vault_url.into(), prefer_tpm: false, ..Config::default() }
}

#[tokio::test]
async fn delete_data_revokes_the_device_with_its_own_key_first() {
    let dir = tempfile::tempdir().unwrap();
    let (v, agent) = common::enrolled(dir.path()).await;
    let url = agent.cfg.vault_url.clone();
    let revoked = pool_core::agent::uninstall_self_revoke(dir.path(), &cfg(&url), Duration::from_secs(5)).await.unwrap();
    assert!(revoked, "an enrolled device is revoked");
    // the mock checks the COSE signature against the device's current key, the closed map, ts and the nonce
    let controls = v.controls.lock().unwrap().clone();
    assert_eq!(controls.len(), 1, "exactly one control: {controls:?}");
    assert_eq!(controls[0].0, "self_revoke");
    let problems = v.problems.lock().unwrap().clone();
    assert!(problems.is_empty(), "the server accepted it: {problems:?}");
}

#[tokio::test]
async fn nothing_registered_means_nothing_to_revoke_and_no_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let revoked =
        pool_core::agent::uninstall_self_revoke(dir.path(), &cfg("http://127.0.0.1:9"), Duration::from_secs(5)).await.unwrap();
    assert!(!revoked);
    assert!(!pool_core::identity::software_key_path(dir.path()).exists(), "no key may be created on uninstall");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing written");
}

#[tokio::test]
async fn a_silent_server_is_cut_off_at_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (_v, _agent) = common::enrolled(dir.path()).await;
    // accepts connections and never answers
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let t0 = Instant::now();
    let r = pool_core::agent::uninstall_self_revoke(dir.path(), &cfg(&format!("http://{addr}")), Duration::from_secs(1)).await;
    assert!(r.is_err(), "no answer is an error the uninstaller reports and ignores");
    assert!(t0.elapsed() < Duration::from_secs(4), "bounded by the limit: {:?}", t0.elapsed());
}
