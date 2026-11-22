//! Auto-update with signature verification (Tauri updater, minisign/Ed25519), with **separate channels** for dev and
//! release builds:
//!
//! * **Dev builds** (the default; the agent is built with `dev-trust`): the `dev` channel, verified only with the two
//!   DEV updater keys (`client/dev-keys/updater-*.key`), from the dev endpoint. They show a permanent "DEV BUILD"
//!   marker. A dev build therefore never installs a release (release-signed) update, and cannot be mistaken for one.
//! * **Release builds** (`POOL_RELEASE=1`): the `release` channel, verified only with the release keys given at build
//!   time (`VOUCH_RELEASE_UPDATER_PUBKEYS`, from the offline/KMS keys behind two approvals; `build.rs` refuses to build
//!   without them or with a dev key among them), from the release endpoint (`VOUCH_RELEASE_UPDATE_URL`). A release
//!   build never installs a dev-signed update.
//!
//! Two keys per channel so a key can rotate: the update is verified against key A and, if that fails, key B. The
//! release key signs app binaries and backend packs only, never model files.

use serde_json::{json, Value};
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(app_release), allow(dead_code))]
pub enum Channel {
    Dev,
    Release,
}

/// The dev channel's keys (public halves of `client/dev-keys/updater-1.key` and `updater-2.key`).
pub const DEV_UPDATER_PUBKEYS: [&str; 2] = [
    "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IENERjg1NjMwOTZFRUQzNEMKUldSTTArNldNRmI0emF2azJaTThuYVRGTGlENVk1T2xSREZMYVBUaUFGOVlNRTd1R21BQ3pjamgK",
    "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDA1NUE0MkVGNzdBQzYxNzgKUldSNFlheDM3MEphQlE2YjVGY05qZGI1N2VacEhLRUdoM2k2NDBLWThqQ3MyeHBJL2RSZDlicngK",
];
pub const DEV_UPDATE_ENDPOINT: &str = "http://127.0.0.1:3000/updates/vouchcompute-dev/{{target}}/{{arch}}/{{current_version}}.json";

#[cfg(app_release)]
pub const CHANNEL: Channel = Channel::Release;
#[cfg(not(app_release))]
pub const CHANNEL: Channel = Channel::Dev;

/// The keys this build accepts updates from: its own channel's keys only.
pub fn channel_pubkeys(channel: Channel) -> Vec<String> {
    match channel {
        Channel::Dev => DEV_UPDATER_PUBKEYS.iter().map(|s| s.to_string()).collect(),
        Channel::Release => release_pubkeys(),
    }
}

#[cfg(app_release)]
fn release_pubkeys() -> Vec<String> {
    env!("VOUCH_RELEASE_UPDATER_PUBKEYS").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}
#[cfg(not(app_release))]
fn release_pubkeys() -> Vec<String> {
    vec![] // a dev build carries no release key, so it cannot verify (and install) a release update
}

fn endpoint(channel: Channel) -> String {
    match channel {
        Channel::Dev => DEV_UPDATE_ENDPOINT.to_string(),
        #[cfg(app_release)]
        Channel::Release => env!("VOUCH_RELEASE_UPDATE_URL").to_string(),
        #[cfg(not(app_release))]
        Channel::Release => String::new(),
    }
}

fn updater(app: &AppHandle, key: &str) -> Result<tauri_plugin_updater::Updater, String> {
    let url = endpoint(CHANNEL).parse::<tauri::Url>().map_err(|e| crate::i18n::tv("error.update.endpoint", &[("detail", &e.to_string())]))?;
    let mut b = app
        .updater_builder()
        .pubkey(key)
        .endpoints(vec![url])
        .map_err(|e| e.to_string())?
        // Strictly newer only (explicit, so a changed plugin default or `allowDowngrades` cannot weaken it)
        .version_comparator(|current, release| crate::update_policy::is_newer(&current.to_string(), &release.version.to_string()));
    if CHANNEL == Channel::Dev {
        b = b.header("X-Update-Channel", "dev").map_err(|e| e.to_string())?;
    }
    b.build().map_err(|e| e.to_string())
}

pub fn info() -> Value {
    json!({ "channel": match CHANNEL { Channel::Dev => "dev", Channel::Release => "release" }, "dev_build": CHANNEL == Channel::Dev })
}

/// Downgrade/rollback policy (`update_policy.rs`), applied before anything is downloaded.
fn policy(u: &tauri_plugin_updater::Update) -> Result<(), String> {
    // the policy's own reason stays as written (a security diagnostic); the sentence around it is translated
    crate::update_policy::precheck(&u.signature, &u.version, &u.current_version, crate::update_policy::build_unix_s())
        .map(|_| ())
        .map_err(|e| crate::i18n::tv("error.update.refused", &[("detail", &e)]))
}

pub async fn check(app: &AppHandle) -> Result<Value, String> {
    let keys = channel_pubkeys(CHANNEL);
    let key = keys.first().ok_or_else(|| crate::i18n::t("error.update.noKey"))?;
    match updater(app, key)?.check().await {
        Ok(Some(u)) => {
            policy(&u)?;
            Ok(json!({ "available": true, "version": u.version, "notes": u.body, "channel": info()["channel"] }))
        }
        Ok(None) => Ok(json!({ "available": false, "channel": info()["channel"] })),
        Err(e) => Err(crate::i18n::tv("error.update.checkFailed", &[("detail", &e.to_string())])),
    }
}

/// Download and install, verifying the signature with each of this channel's keys in turn.
pub async fn install(app: &AppHandle) -> Result<(), String> {
    let mut last = crate::i18n::t("error.update.noneAvailable");
    for key in channel_pubkeys(CHANNEL) {
        let Some(update) = updater(app, &key)?.check().await.map_err(|e| e.to_string())? else {
            return Err(last);
        };
        policy(&update)?;
        match update.download_and_install(|_, _| {}, || {}).await {
            Ok(()) => {
                app.restart();
            }
            Err(e) => last = crate::i18n::tv("error.update.rejected", &[("detail", &e.to_string())]),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const PAYLOAD: &[u8] = include_bytes!("../tests/data/payload.bin");
    const DEV_SIG: &str = include_str!("../tests/data/payload.dev.sig");
    const RELEASE_SIG: &str = include_str!("../tests/data/payload.release-test.sig");
    /// Stands in for the real release key (its private half was thrown away after signing the fixture).
    const RELEASE_TEST_PUB: &str = include_str!("../tests/data/release-test.key.pub");

    fn b64text(s: &str) -> String {
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s.trim()).unwrap()).unwrap()
    }

    /// Verification exactly as the Tauri updater does it (base64-wrapped minisign key and signature).
    fn verifies(pubkey_b64: &str, sig_b64: &str) -> bool {
        let pk = minisign_verify::PublicKey::decode(&b64text(pubkey_b64)).unwrap();
        let sig = minisign_verify::Signature::decode(&b64text(sig_b64)).unwrap();
        pk.verify(PAYLOAD, &sig, true).is_ok()
    }

    fn accepted_by(keys: &[String], sig: &str) -> bool {
        keys.iter().any(|k| verifies(k, sig))
    }

    /// A dev build cannot install an update signed with the release key, and a release build cannot install
    /// one signed with a dev key.
    #[test]
    fn dev_and_release_channels_never_accept_each_others_updates() {
        let dev = channel_pubkeys(Channel::Dev);
        let release = vec![RELEASE_TEST_PUB.trim().to_string()];
        assert!(accepted_by(&dev, DEV_SIG), "the dev channel accepts dev-signed updates");
        assert!(!accepted_by(&dev, RELEASE_SIG), "a dev build refuses a release-signed update");
        assert!(accepted_by(&release, RELEASE_SIG), "the release channel accepts release-signed updates");
        assert!(!accepted_by(&release, DEV_SIG), "a release build refuses a dev-signed update");
        assert!(release.iter().all(|r| !dev.contains(r)), "disjoint key sets");
        // and this (dev) build carries no release key at all
        #[cfg(not(app_release))]
        {
            assert_eq!(CHANNEL, Channel::Dev);
            assert!(channel_pubkeys(Channel::Release).is_empty());
            assert!(DEV_UPDATE_ENDPOINT.contains("vouchcompute-dev"), "its own update channel");
        }
    }
}
