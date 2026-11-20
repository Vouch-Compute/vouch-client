//! Device identity.
//!
//! * Windows: a non-exportable ES256 (P-256) key in TPM 2.0 through the Microsoft Platform Crypto
//!   Provider (`tpm.rs`). Verified on a real TPM.
//! * Otherwise (no TPM, Linux without TPM, macOS until the Secure Enclave helper is signed): a software
//!   ES256 key flagged **DEV**, sealed at rest (DPAPI on Windows, 0600 file elsewhere).
//! * A reinstall generates a new key, and so a new enrollment as a new device.
//!
//! Enrollment attestation ([`attestation`]), contract 2.1.0:
//! * Linux + software key: `format: "none"` (no hardware key attestation).
//! * Dev mode (dev build + `dev: true`): the platform format with the server's **dev** blob `{"dev_software_key": true,...}`,
//!   which the server accepts only with `VAULT_DEV_ALLOW_SOFTWARE_ATTESTATION=true` (refused when `VAULT_ENV=prod`).
//! * Otherwise, Windows TPM keys: the `tpm2` **v2** blob ([`attest`]): the enrollment challenge is requested with
//!   `{tpm: {ek_public, aik_public}}`, the TPM activates the server's credential, certifies the device key, and the blob is
//!   checked locally before it is sent. Release builds send the `tpm2` claim or nothing, never the dev blob and never
//!   `none` from Windows or macOS. the server's verifiers fail closed.

pub mod attest;
mod software;
#[cfg(windows)]
pub mod tpm;

use std::path::Path;
use std::sync::Arc;

use pool_proto::cose::Es256Signer;
use serde::{Deserialize, Serialize};

pub use software::SoftwareDeviceKey;
pub(crate) use software::{seal as seal_secret, unseal as unseal_secret};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    /// TPM 2.0 via the Windows Platform Crypto Provider (non-exportable).
    Tpm,
    /// Software key (DEV tier): no hardware key attestation.
    SoftwareDev,
}

pub trait DeviceKey: Es256Signer + Send + Sync {
    fn spki_der(&self) -> Vec<u8>;
    fn storage(&self) -> KeyStorage;
    fn device_key_id(&self) -> String {
        self.kid()
    }
    /// The TPM operations for the `tpm2` v2 attestation; `None` when the key is not in a TPM.
    fn tpm(&self) -> Option<&dyn attest::TpmAttester> {
        None
    }
    /// Wipe the private key for good ("Remove this device", key rotation): the TPM key is deleted, the sealed
    /// software key file (DPAPI blob on Windows) is removed. The key cannot sign afterwards.
    fn destroy(&self) -> anyhow::Result<()>;
    /// The persisted name of a TPM key (kept in `state.json` so a rotated key is found again).
    fn key_name(&self) -> Option<String> {
        None
    }
}

/// The `tpm` body of `POST /v1/devices/enrollment-challenges`: only outside dev mode and only
/// for a TPM key. `Err` (logged) when this TPM cannot give its EK or AIK: the enrollment then sends no blob and the server
/// refuses Windows (no capped tier), as the contract intends.
pub fn tpm_request(key: &dyn DeviceKey, dev: bool) -> Option<anyhow::Result<attest::TpmPublics>> {
    if dev {
        return None;
    }
    key.tpm().map(|t| t.publics())
}

/// What the enrollment challenge gave for the attestation.
pub struct ChallengeForAttestation<'a> {
    pub challenge_id: &'a str,
    pub nonce: &'a [u8; 32],
    pub tpm_activation: Option<&'a attest::TpmActivation>,
}

/// `key_attestation` for `POST /v1/devices`: `(format, blob_base64)`.
pub fn attestation(
    key: &dyn DeviceKey,
    os: &str,
    ch: &ChallengeForAttestation<'_>,
    publics: Option<&attest::TpmPublics>,
    dev: bool,
) -> (&'static str, Option<String>) {
    let storage = key.storage();
    if let ("linux", KeyStorage::SoftwareDev) = (os, storage) {
        return ("none", None);
    }
    let format = if os == "macos" { "apple_se" } else { "tpm2" };
    if dev {
        let storage = match storage {
            KeyStorage::Tpm => "tpm2-platform-crypto-provider",
            KeyStorage::SoftwareDev => "software",
        };
        let blob = serde_json::json!({ "dev_software_key": true, "key_storage": storage }).to_string();
        return (format, Some(pool_proto::keys::b64(blob.as_bytes())));
    }
    let (Some(tpm), Some(publics), Some(act)) = (key.tpm(), publics, ch.tpm_activation) else {
        return (format, None);
    };
    match attest::build_v2(tpm, publics, ch.challenge_id, ch.nonce, act, &key.spki_der()) {
        Ok(a) => (format, Some(pool_proto::keys::b64(&a.to_cbor()))),
        Err(e) => {
            tracing::warn!("no tpm2 v2 key attestation on this machine: {e}");
            (format, None)
        }
    }
}

/// Load the existing device key or create one. `prefer_tpm`: try the platform TPM first. `tpm_key_name`: the
/// persisted TPM key name from `state.json` (after a key rotation), else the default name.
pub fn load_or_create(data_dir: &Path, prefer_tpm: bool, tpm_key_name: Option<&str>) -> anyhow::Result<Arc<dyn DeviceKey>> {
    #[cfg(windows)]
    if prefer_tpm {
        match tpm::TpmDeviceKey::open_or_create(tpm_key_name.unwrap_or(tpm::KEY_NAME)) {
            Ok(k) => return Ok(Arc::new(k)),
            Err(e) => tracing::warn!("TPM key unavailable, using a DEV software key: {e}"),
        }
    }
    let _ = (prefer_tpm, tpm_key_name);
    Ok(Arc::new(SoftwareDeviceKey::load_or_create(&software_key_path(data_dir))?))
}

pub fn software_key_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("device-key.sealed")
}

fn rotating_key_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("device-key.rotating.sealed")
}

/// A fresh key for a key rotation ("Repair device identity"): a new TPM key under a new name, or a new software key
/// at a temporary path (moved into place once the server accepted the rotation).
pub fn create_rotation_key(data_dir: &Path, current: &dyn DeviceKey) -> anyhow::Result<Arc<dyn DeviceKey>> {
    #[cfg(windows)]
    if current.storage() == KeyStorage::Tpm {
        let name = format!("VouchCompute-Device-Key-r{}", pool_proto::now_ms());
        return Ok(Arc::new(tpm::TpmDeviceKey::create_new(&name)?));
    }
    let _ = current;
    let p = rotating_key_path(data_dir);
    let _ = std::fs::remove_file(&p);
    Ok(Arc::new(SoftwareDeviceKey::load_or_create(&p)?))
}

/// Make a rotated software key the device key (a TPM key needs no move: its name goes to `state.json`).
pub fn commit_rotation_key(data_dir: &Path, key: &dyn DeviceKey) -> anyhow::Result<Arc<dyn DeviceKey>> {
    if key.storage() == KeyStorage::SoftwareDev {
        std::fs::rename(rotating_key_path(data_dir), software_key_path(data_dir))?;
        return Ok(Arc::new(SoftwareDeviceKey::load_or_create(&software_key_path(data_dir))?));
    }
    #[cfg(windows)]
    if let Some(name) = key.key_name() {
        return Ok(Arc::new(tpm::TpmDeviceKey::open_or_create(&name)?));
    }
    anyhow::bail!("cannot reopen the rotated key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_policy_matches_vault() {
        let sw = SoftwareDeviceKey::generate();
        let n = [3u8; 32];
        let ch = ChallengeForAttestation { challenge_id: "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e", nonce: &n, tpm_activation: None };
        assert_eq!(attestation(&sw, "linux", &ch, None, true), ("none", None));
        assert_eq!(attestation(&sw, "linux", &ch, None, false), ("none", None));
        let (f, blob) = attestation(&sw, "windows", &ch, None, true);
        assert_eq!(f, "tpm2");
        let doc: serde_json::Value = serde_json::from_slice(&pool_proto::keys::b64_decode(&blob.unwrap()).unwrap()).unwrap();
        assert_eq!(doc["dev_software_key"], true);
        assert_eq!(attestation(&sw, "macos", &ch, None, true).0, "apple_se");
        // Outside dev mode the dev blob is never sent; a software key on Windows/macOS has no attestation
        // (refused), and never `none`
        assert_eq!(attestation(&sw, "windows", &ch, None, false), ("tpm2", None));
        assert_eq!(attestation(&sw, "macos", &ch, None, false), ("apple_se", None));
        // no TPM request in dev mode or for a software key
        assert!(tpm_request(&sw, false).is_none() && tpm_request(&sw, true).is_none());
    }

    #[test]
    fn destroy_removes_the_sealed_software_key() {
        let d = tempfile::tempdir().unwrap();
        let p = software_key_path(d.path());
        let k = SoftwareDeviceKey::load_or_create(&p).unwrap();
        assert!(p.exists());
        k.destroy().unwrap();
        assert!(!p.exists(), "the sealed (DPAPI on Windows) key file is removed");
        assert!(k.sign_es256(b"m").is_err(), "a destroyed key cannot sign");
        // the next load creates a different key
        let k2 = SoftwareDeviceKey::load_or_create(&p).unwrap();
        assert_ne!(k2.kid(), k.kid());
    }
}
