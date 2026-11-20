//! Key encodings: SubjectPublicKeyInfo DER, `device_key_id`, and a software ES256 key.

use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

use crate::{cose::Es256Signer, Error};

pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}
pub fn b64_decode(s: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| Error::Malformed("bad base64"))
}

/// SPKI DER of a P-256 public key.
pub fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    key.to_public_key_der().expect("P-256 SPKI encoding").as_bytes().to_vec()
}

/// Parse SPKI DER; only P-256 is accepted.
pub fn parse_spki(der: &[u8]) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_public_key_der(der).map_err(|_| Error::Malformed("not a P-256 SPKI key"))
}

/// Build a VerifyingKey from an uncompressed SEC1 point (0x04 || X || Y).
pub fn from_sec1(point: &[u8]) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::Malformed("bad SEC1 point"))
}

/// `device_key_id = "dk_" + base64url-nopad(SHA-256(SPKI DER))`.
pub fn device_key_id(key: &VerifyingKey) -> String {
    format!("dk_{}", b64url(&crate::sha256(&spki_der(key))))
}

/// Software ES256 key. Used for the DEV identity tier (no TPM / platform key available), for tests and
/// for the test doubles of the server keys. A device using it enrolls with `key_attestation.format = "none"`,
/// which has no hardware key attestation.
#[derive(Clone)]
pub struct SoftwareKey {
    key: SigningKey,
    kid: String,
}

impl SoftwareKey {
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::random(&mut rand_core::OsRng))
    }
    pub fn from_signing_key(key: SigningKey) -> Self {
        let kid = device_key_id(key.verifying_key());
        Self { key, kid }
    }
    /// Use an explicit kid (server keys use `vk_<purpose>_<yyyymm>_<n>`).
    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = kid.to_string();
        self
    }
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        SigningKey::from_pkcs8_der(der)
            .map(Self::from_signing_key)
            .map_err(|_| Error::Malformed("bad PKCS#8 key"))
    }
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        self.key.to_pkcs8_der().expect("PKCS#8 encoding").as_bytes().to_vec()
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }
    pub fn spki_der(&self) -> Vec<u8> {
        spki_der(self.key.verifying_key())
    }
}

impl Es256Signer for SoftwareKey {
    fn kid(&self) -> String {
        self.kid.clone()
    }
    fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64], Error> {
        let sig: Signature = self.key.sign(msg);
        Ok(sig.to_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_id_shape() {
        let k = SoftwareKey::generate();
        let id = device_key_id(&k.verifying_key());
        assert!(id.starts_with("dk_"));
        assert_eq!(id.len(), 3 + 43);
        assert!(id[3..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn spki_and_pkcs8_roundtrip() {
        let k = SoftwareKey::generate();
        let vk = parse_spki(&k.spki_der()).unwrap();
        assert_eq!(vk, k.verifying_key());
        let k2 = SoftwareKey::from_pkcs8_der(&k.to_pkcs8_der()).unwrap();
        assert_eq!(k2.verifying_key(), k.verifying_key());
        assert!(parse_spki(b"garbage").is_err());
    }
}
