//! Trust distribution: KeySet verification against the two embedded root keys, rollback protection,
//! and lookup of the server keys by purpose (`dispatch`, `registry`, `benchmark`,...).
//!
//! Model bundles are trusted only through a ModelManifest signed by a `registry` key from a
//! root-signed KeySet. The app-release (updater) key is never accepted for model files.

use p256::ecdsa::VerifyingKey;

use crate::cose::{parse_sign1, Sign1};
use crate::objects::{BenchmarkWorkload, KeySet, LeaseEnvelope, ModelManifest};
use crate::{keys, object_types as t, Error};

/// Placeholder KeySet root public keys (SPKI DER, base64), DEV ONLY. They are replaced with the
/// two offline root keys from the server's key ceremony before any production build.
/// Dev keys; the private halves are in `client/dev-keys/` (gitignored), for the server's dev KeySet.
pub const EMBEDDED_ROOTS_B64: [&str; 2] = [
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJk1NUIMkiup7aDynS0iO3CSglPObQk0K3CvTohrHl7QNvSb41o39OW2/tW5BQpBiWzEgv2EHpR5oNdsC49pUzw==",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq9cjKKkk6peDs8Z6UoGLfk4UZ7dc7ImIVJysxraGLLDlmzgngb5b2h30rhT4YxLgFmGQSQg7TibNQTEwCRGTcA==",
];

/// Environment variable that overrides the roots (comma-separated base64 SPKI). Exists (and is honoured) only in
/// builds with the `dev-trust` feature, which release builds cannot enable (release guard in `lib.rs`); the release
/// CI job checks that packaged binaries do not even contain this name.
#[cfg(feature = "dev-trust")]
pub const DEV_ROOTS_ENV: &str = "POOL_DEV_TRUST_ROOTS";

/// The KeySet roots that count as **dev** roots: the placeholder roots whose private halves
/// are in `client/dev-keys/` (the server's dev KeySet), plus any root supplied through [`DEV_ROOTS_ENV`]. Only dev-trust
/// builds have a dev root at all; the production roots (which replace [`EMBEDDED_ROOTS_B64`]) never count.
#[cfg(feature = "dev-trust")]
pub const DEV_PLACEHOLDER_ROOTS_B64: [&str; 2] = [
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJk1NUIMkiup7aDynS0iO3CSglPObQk0K3CvTohrHl7QNvSb41o39OW2/tW5BQpBiWzEgv2EHpR5oNdsC49pUzw==",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq9cjKKkk6peDs8Z6UoGLfk4UZ7dc7ImIVJysxraGLLDlmzgngb5b2h30rhT4YxLgFmGQSQg7TibNQTEwCRGTcA==",
];

#[cfg(feature = "dev-trust")]
fn env_roots() -> Option<Result<Vec<VerifyingKey>, Error>> {
    let v = std::env::var(DEV_ROOTS_ENV).ok()?;
    if v.trim().is_empty() {
        return None;
    }
    Some(v.split(',').map(|s| keys::parse_spki(&keys::b64_decode(s)?)).collect())
}

pub fn trust_roots() -> Result<Vec<VerifyingKey>, Error> {
    #[cfg(feature = "dev-trust")]
    if let Some(r) = env_roots() {
        return r;
    }
    EMBEDDED_ROOTS_B64.iter().map(|s| keys::parse_spki(&keys::b64_decode(s)?)).collect()
}

/// Is `root` a dev KeySet root (see [`DEV_PLACEHOLDER_ROOTS_B64`])? Always `false` in release builds.
pub fn is_dev_root(root: &VerifyingKey) -> bool {
    #[cfg(feature = "dev-trust")]
    {
        let placeholder = DEV_PLACEHOLDER_ROOTS_B64.iter().filter_map(|s| keys::parse_spki(&keys::b64_decode(s).ok()?).ok());
        let from_env = env_roots().and_then(Result::ok).unwrap_or_default();
        placeholder.chain(from_env).any(|k| &k == root)
    }
    #[cfg(not(feature = "dev-trust"))]
    {
        let _ = root;
        false
    }
}

/// A KeySet that verified against a root.
#[derive(Debug, Clone)]
pub struct TrustedKeySet {
    pub keyset: KeySet,
    /// The exact COSE bytes (forwarded unchanged to the runner, which re-verifies them).
    pub raw: Vec<u8>,
    /// The root whose signature verified this KeySet.
    pub root: VerifyingKey,
}

/// Verify a KeySet against the roots and reject rollback below `min_version` (the highest version seen).
pub fn verify_keyset(bytes: &[u8], roots: &[VerifyingKey], min_version: u64) -> Result<TrustedKeySet, Error> {
    let s = parse_sign1(bytes, t::KEY_SET)?;
    let root = *roots.iter().find(|k| s.verify(k).is_ok()).ok_or(Error::BadSignature)?;
    let keyset = KeySet::from_value(&s.claims)?;
    if keyset.version < min_version {
        return Err(Error::Rollback);
    }
    Ok(TrustedKeySet { keyset, raw: bytes.to_vec(), root })
}

impl TrustedKeySet {
    /// The KeySet was verified under a dev root: only then may a dev build run the dev reference
    /// backend for a bundle that says `dev_reference`. Always `false` in release builds.
    pub fn signed_by_dev_root(&self) -> bool {
        is_dev_root(&self.root)
    }

    /// The key with `kid` and `purpose`, valid at `now_ms`.
    pub fn key(&self, kid: &str, purpose: &str, now_ms: u64) -> Result<VerifyingKey, Error> {
        let k = self
            .keyset
            .keys
            .iter()
            .find(|k| k.kid == kid && k.purpose == purpose)
            .ok_or(Error::UnknownKey)?;
        if k.alg != -7 {
            return Err(Error::UnknownKey);
        }
        if now_ms < k.not_before || now_ms > k.not_after {
            return Err(Error::Expired);
        }
        keys::parse_spki(&k.public_key)
    }

    fn verify_obj(&self, bytes: &[u8], ty: &str, purpose: &str, now_ms: u64) -> Result<Sign1, Error> {
        let s = parse_sign1(bytes, ty)?;
        let key = self.key(&s.kid, purpose, now_ms)?;
        s.verify(&key)?;
        Ok(s)
    }

    /// ModelManifest signed by the single bundle root: a `registry` key.
    /// Returns the manifest and its `model_hash` (SHA-256 of the signed payload).
    pub fn verify_manifest(&self, bytes: &[u8], now_ms: u64) -> Result<(ModelManifest, [u8; 32]), Error> {
        let s = self.verify_obj(bytes, t::MODEL_MANIFEST, "registry", now_ms)?;
        Ok((ModelManifest::from_value(&s.claims)?, s.payload_sha256()))
    }

    /// LeaseEnvelope signed by a server `dispatch` key.
    pub fn verify_lease_envelope(&self, bytes: &[u8], now_ms: u64) -> Result<LeaseEnvelope, Error> {
        let s = self.verify_obj(bytes, t::LEASE_ENVELOPE, "dispatch", now_ms)?;
        LeaseEnvelope::from_value(&s.claims)
    }

    /// BenchmarkWorkload signed by a server `benchmark` key.
    pub fn verify_benchmark_workload(&self, bytes: &[u8], now_ms: u64) -> Result<BenchmarkWorkload, Error> {
        let s = self.verify_obj(bytes, t::BENCHMARK_WORKLOAD, "benchmark", now_ms)?;
        BenchmarkWorkload::from_value(&s.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::fixtures::manifest;
    use crate::testkit::FakeVault;

    #[test]
    fn embedded_roots_parse() {
        assert_eq!(EMBEDDED_ROOTS_B64.len(), 2);
        for r in EMBEDDED_ROOTS_B64 {
            keys::parse_spki(&keys::b64_decode(r).unwrap()).unwrap();
        }
    }

    #[test]
    fn keyset_verifies_with_either_root_and_rejects_rollback() {
        let v = FakeVault::new();
        let ks = v.keyset_bytes(5);
        let t = verify_keyset(&ks, &v.roots(), 0).unwrap();
        assert_eq!(t.keyset.version, 5);
        assert!(matches!(verify_keyset(&ks, &v.roots(), 6), Err(Error::Rollback)));
        // signed by the second root
        let ks2 = v.keyset_bytes_with_root(7, 1);
        assert_eq!(verify_keyset(&ks2, &v.roots(), 5).unwrap().keyset.version, 7);
        // not signed by a root
        let other = FakeVault::new();
        assert!(verify_keyset(&other.keyset_bytes(9), &v.roots(), 0).is_err());
    }

    #[test]
    fn dev_root_is_recognised_only_for_dev_roots() {
        let v = FakeVault::new();
        let t = verify_keyset(&v.keyset_bytes(1), &v.roots(), 0).unwrap();
        assert!(t.root == v.roots()[0]);
        // a root that is neither a placeholder dev root nor in POOL_DEV_TRUST_ROOTS (e.g. a production root)
        let other = FakeVault::new();
        let t2 = verify_keyset(&other.keyset_bytes(1), &other.roots(), 0).unwrap();
        #[cfg(feature = "dev-trust")]
        {
            // the placeholder roots are dev roots in a dev build
            let ph = keys::parse_spki(&keys::b64_decode(DEV_PLACEHOLDER_ROOTS_B64[0]).unwrap()).unwrap();
            assert!(is_dev_root(&ph));
            // `other`'s roots are fresh random keys: never placeholders, and no test here exports them
            assert!(!t2.signed_by_dev_root(), "a root outside the dev set is not a dev root");
        }
        #[cfg(not(feature = "dev-trust"))]
        assert!(!t.signed_by_dev_root() && !t2.signed_by_dev_root(), "release builds have no dev root");
    }

    #[test]
    fn manifest_must_be_signed_by_registry_key() {
        let v = FakeVault::new();
        let ks = verify_keyset(&v.keyset_bytes(1), &v.roots(), 0).unwrap();
        let m = manifest();
        let good = v.sign_manifest(&m);
        let (got, hash) = ks.verify_manifest(&good, v.now()).unwrap();
        assert_eq!(got, m);
        assert_eq!(hash, crate::sha256(&crate::cbor::encode(&m.to_value())));
        // signed by the dispatch key (wrong purpose) -> rejected
        let wrong = crate::cose::sign1(&m.to_value(), &v.dispatch).unwrap();
        assert!(ks.verify_manifest(&wrong, v.now()).is_err());
        // signed by the updater/release key (never valid for model files) -> rejected
        let rel = crate::cose::sign1(&m.to_value(), &v.updater).unwrap();
        assert!(ks.verify_manifest(&rel, v.now()).is_err());
        // expired key
        assert!(matches!(ks.verify_manifest(&good, u64::MAX), Err(Error::Expired)));
    }
}
