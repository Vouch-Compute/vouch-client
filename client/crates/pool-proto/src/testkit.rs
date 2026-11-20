//! Test doubles for the server's keys (feature `testkit`, used by tests in this workspace only).

use crate::cose::{sign1, Es256Signer};
use crate::keys::SoftwareKey;
use crate::objects::{BenchmarkWorkload, KeySet, KeySetEntry, LeaseEnvelope, ModelManifest};
use p256::ecdsa::VerifyingKey;

pub struct FakeVault {
    pub roots: [SoftwareKey; 2],
    pub dispatch: SoftwareKey,
    pub registry: SoftwareKey,
    pub benchmark: SoftwareKey,
    pub updater: SoftwareKey,
}

impl Default for FakeVault {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeVault {
    pub fn new() -> Self {
        Self {
            roots: [
                SoftwareKey::generate().with_kid("vk_root_202611_1"),
                SoftwareKey::generate().with_kid("vk_root_202611_2"),
            ],
            dispatch: SoftwareKey::generate().with_kid("vk_dispatch_202611_1"),
            registry: SoftwareKey::generate().with_kid("vk_registry_202611_1"),
            benchmark: SoftwareKey::generate().with_kid("vk_benchmark_202611_1"),
            updater: SoftwareKey::generate().with_kid("vk_updater_202611_1"),
        }
    }

    pub fn now(&self) -> u64 {
        crate::now_ms()
    }

    pub fn roots(&self) -> Vec<VerifyingKey> {
        self.roots.iter().map(|k| k.verifying_key()).collect()
    }

    /// Comma-separated base64 SPKI of the roots (for `POOL_DEV_TRUST_ROOTS`).
    pub fn roots_env(&self) -> String {
        self.roots.iter().map(|k| crate::keys::b64(&k.spki_der())).collect::<Vec<_>>().join(",")
    }

    pub fn keyset(&self, version: u64) -> KeySet {
        let entry = |k: &SoftwareKey, purpose: &str| KeySetEntry {
            kid: k.kid(),
            alg: -7,
            purpose: purpose.into(),
            public_key: k.spki_der(),
            not_before: 0,
            not_after: self.now() + 86_400_000,
        };
        KeySet {
            version,
            issued_at: self.now(),
            keys: vec![
                entry(&self.dispatch, "dispatch"),
                entry(&self.registry, "registry"),
                entry(&self.benchmark, "benchmark"),
                entry(&self.updater, "updater"),
            ],
        }
    }

    pub fn keyset_bytes(&self, version: u64) -> Vec<u8> {
        self.keyset_bytes_with_root(version, 0)
    }

    pub fn keyset_bytes_with_root(&self, version: u64, root: usize) -> Vec<u8> {
        sign1(&self.keyset(version).to_value(), &self.roots[root]).unwrap()
    }

    pub fn sign_manifest(&self, m: &ModelManifest) -> Vec<u8> {
        sign1(&m.to_value(), &self.registry).unwrap()
    }

    pub fn sign_envelope(&self, e: &LeaseEnvelope) -> Vec<u8> {
        sign1(&e.to_value(), &self.dispatch).unwrap()
    }

    pub fn sign_workload(&self, w: &BenchmarkWorkload) -> Vec<u8> {
        sign1(&w.to_value(), &self.benchmark).unwrap()
    }
}
