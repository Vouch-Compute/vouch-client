//! Deterministic CBOR, COSE_Sign1 parsing and every typed claims decoder. Must never panic; what decodes as
//! deterministic CBOR re-encodes to the same bytes; random bytes never verify under a real key.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pool_proto::objects::*;
use pool_proto::{cbor, cose, object_types as ot};

fn claims(v: &cbor::Value) {
    let _ = HelloClaims::from_value(v);
    let _ = ResultClaims::from_value(v);
    let _ = LeaseProof::from_value(v);
    let _ = EnrollClaims::from_value(v);
    let _ = HwClaims::from_value(v);
    let _ = BenchmarkResult::from_value(v);
    let _ = LeaseEnvelope::from_value(v);
    let _ = BenchmarkWorkload::from_value(v);
    let _ = ModelManifest::from_value(v);
    let _ = KeySet::from_value(v);
    let _ = HwIdentifiers::from_value(v);
    let _ = DeviceControl::from_value(v);
    let _ = RecoveryProof::from_value(v);
    let _ = KeyRotationClaims::from_value(v);
}

fn key() -> &'static p256::ecdsa::VerifyingKey {
    static K: std::sync::OnceLock<p256::ecdsa::VerifyingKey> = std::sync::OnceLock::new();
    K.get_or_init(|| pool_proto::keys::SoftwareKey::generate().verifying_key())
}

fuzz_target!(|data: &[u8]| {
    let _ = cbor::decode_any(data);
    if let Ok(v) = cbor::decode_deterministic(data) {
        claims(&v);
        assert_eq!(cbor::encode(&v), data);
    }
    for ty in [ot::MODEL_MANIFEST, ot::KEY_SET, ot::LEASE_ENVELOPE, ot::BENCHMARK_WORKLOAD, ot::RESULT_CLAIMS] {
        if let Ok(s) = cose::parse_sign1(data, ty) {
            claims(&s.claims);
            assert!(s.verify(key()).is_err());
        }
    }
});
