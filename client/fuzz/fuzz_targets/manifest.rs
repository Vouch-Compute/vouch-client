//! Registry manifests and KeySets: arbitrary bytes through the full trust chain the agent and runner use. Nothing
//! unsigned verifies; every manifest the decoder accepts has safe paths and a bounded total size.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pool_proto::testkit::FakeVault;
use pool_proto::trust;

struct W {
    v: FakeVault,
    ks: trust::TrustedKeySet,
}

fn w() -> &'static W {
    static X: std::sync::OnceLock<W> = std::sync::OnceLock::new();
    X.get_or_init(|| {
        let v = FakeVault::new();
        let ks = trust::verify_keyset(&v.keyset_bytes(2), &v.roots(), 0).unwrap();
        W { v, ks }
    })
}

fuzz_target!(|data: &[u8]| {
    let w = w();
    assert!(trust::verify_keyset(data, &w.v.roots(), 0).is_err());
    assert!(w.ks.verify_manifest(data, 1000).is_err());
    assert!(w.ks.verify_lease_envelope(data, 1000).is_err());
    assert!(w.ks.verify_benchmark_workload(data, 1000).is_err());
    if let Ok(v) = pool_proto::cbor::decode_deterministic(data) {
        if let Ok(m) = pool_proto::objects::ModelManifest::from_value(&v) {
            let mut total = 0u64;
            for f in &m.files {
                assert!(pool_proto::objects::is_safe_relative_path(&f.path));
                total += f.size;
            }
            assert!(total <= pool_proto::objects::MAX_BUNDLE_BYTES);
        }
    }
});
