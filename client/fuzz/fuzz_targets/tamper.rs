//! Tampering: the fuzzer's bytes are an edit script applied to a validly signed KeySet, manifest and lease
//! envelope. Any change must be refused.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pool_proto::objects::*;
use pool_proto::testkit::FakeVault;
use pool_proto::trust;

struct W {
    v: FakeVault,
    ks_bytes: Vec<u8>,
    ks: trust::TrustedKeySet,
    manifest: Vec<u8>,
    envelope: Vec<u8>,
}

fn w() -> &'static W {
    static X: std::sync::OnceLock<W> = std::sync::OnceLock::new();
    X.get_or_init(|| {
        let v = FakeVault::new();
        let ks_bytes = v.keyset_bytes(2);
        let ks = trust::verify_keyset(&ks_bytes, &v.roots(), 0).unwrap();
        let m = ModelManifest {
            model_id: "m".into(),
            version: "1".into(),
            source_repo: "r".into(),
            source_commit: "c".into(),
            license: "MIT".into(),
            format: "safetensors".into(),
            runtime: "candle".into(),
            quantization: "f32".into(),
            files: vec![ManifestFile { path: "model.safetensors".into(), sha256: [1; 32], size: 9 }],
            min_vram_mb: 0,
            min_ram_mb: 1,
            tolerance_class: "t".into(),
            tiers: vec!["cpu".into()],
            input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
            issued_at: 1,
            approvals: vec!["a".into(), "b".into()],
        };
        let manifest = v.sign_manifest(&m);
        let e = LeaseEnvelope {
            job_id: "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
            lease_id: "1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
            device_id: "2b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
            device_key_id: format!("dk_{}", "A".repeat(43)),
            model_id: "m".into(),
            model_hash: [2; 32],
            input_sha256: [3; 32],
            input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
            input_bytes: 5,
            unit_type: "token".into(),
            issued_at: 1,
            deadline: 9,
            language: None,
        };
        let envelope = v.sign_envelope(&e);
        W { v, ks_bytes, ks, manifest, envelope }
    })
}

/// Edit script: triples of (op, position, byte).
fn edit(orig: &[u8], script: &[u8]) -> Vec<u8> {
    let mut b = orig.to_vec();
    for c in script.chunks(3) {
        let (op, a, x) = (c[0], *c.get(1).unwrap_or(&0) as usize, *c.get(2).unwrap_or(&0));
        let n = b.len().max(1);
        let at = (a * 7919) % n;
        match op % 5 {
            0 if !b.is_empty() => b[at] ^= x | 1,
            1 if !b.is_empty() => b[at] = x,
            2 => b.insert(at.min(b.len()), x),
            3 if !b.is_empty() => {
                b.remove(at);
            }
            4 => b.truncate(at),
            _ => {}
        }
    }
    b
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let w = w();
    let which = data[0] % 3;
    let orig: &[u8] = match which {
        0 => &w.ks_bytes,
        1 => &w.manifest,
        _ => &w.envelope,
    };
    let t = edit(orig, &data[1..]);
    if t == orig {
        return;
    }
    let accepted = match which {
        0 => trust::verify_keyset(&t, &w.v.roots(), 0).is_ok(),
        1 => w.ks.verify_manifest(&t, 1000).is_ok(),
        _ => w.ks.verify_lease_envelope(&t, 1000).is_ok(),
    };
    assert!(!accepted, "tampered object accepted");
});
