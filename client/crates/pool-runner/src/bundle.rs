//! Signed model bundle loading. The runner trusts nothing pool-core says about the model:
//! it re-verifies the KeySet against its own embedded roots, the ModelManifest against the KeySet's
//! `registry` key, the manifest hash against the lease's `model_hash`, and every file's size and
//! SHA-256 before any byte reaches a model parser. Files are read into memory once.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use pool_proto::objects::ModelManifest;
use pool_proto::{keys, now_ms, sha256, trust};

#[derive(Debug, thiserror::Error)]
#[error("bundle invalid: {0}")]
pub struct BundleError(pub String);

fn err(s: impl Into<String>) -> BundleError {
    BundleError(s.into())
}

pub struct VerifiedBundle {
    pub manifest: ModelManifest,
    pub model_hash: [u8; 32],
    /// path -> bytes, every entry hash-checked against the manifest.
    pub files: BTreeMap<String, Vec<u8>>,
    /// The manifest chain was verified under a **dev** KeySet root (`trust::is_dev_root`; always `false` in release
    /// builds). The dev reference backend requires it.
    pub dev_root: bool,
}

impl VerifiedBundle {
    pub fn file(&self, path: &str) -> Result<&[u8], BundleError> {
        self.files.get(path).map(|v| v.as_slice()).ok_or_else(|| err(format!("bundle lacks {path}")))
    }
}

/// A manifest whose chain verified: the manifest, its `model_hash`, and whether the KeySet root is a dev root.
pub struct VerifiedManifest {
    pub manifest: ModelManifest,
    pub model_hash: [u8; 32],
    pub dev_root: bool,
}

/// Verify the manifest chain only (no file I/O).
pub fn verify_manifest(keyset_cose: &[u8], manifest_cose: &[u8], expected_model_hash: &[u8; 32]) -> Result<VerifiedManifest, BundleError> {
    let roots = trust::trust_roots().map_err(|e| err(format!("trust roots: {e}")))?;
    let ks = trust::verify_keyset(keyset_cose, &roots, 0).map_err(|e| err(format!("keyset: {e}")))?;
    let (manifest, hash) = ks.verify_manifest(manifest_cose, now_ms()).map_err(|e| err(format!("manifest: {e}")))?;
    if &hash != expected_model_hash {
        return Err(err("model_hash does not match the signed manifest"));
    }
    Ok(VerifiedManifest { manifest, model_hash: hash, dev_root: ks.signed_by_dev_root() })
}

/// Verify the chain and load every bundle file from `dir`, checking size and SHA-256.
pub fn load(
    keyset_cose: &[u8],
    manifest_cose: &[u8],
    expected_model_hash: &[u8; 32],
    dir: &Path,
) -> Result<VerifiedBundle, BundleError> {
    let VerifiedManifest { manifest, model_hash, dev_root } = verify_manifest(keyset_cose, manifest_cose, expected_model_hash)?;
    let mut files = BTreeMap::new();
    for f in &manifest.files {
        // paths were validated as safe relative paths when the manifest was parsed
        let path = dir.join(&f.path);
        let file = std::fs::File::open(&path).map_err(|e| err(format!("open {}: {e}", f.path)))?;
        let mut data = Vec::with_capacity(f.size.min(1 << 32) as usize);
        file.take(f.size + 1).read_to_end(&mut data).map_err(|e| err(format!("read {}: {e}", f.path)))?;
        if data.len() as u64 != f.size {
            return Err(err(format!("size mismatch for {}", f.path)));
        }
        if sha256(&data) != f.sha256 {
            return Err(err(format!("hash mismatch for {}", f.path)));
        }
        // file-type policy: no pickle/.pt/.bin/code; a ct2 `model.bin` only with a
        // valid CTranslate2 header. Checked after the hash, before any parser sees the bytes.
        pool_proto::objects::check_bundle_file_content(&manifest.format, &f.path, &data)
            .map_err(|e| err(format!("{}: {e}", f.path)))?;
        files.insert(f.path.clone(), data);
    }
    Ok(VerifiedBundle { manifest, model_hash, files, dev_root })
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>, BundleError> {
    keys::b64_decode(s).map_err(|_| err("bad base64"))
}

pub fn decode_hash_hex(s: &str) -> Result<[u8; 32], BundleError> {
    let v = hex::decode(s).map_err(|_| err("bad hex"))?;
    v.try_into().map_err(|_| err("model hash must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{bundle_fixture, set_dev_roots};

    #[test]
    fn verified_bundle_loads_and_tampering_is_detected() {
        let fx = bundle_fixture(&[("a.dat", b"hello".to_vec()), ("dir/b.txt", b"world".to_vec())]);
        set_dev_roots(fx.vault);
        let b = load(&fx.keyset, &fx.manifest_cose, &fx.model_hash, fx.dir.path()).unwrap();
        assert_eq!(b.file("a.dat").unwrap(), b"hello");

        // wrong expected hash (offer for another model)
        assert!(load(&fx.keyset, &fx.manifest_cose, &[0; 32], fx.dir.path()).is_err());
        // tampered file on disk
        std::fs::write(fx.dir.path().join("a.dat"), b"hellO").unwrap();
        assert!(load(&fx.keyset, &fx.manifest_cose, &fx.model_hash, fx.dir.path()).is_err());
        // grown file
        std::fs::write(fx.dir.path().join("a.dat"), b"hello!").unwrap();
        assert!(load(&fx.keyset, &fx.manifest_cose, &fx.model_hash, fx.dir.path()).is_err());
    }

    #[test]
    fn ct2_model_bin_needs_a_valid_header() {
        use crate::testutil::bundle_fixture_with;
        let mut good = 6u32.to_le_bytes().to_vec();
        good.extend_from_slice(&[7; 60]);
        let fx = bundle_fixture_with(
            &[("model.bin", good), ("config.json", b"{}".to_vec())],
            "ctranslate2",
            "ct2",
            pool_proto::CANONICAL_AUDIO_FORMAT,
            "whisper-tiny",
        );
        set_dev_roots(fx.vault);
        assert!(load(&fx.keyset, &fx.manifest_cose, &fx.model_hash, fx.dir.path()).is_ok());
        // signed and hash-correct, but a pickle stream: refused before any parser sees it
        for bad in [vec![0x80, 0x04, 0x95, 0x10, 0, 0, 0, 0], b"PK".iter().copied().chain([3, 4, 0x14, 0]).collect(), 99u32.to_le_bytes().to_vec()] {
            let fx = bundle_fixture_with(&[("model.bin", bad)], "ctranslate2", "ct2", pool_proto::CANONICAL_AUDIO_FORMAT, "w");
            set_dev_roots(fx.vault);
            let e = load(&fx.keyset, &fx.manifest_cose, &fx.model_hash, fx.dir.path()).err().expect("refused");
            assert!(e.0.contains("CTranslate2"), "{e}");
        }
    }

    #[test]
    fn manifest_not_from_registry_key_is_refused() {
        let fx = bundle_fixture(&[("a.dat", b"x".to_vec())]);
        set_dev_roots(fx.vault);
        // same manifest, signed by the dispatch key instead of the registry key
        let forged = pool_proto::cose::sign1(&fx.manifest.to_value(), &fx.vault.dispatch).unwrap();
        let hash = sha256(&pool_proto::cbor::encode(&fx.manifest.to_value()));
        assert!(load(&fx.keyset, &forged, &hash, fx.dir.path()).is_err());
        // KeySet signed by a non-root key
        let other = pool_proto::testkit::FakeVault::new();
        assert!(load(&other.keyset_bytes(1), &fx.manifest_cose, &fx.model_hash, fx.dir.path()).is_err());
    }
}
