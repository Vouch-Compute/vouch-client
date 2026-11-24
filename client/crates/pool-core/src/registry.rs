//! Model cache. Only bundles described by a ModelManifest signed by the server's `registry` key (the single
//! bundle root) are downloaded; every file is size- and SHA-256-checked while streaming and again by
//! the runner at load. Allowed formats: safetensors, gguf, onnx, ct2. Pickle, `.pt`, code and `.bin` are never
//! loaded, except `model.bin` in a ct2 bundle with a valid CTranslate2 header.
//! Layout: `<data>/models/<model_hash hex>/{manifest.cose, <files...>}`. LRU eviction by size cap.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pool_proto::objects::ModelManifest;
use pool_proto::trust::TrustedKeySet;
use pool_proto::{now_ms, pb};
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct CachedModel {
    pub manifest: ModelManifest,
    pub manifest_cose: Vec<u8>,
    pub model_hash: [u8; 32],
    pub dir: PathBuf,
}

pub struct Registry {
    root: PathBuf,
    cap_bytes: u64,
    index: Mutex<HashMap<[u8; 32], CachedModel>>,
    /// Bundles being downloaded now (one download per model hash; a benchmark offer waits for it).
    downloading: Mutex<std::collections::HashSet<[u8; 32]>>,
}

/// A bundle file may take this long per byte at the slowest (128 KiB/s), and at least 2 minutes. The agent's shared
/// HTTP client stops a request after 120 s, which a 2.3 GB model (bge-m3) does not fit on a home connection.
pub const MIN_DOWNLOAD_BYTES_PER_S: u64 = 128 << 10;
/// A download that receives nothing for this long is dropped (and retried at the next hint).
pub const DOWNLOAD_STALL: std::time::Duration = std::time::Duration::from_secs(60);

/// The time limit for one bundle file of `size` bytes.
pub fn file_download_limit(size: u64) -> std::time::Duration {
    std::time::Duration::from_secs((size / MIN_DOWNLOAD_BYTES_PER_S).max(120))
}

/// Removes the hash from the in-progress set however the download ends.
struct Downloading<'a>(&'a Registry, [u8; 32]);
impl Drop for Downloading<'_> {
    fn drop(&mut self) {
        self.0.downloading.lock().unwrap().remove(&self.1);
    }
}

/// `ws(s)://host:port/...` -> `http(s)://host:port`
pub fn http_base(ws_url: &str) -> String {
    let (scheme, rest) = if let Some(r) = ws_url.strip_prefix("wss://") {
        ("https://", r)
    } else if let Some(r) = ws_url.strip_prefix("ws://") {
        ("http://", r)
    } else {
        ("", ws_url)
    };
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}{host}")
}

fn dir_size(p: &Path) -> u64 {
    std::fs::read_dir(p)
        .map(|rd| {
            rd.flatten()
                .map(|e| match e.metadata() {
                    Ok(m) if m.is_dir() => dir_size(&e.path()),
                    Ok(m) => m.len(),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

impl Registry {
    pub fn new(root: PathBuf, cap_gb: u32) -> Self {
        let _ = std::fs::create_dir_all(&root);
        Self { root, cap_bytes: u64::from(cap_gb) << 30, index: Mutex::new(HashMap::new()), downloading: Mutex::new(Default::default()) }
    }

    /// Re-index cached models whose manifest still verifies under the current KeySet.
    pub fn load_index(&self, ks: &TrustedKeySet) {
        let mut idx = self.index.lock().unwrap();
        idx.clear();
        if let Ok(rd) = std::fs::read_dir(&self.root) {
            for e in rd.flatten() {
                let dir = e.path();
                let Ok(cose) = std::fs::read(dir.join("manifest.cose")) else { continue };
                match ks.verify_manifest(&cose, now_ms()) {
                    Ok((manifest, hash)) if dir.file_name().and_then(|n| n.to_str()) == Some(&hex::encode(hash)) => {
                        idx.insert(hash, CachedModel { manifest, manifest_cose: cose, model_hash: hash, dir });
                    }
                    _ => {
                        tracing::warn!("dropping cached model that no longer verifies: {}", dir.display());
                        let _ = std::fs::remove_dir_all(&dir);
                    }
                }
            }
        }
    }

    pub fn get(&self, model_hash: &[u8]) -> Option<CachedModel> {
        let h: [u8; 32] = model_hash.try_into().ok()?;
        let m = self.index.lock().unwrap().get(&h).cloned();
        if let Some(m) = &m {
            // LRU touch
            let _ = std::fs::File::options().append(true).open(m.dir.join("manifest.cose")).and_then(|f| f.set_modified(std::time::SystemTime::now()));
        }
        m
    }

    /// Drop a cached model (its files failed verification at load): it is no longer announced, offers for it are
    /// declined as not cached, and the next ModelHint downloads a fresh, verified copy.
    pub fn evict(&self, model_hash: &[u8; 32]) {
        if let Some(m) = self.index.lock().unwrap().remove(model_hash) {
            tracing::warn!("evicting cached model {} ({}): bundle failed verification", m.manifest.model_id, m.dir.display());
            let _ = std::fs::remove_dir_all(&m.dir);
        }
    }

    pub fn cached(&self) -> Vec<pb::CachedModel> {
        self.index
            .lock()
            .unwrap()
            .values()
            .map(|m| pb::CachedModel { model_id: m.manifest.model_id.clone(), model_hash: m.model_hash.to_vec() })
            .collect()
    }

    /// Fetch, verify and cache a model announced by a ModelHint.
    pub async fn ensure(
        &self,
        http: &reqwest::Client,
        engine_http: &str,
        hint: &pb::ModelHint,
        ks: &TrustedKeySet,
    ) -> anyhow::Result<[u8; 32]> {
        let murl = if hint.manifest_url.starts_with('/') {
            format!("{engine_http}{}", hint.manifest_url)
        } else if hint.manifest_url.is_empty() {
            format!("{engine_http}/node/v1/manifests/{}/{}", hint.model_id, hint.version)
        } else {
            hint.manifest_url.clone()
        };
        let resp = http.get(&murl).send().await?.error_for_status()?;
        let cose = resp.bytes().await?.to_vec();
        let (manifest, hash) = ks.verify_manifest(&cose, now_ms()).map_err(|e| anyhow::anyhow!("manifest rejected: {e}"))?;
        if manifest.model_id != hint.model_id || manifest.version != hint.version {
            anyhow::bail!("manifest does not match the hint");
        }
        if self.index.lock().unwrap().contains_key(&hash) {
            return Ok(hash);
        }
        // one download per bundle: a second hint for a model being downloaded waits for that download
        if !self.downloading.lock().unwrap().insert(hash) {
            while self.is_downloading(&hash) {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            return if self.index.lock().unwrap().contains_key(&hash) { Ok(hash) } else { anyhow::bail!("the download of this model failed") };
        }
        let _guard = Downloading(self, hash);
        let total: u64 = manifest.files.iter().map(|f| f.size).sum();
        self.evict_for(total);
        let dir = self.root.join(hex::encode(hash));
        let staging = self.root.join(format!(".staging-{}", hex::encode(&hash[..8])));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)?;
        let res = async {
            for f in &manifest.files {
                let url = format!("{engine_http}/node/v1/bundles/{}/{}/{}", manifest.model_id, manifest.version, f.path);
                let mut resp = http.get(&url).timeout(file_download_limit(f.size)).send().await?.error_for_status()?;
                let p = staging.join(&f.path);
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut out = std::fs::File::create(&p)?;
                let mut hasher = sha2::Sha256::new();
                let mut n = 0u64;
                let mut head = Vec::with_capacity(16);
                while let Some(chunk) = tokio::time::timeout(DOWNLOAD_STALL, resp.chunk())
                    .await
                    .map_err(|_| anyhow::anyhow!("{}: no data for {} s", f.path, DOWNLOAD_STALL.as_secs()))??
                {
                    n += chunk.len() as u64;
                    if n > f.size {
                        anyhow::bail!("{} larger than the manifest says", f.path);
                    }
                    if head.len() < 16 {
                        head.extend(chunk.iter().take(16 - head.len()));
                    }
                    hasher.update(&chunk);
                    out.write_all(&chunk)?;
                }
                let digest: [u8; 32] = hasher.finalize().into();
                if n != f.size || digest != f.sha256 {
                    anyhow::bail!("{} does not match the signed manifest", f.path);
                }
                // A ct2 `model.bin` must carry a CTranslate2 header (not pickle, not ZIP); the names were
                // already checked when the manifest was parsed. The runner checks the whole file again at load.
                if pool_proto::objects::is_ct2_model_bin(&manifest.format, &f.path) && !pool_proto::objects::ct2_header_ok(&head) {
                    anyhow::bail!("{} is not a CTranslate2 binary", f.path);
                }
            }
            std::fs::write(staging.join("manifest.cose"), &cose)?;
            Ok(())
        }
        .await;
        if let Err(e) = res {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(e) = rename_dir_with_retry(&staging, &dir).await {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e.into());
        }
        self.index.lock().unwrap().insert(hash, CachedModel { manifest, manifest_cose: cose, model_hash: hash, dir });
        Ok(hash)
    }

    /// Is the bundle with this manifest hash being downloaded now?
    pub fn is_downloading(&self, model_hash: &[u8]) -> bool {
        <[u8; 32]>::try_from(model_hash).is_ok_and(|h| self.downloading.lock().unwrap().contains(&h))
    }

    fn evict_for(&self, incoming: u64) {
        let mut entries: Vec<(std::time::SystemTime, [u8; 32], PathBuf, u64)> = self
            .index
            .lock()
            .unwrap()
            .values()
            .map(|m| {
                let t = std::fs::metadata(m.dir.join("manifest.cose")).and_then(|x| x.modified()).unwrap_or(std::time::UNIX_EPOCH);
                (t, m.model_hash, m.dir.clone(), dir_size(&m.dir))
            })
            .collect();
        let mut used: u64 = entries.iter().map(|e| e.3).sum();
        entries.sort_by_key(|e| e.0);
        for (_, hash, dir, size) in entries {
            if used + incoming <= self.cap_bytes {
                break;
            }
            let _ = std::fs::remove_dir_all(&dir);
            self.index.lock().unwrap().remove(&hash);
            used = used.saturating_sub(size);
        }
    }
}

/// Move the verified staging dir into place. On Windows a directory cannot be renamed while any file in it is
/// open without delete sharing, and antivirus scanners open freshly written files (model weights especially) for a
/// moment: without the retry, every download could fail with `Access is denied (os error 5)` at this step.
/// Retry for a few seconds before giving up.
async fn rename_dir_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut wait = std::time::Duration::from_millis(50);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && std::time::Instant::now() < deadline => {
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(std::time::Duration::from_millis(1000));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod download_limit_tests {
    use super::*;

    /// bge-m3's weights (2.3 GB) get hours, not the shared client's 120 s; small files keep a 2-minute floor.
    #[test]
    fn large_bundle_files_get_time_to_download() {
        assert_eq!(file_download_limit(10 << 20), std::time::Duration::from_secs(120));
        let bge_m3 = file_download_limit(2_270_000_000);
        assert!(bge_m3 >= std::time::Duration::from_secs(4 * 3600), "{bge_m3:?}");
    }

    #[test]
    fn download_state_is_cleared_however_the_download_ends() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path().join("models"), 1);
        let h = [7u8; 32];
        r.downloading.lock().unwrap().insert(h);
        assert!(r.is_downloading(&h));
        drop(Downloading(&r, h));
        assert!(!r.is_downloading(&h));
        assert!(!r.is_downloading(&[1, 2, 3]), "a malformed hash is never downloading");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_base_from_ws_url() {
        assert_eq!(http_base("wss://engine.example:443/node/v1/connect"), "https://engine.example:443");
        assert_eq!(http_base("ws://127.0.0.1:8000/node/v1/connect"), "http://127.0.0.1:8000");
    }

    #[test]
    fn index_drops_models_that_do_not_verify() {
        let fx = pool_runner::testutil::bundle_fixture(&[("model.safetensors", b"w".to_vec())]);
        let root = tempfile::tempdir().unwrap();
        let ks = pool_proto::trust::verify_keyset(&fx.keyset, &fx.vault.roots(), 0).unwrap();
        // a good cached model
        let good = root.path().join(hex::encode(fx.model_hash));
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(good.join("manifest.cose"), &fx.manifest_cose).unwrap();
        // a forged one (signed by the dispatch key)
        let forged = pool_proto::cose::sign1(&fx.manifest.to_value(), &fx.vault.dispatch).unwrap();
        let bad = root.path().join("ab".repeat(32));
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("manifest.cose"), forged).unwrap();
        let r = Registry::new(root.path().to_path_buf(), 1);
        r.load_index(&ks);
        assert!(r.get(&fx.model_hash).is_some());
        assert_eq!(r.cached().len(), 1);
        assert!(!bad.exists(), "forged manifest removed from cache");
    }
}
