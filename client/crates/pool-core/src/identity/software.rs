//! Software ES256 device key (DEV tier). Sealed at rest with DPAPI (Windows, current-user scope) or
//! stored with mode 0600 (Unix). Never leaves the agent process; the app holds no keys.

use std::path::Path;

use pool_proto::cose::Es256Signer;
use pool_proto::keys::SoftwareKey;

use super::{DeviceKey, KeyStorage};

pub struct SoftwareDeviceKey {
    key: std::sync::Mutex<Option<SoftwareKey>>,
    kid: String,
    spki: Vec<u8>,
    path: Option<std::path::PathBuf>,
}

impl SoftwareDeviceKey {
    fn new(k: SoftwareKey, path: Option<std::path::PathBuf>) -> Self {
        Self { kid: k.kid(), spki: k.spki_der(), key: std::sync::Mutex::new(Some(k)), path }
    }

    pub fn generate() -> Self {
        Self::new(SoftwareKey::generate(), None)
    }

    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let sealed = std::fs::read(path)?;
            let der = unseal(&sealed)?;
            return Ok(Self::new(SoftwareKey::from_pkcs8_der(&der).map_err(|e| anyhow::anyhow!("{e}"))?, Some(path.to_path_buf())));
        }
        let k = SoftwareKey::generate();
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        write_private(path, &seal(&k.to_pkcs8_der())?)?;
        Ok(Self::new(k, Some(path.to_path_buf())))
    }

    #[cfg(test)]
    fn pkcs8(&self) -> Vec<u8> {
        self.key.lock().unwrap().as_ref().map(|k| k.to_pkcs8_der()).unwrap_or_default()
    }
}

impl Es256Signer for SoftwareDeviceKey {
    fn kid(&self) -> String {
        self.kid.clone()
    }
    fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64], pool_proto::Error> {
        match &*self.key.lock().unwrap() {
            Some(k) => k.sign_es256(msg),
            None => Err(pool_proto::Error::Signer("the device key was destroyed".into())),
        }
    }
}

impl DeviceKey for SoftwareDeviceKey {
    fn spki_der(&self) -> Vec<u8> {
        self.spki.clone()
    }
    fn storage(&self) -> KeyStorage {
        KeyStorage::SoftwareDev
    }
    fn destroy(&self) -> anyhow::Result<()> {
        *self.key.lock().unwrap() = None;
        if let Some(p) = &self.path {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(windows)]
pub(crate) fn seal(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    crate::dpapi::protect(data)
}
#[cfg(windows)]
pub(crate) fn unseal(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    crate::dpapi::unprotect(data)
}
#[cfg(not(windows))]
pub(crate) fn seal(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
pub(crate) fn unseal(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.sealed");
        let a = SoftwareDeviceKey::load_or_create(&p).unwrap();
        let b = SoftwareDeviceKey::load_or_create(&p).unwrap();
        assert_eq!(a.kid(), b.kid());
        assert_eq!(a.storage(), KeyStorage::SoftwareDev);
        // the sealed file is not the plain PKCS#8 key on Windows
        #[cfg(windows)]
        assert_ne!(std::fs::read(&p).unwrap(), a.pkcs8());
        let sig = a.sign_es256(b"m").unwrap();
        use p256::ecdsa::signature::Verifier;
        let vk = pool_proto::keys::parse_spki(&a.spki_der()).unwrap();
        vk.verify(b"m", &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
    }

    /// Key storage: a file readable by its user only on Unix; on Windows the DPAPI blob contains neither the PKCS#8 encoding nor
    /// the raw 32-byte private scalar; a damaged key file is refused, never silently replaced (a replaced key would
    /// be a different device to the server); destroy() removes the file.
    #[test]
    fn key_file_is_private_sealed_and_tamper_evident() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("device_key.sealed");
        let a = SoftwareDeviceKey::load_or_create(&p).unwrap();
        let on_disk = std::fs::read(&p).unwrap();
        let pkcs8 = a.pkcs8();
        let scalar = <p256::ecdsa::SigningKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_der(&pkcs8).unwrap().to_bytes().to_vec();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            // documented residual risk (M7-client.md section 9): plain PKCS#8 on Unix, protected by the file mode only
            assert_eq!(on_disk, pkcs8);
        }
        #[cfg(windows)]
        {
            assert!(!on_disk.windows(scalar.len()).any(|w| w == scalar.as_slice()), "raw private scalar on disk");
            assert!(!on_disk.windows(pkcs8.len()).any(|w| w == pkcs8.as_slice()), "PKCS#8 on disk");
        }
        let _ = &scalar;
        // Windows (DPAPI is authenticated): flip a byte in the middle: the key is refused, and the file is left for
        // the user/support to see. Unix stores plain PKCS#8 (0600, software keys only): no integrity check there.
        #[cfg(windows)]
        {
            let mut bad = on_disk.clone();
            let mid = bad.len() / 2;
            bad[mid] ^= 0x55;
            std::fs::write(&p, &bad).unwrap();
            assert!(SoftwareDeviceKey::load_or_create(&p).is_err(), "a damaged key file must not load");
            assert_eq!(std::fs::read(&p).unwrap(), bad, "and must not be silently replaced");
            std::fs::write(&p, &on_disk).unwrap();
        }
        let b = SoftwareDeviceKey::load_or_create(&p).unwrap();
        assert_eq!(a.kid(), b.kid());
        b.destroy().unwrap();
        assert!(!p.exists());
        assert!(b.sign_es256(b"m").is_err(), "a destroyed key cannot sign");
    }
}
