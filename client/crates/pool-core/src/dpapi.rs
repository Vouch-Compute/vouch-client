//! DPAPI (current-user scope) for secrets at rest on Windows: the DEV software key and the refresh token.

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const ENTROPY: &[u8] = b"vouchcompute/pool-core/v1";

fn blob(d: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: d.len() as u32, pbData: d.as_ptr() as *mut u8 }
}

pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = CRYPT_INTEGER_BLOB::default();
    let ent = blob(ENTROPY);
    unsafe {
        CryptProtectData(&blob(data), None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
        Ok(v)
    }
}

pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = CRYPT_INTEGER_BLOB::default();
    let ent = blob(ENTROPY);
    unsafe {
        CryptUnprotectData(&blob(data), None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let s = super::protect(b"secret").unwrap();
        assert_ne!(s, b"secret");
        assert_eq!(super::unprotect(&s).unwrap(), b"secret");
        let mut bad = s.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(super::unprotect(&bad).is_err());
    }
}
