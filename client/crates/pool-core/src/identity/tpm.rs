//! TPM 2.0 device key on Windows through the Microsoft Platform Crypto Provider (NCrypt / PCP).
//! The private key is generated inside the TPM and is non-exportable; signing hashes the message with
//! SHA-256 and asks the TPM for an ECDSA P-256 signature (raw r || s, as COSE ES256 needs).
//!
//! `tpm2` v2 attestation (`attest.rs`): the EK public key (`PCP_EKPUB`, rebuilt as the default EK template's
//! `TPM2B_PUBLIC`), the AIK's `TPM2B_PUBLIC` (its identity binding, `PCP_TPM12_IDBINDING`), `TPM2_ActivateCredential`
//! through the AIK's `PCP_TPM12_IDACTIVATION` property, and TPM2_Certify of the device key through
//! `NCryptCreateClaim(NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT)`.

use std::sync::Mutex;

use pool_proto::cose::Es256Signer;
use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, CERT_KEY_SPEC, NCRYPT_FLAGS,
    NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

use super::attest::{self, TpmActivation, TpmAttester, TpmPublics};
use super::{DeviceKey, KeyStorage};

pub const KEY_NAME: &str = "VouchCompute-Device-Key";
/// Name of the persisted attestation identity key (AIK) in the Platform Crypto Provider.
pub const AIK_NAME: &str = "VouchCompute-AIK";
const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345; // "ECS1"
const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352; // "RSA1"

pub struct TpmDeviceKey {
    /// `None` once the key was deleted ("Remove this device", key rotation).
    key: Mutex<Option<NCRYPT_KEY_HANDLE>>,
    prov: NCRYPT_PROV_HANDLE,
    spki: Vec<u8>,
    kid: String,
    name: String,
    aik_name: String,
}

unsafe impl Send for TpmDeviceKey {}
unsafe impl Sync for TpmDeviceKey {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn open_provider() -> anyhow::Result<NCRYPT_PROV_HANDLE> {
    let mut prov = NCRYPT_PROV_HANDLE::default();
    NCryptOpenStorageProvider(&mut prov, w!("Microsoft Platform Crypto Provider"), 0)?;
    Ok(prov)
}

impl TpmDeviceKey {
    /// Open the persisted key `name`, or create it.
    pub fn open_or_create(name: &str) -> anyhow::Result<Self> {
        Self::open_inner(name, true)
    }

    /// Create a new key `name`; fails if one exists (key rotation).
    pub fn create_new(name: &str) -> anyhow::Result<Self> {
        if Self::open_inner(name, false).is_ok() {
            anyhow::bail!("a TPM key named {name} already exists");
        }
        Self::open_inner(name, true)
    }

    fn open_inner(name: &str, create: bool) -> anyhow::Result<Self> {
        unsafe {
            let prov = open_provider()?;
            let wname = wide(name);
            let mut key = NCRYPT_KEY_HANDLE::default();
            let opened = NCryptOpenKey(prov, &mut key, PCWSTR(wname.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_SILENT_FLAG);
            if let Err(e) = opened {
                if !create {
                    let _ = NCryptFreeObject(prov.into());
                    return Err(e.into());
                }
                NCryptCreatePersistedKey(prov, &mut key, BCRYPT_ECDSA_P256_ALGORITHM, PCWSTR(wname.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))?;
                if let Err(e) = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) {
                    let _ = NCryptFreeObject(key.into());
                    let _ = NCryptFreeObject(prov.into());
                    return Err(e.into());
                }
            }
            let point = match export_point(key) {
                Ok(p) => p,
                Err(e) => {
                    let _ = NCryptFreeObject(key.into());
                    let _ = NCryptFreeObject(prov.into());
                    return Err(e);
                }
            };
            let vk = pool_proto::keys::from_sec1(&point).map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(Self {
                key: Mutex::new(Some(key)),
                prov,
                spki: pool_proto::keys::spki_der(&vk),
                kid: pool_proto::keys::device_key_id(&vk),
                name: name.to_string(),
                aik_name: AIK_NAME.to_string(),
            })
        }
    }

    /// Use another AIK name (tests).
    pub fn with_aik_name(mut self, aik_name: &str) -> Self {
        self.aik_name = aik_name.to_string();
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn handle(&self) -> anyhow::Result<NCRYPT_KEY_HANDLE> {
        self.key.lock().unwrap().ok_or_else(|| anyhow::anyhow!("the TPM device key was deleted"))
    }

    /// Delete the persisted key inside the TPM ("Remove this device", key rotation, tests). Afterwards the key can no
    /// longer sign, and opening it by name fails.
    pub fn delete_key(&self) -> anyhow::Result<()> {
        let mut guard = self.key.lock().unwrap();
        if let Some(k) = guard.take() {
            unsafe { NCryptDeleteKey(k, 0)? }; // also releases the handle
        }
        Ok(())
    }

    /// Delete the AIK (tests).
    pub fn delete_aik(&self) -> anyhow::Result<()> {
        unsafe {
            let aik = self.open_or_create_aik()?;
            NCryptDeleteKey(aik, 0)?;
        }
        Ok(())
    }
}

unsafe fn export_point(key: NCRYPT_KEY_HANDLE) -> anyhow::Result<Vec<u8>> {
    let mut size = 0u32;
    NCryptExportKey(key, None, BCRYPT_ECCPUBLIC_BLOB, None, None, &mut size, NCRYPT_FLAGS(0))?;
    let mut buf = vec![0u8; size as usize];
    NCryptExportKey(key, None, BCRYPT_ECCPUBLIC_BLOB, None, Some(&mut buf), &mut size, NCRYPT_FLAGS(0))?;
    // BCRYPT_ECCKEY_BLOB { dwMagic, cbKey } || X || Y
    if buf.len() < 8 + 64 {
        anyhow::bail!("short ECC public blob");
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into()?);
    let cb = u32::from_le_bytes(buf[4..8].try_into()?) as usize;
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb != 32 {
        anyhow::bail!("not a P-256 ECDSA public key");
    }
    let mut point = vec![0x04];
    point.extend_from_slice(&buf[8..8 + 64]);
    Ok(point)
}

unsafe fn get_property(h: NCRYPT_HANDLE, name: PCWSTR) -> anyhow::Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::NCryptGetProperty;
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    let mut size = 0u32;
    NCryptGetProperty(h, name, None, &mut size, OBJECT_SECURITY_INFORMATION(0))?;
    let mut buf = vec![0u8; size as usize];
    NCryptGetProperty(h, name, Some(&mut buf), &mut size, OBJECT_SECURITY_INFORMATION(0))?;
    buf.truncate(size as usize);
    Ok(buf)
}

/// `BCRYPT_RSAKEY_BLOB` (Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2; exponent; modulus) -> (n, e).
fn parse_bcrypt_rsa_public(b: &[u8]) -> anyhow::Result<(Vec<u8>, u32)> {
    let u = |i: usize| -> anyhow::Result<usize> {
        Ok(u32::from_le_bytes(b.get(i * 4..i * 4 + 4).ok_or_else(|| anyhow::anyhow!("short RSA blob"))?.try_into()?) as usize)
    };
    if u(0)? as u32 != BCRYPT_RSAPUBLIC_MAGIC {
        anyhow::bail!("the EK is not an RSA key (only RSA-2048 EKs are supported)");
    }
    let (ne, nm) = (u(2)?, u(3)?);
    let exp = b.get(24..24 + ne).ok_or_else(|| anyhow::anyhow!("short RSA blob"))?;
    let modulus = b.get(24 + ne..24 + ne + nm).ok_or_else(|| anyhow::anyhow!("short RSA blob"))?;
    let e = exp.iter().fold(0u32, |acc, x| (acc << 8) | u32::from(*x));
    Ok((modulus.to_vec(), e))
}

impl TpmDeviceKey {
    /// Open or create the AIK (an RSA identity key inside the TPM, `NCRYPT_PCP_IDENTITY_KEY`).
    unsafe fn open_or_create_aik(&self) -> anyhow::Result<NCRYPT_KEY_HANDLE> {
        use windows::Win32::Security::Cryptography::{
            NCryptSetProperty, BCRYPT_RSA_ALGORITHM, NCRYPT_PCP_IDENTITY_KEY, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
        };
        let wname = wide(&self.aik_name);
        let mut aik = NCRYPT_KEY_HANDLE::default();
        if NCryptOpenKey(self.prov, &mut aik, PCWSTR(wname.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_SILENT_FLAG).is_ok() {
            return Ok(aik);
        }
        NCryptCreatePersistedKey(self.prov, &mut aik, BCRYPT_RSA_ALGORITHM, PCWSTR(wname.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))?;
        let usage = NCRYPT_PCP_IDENTITY_KEY.to_le_bytes();
        let r = NCryptSetProperty(aik.into(), NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, &usage, NCRYPT_FLAGS(0))
            .and_then(|_| NCryptFinalizeKey(aik, NCRYPT_SILENT_FLAG));
        if let Err(e) = r {
            let _ = NCryptFreeObject(aik.into());
            return Err(e.into());
        }
        Ok(aik)
    }

    /// The TPM's endorsement-key certificate (DER), from NV or the provider's cache, when the platform has one.
    unsafe fn ek_cert(&self) -> Option<Vec<u8>> {
        for prop in [w!("PCP_EKNVCERT"), w!("PCP_EKCERT")] {
            if let Ok(c) = get_property(self.prov.into(), prop) {
                // a plain DER certificate starts with SEQUENCE (0x30); serialized stores are skipped
                if c.first() == Some(&0x30) {
                    return Some(c);
                }
            }
        }
        None
    }

    /// The EK's `TPM2B_PUBLIC` (default RSA-2048 EK template filled with `PCP_EKPUB`'s modulus).
    pub fn ek_public(&self) -> anyhow::Result<Vec<u8>> {
        let blob = unsafe { get_property(self.prov.into(), w!("PCP_EKPUB"))? };
        let (n, e) = parse_bcrypt_rsa_public(&blob)?;
        Ok(attest::rsa_ek_template_public(&n, e)?)
    }

    /// The AIK's `TPM2B_PUBLIC`: the first field of its identity binding.
    pub fn aik_public(&self) -> anyhow::Result<Vec<u8>> {
        unsafe {
            let aik = self.open_or_create_aik()?;
            let binding = get_property(aik.into(), w!("PCP_TPM12_IDBINDING"));
            let _ = NCryptFreeObject(aik.into());
            let binding = binding?;
            let n = u16::from_be_bytes(binding.get(..2).ok_or_else(|| anyhow::anyhow!("empty identity binding"))?.try_into()?) as usize;
            let p = binding.get(..2 + n).ok_or_else(|| anyhow::anyhow!("short identity binding"))?.to_vec();
            attest::TpmPublic::parse(&p)?;
            Ok(p)
        }
    }

    /// `NCryptCreateClaim(NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT)`: the raw claim (a `KAST` statement on Windows 11).
    pub fn create_claim(&self, nonce: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            BCryptBuffer, BCryptBufferDesc, NCryptCreateClaim, NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, NCRYPTBUFFER_VERSION,
            NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT,
        };
        unsafe {
            let aik = self.open_or_create_aik()?;
            let mut qd = attest::qualifying_data(nonce);
            let mut buf = BCryptBuffer { cbBuffer: 32, BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, pvBuffer: qd.as_mut_ptr().cast() };
            let desc = BCryptBufferDesc { ulVersion: NCRYPTBUFFER_VERSION, cBuffers: 1, pBuffers: &mut buf };
            let key = self.handle()?;
            let mut size = 0u32;
            let claim = NCryptCreateClaim(Some(key), Some(aik), NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, Some(&desc), None, &mut size, 0).and_then(|_| {
                let mut out = vec![0u8; size as usize];
                NCryptCreateClaim(Some(key), Some(aik), NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT, Some(&desc), Some(&mut out), &mut size, 0).map(|_| {
                    out.truncate(size as usize);
                    out
                })
            });
            let _ = NCryptFreeObject(aik.into());
            Ok(claim?)
        }
    }
}

impl TpmAttester for TpmDeviceKey {
    fn publics(&self) -> anyhow::Result<TpmPublics> {
        Ok(TpmPublics { ek_public: TpmDeviceKey::ek_public(self)?, ek_cert: unsafe { self.ek_cert() }, aik_public: self.aik_public()? })
    }

    fn ek_public(&self) -> anyhow::Result<Vec<u8>> {
        TpmDeviceKey::ek_public(self)
    }

    fn activate(&self, activation: &TpmActivation) -> anyhow::Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::NCryptSetProperty;
        unsafe {
            let aik = self.open_or_create_aik()?;
            let blob = activation.pcp_activation_blob();
            let r = NCryptSetProperty(aik.into(), w!("PCP_TPM12_IDACTIVATION"), &blob, NCRYPT_FLAGS(0))
                .map_err(anyhow::Error::from)
                .and_then(|_| get_property(aik.into(), w!("PCP_TPM12_IDACTIVATION")));
            let _ = NCryptFreeObject(aik.into());
            r.map_err(|e| anyhow::anyhow!("TPM2_ActivateCredential failed: {e}"))
        }
    }

    fn certify(&self, nonce: &[u8; 32]) -> anyhow::Result<attest::CertifyOutput> {
        let claim = self.create_claim(nonce)?;
        let (pcp, authority) = match attest::parse_kast(&claim) {
            Ok(st) => (st.certify.clone(), Some(st.aik_public()?)),
            Err(_) => (attest::parse_ncrypt_claim(&claim)?, None),
        };
        // the statement must be by our AIK (the one the server's credential was made for)
        if let Some(a) = authority {
            if a != self.aik_public()? {
                anyhow::bail!("the claim was certified by another authority key than the AIK");
            }
        }
        let device_public = attest::pcp_key_blob_public(&pcp.key_blob).ok();
        Ok((pcp.key_attest, pcp.signature, device_public))
    }
}

impl Drop for TpmDeviceKey {
    fn drop(&mut self) {
        unsafe {
            if let Some(k) = self.key.lock().unwrap().take() {
                let _ = NCryptFreeObject(k.into());
            }
            let _ = NCryptFreeObject(self.prov.into());
        }
    }
}

impl Es256Signer for TpmDeviceKey {
    fn kid(&self) -> String {
        self.kid.clone()
    }
    fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64], pool_proto::Error> {
        let digest = pool_proto::sha256(msg);
        let key = self.key.lock().unwrap();
        let key = key.ok_or_else(|| pool_proto::Error::Signer("the TPM device key was deleted".into()))?;
        let mut out = [0u8; 64];
        let mut size = 0u32;
        unsafe {
            NCryptSignHash(key, None, &digest, Some(&mut out), &mut size, NCRYPT_SILENT_FLAG).map_err(|e| pool_proto::Error::Signer(e.to_string()))?;
        }
        if size != 64 {
            return Err(pool_proto::Error::Signer(format!("unexpected signature size {size}")));
        }
        Ok(out)
    }
}

impl DeviceKey for TpmDeviceKey {
    fn spki_der(&self) -> Vec<u8> {
        self.spki.clone()
    }
    fn storage(&self) -> KeyStorage {
        KeyStorage::Tpm
    }
    fn tpm(&self) -> Option<&dyn TpmAttester> {
        Some(self)
    }
    fn destroy(&self) -> anyhow::Result<()> {
        self.delete_key()
    }
    fn key_name(&self) -> Option<String> {
        Some(self.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(tag: &str) -> Option<TpmDeviceKey> {
        let name = format!("VouchCompute-Test-{tag}-{}", std::process::id());
        match TpmDeviceKey::open_or_create(&name) {
            Ok(k) => Some(k.with_aik_name(&format!("VouchCompute-Test-AIK-{tag}-{}", std::process::id()))),
            Err(e) => {
                eprintln!("SKIP: no usable TPM platform provider here: {e}");
                None
            }
        }
    }

    /// Runs against the real TPM when this machine has one (skips, with a message, when it does not).
    #[test]
    fn tpm_key_signs_cose_that_verifies_and_delete_wipes_it() {
        let Some(k) = test_key("Key") else { return };
        assert!(k.kid().starts_with("dk_"));
        let claims = pool_proto::cbor::MapBuilder::new("pool/test/v1").uint("x", 1).build();
        let cose = pool_proto::cose::sign1(&claims, &k).unwrap();
        let vk = pool_proto::keys::parse_spki(&k.spki_der()).unwrap();
        pool_proto::cose::verify_sign1(&cose, &vk, "pool/test/v1").unwrap();
        // reopen by name: same key; create_new refuses an existing name
        let again = TpmDeviceKey::open_or_create(k.name()).unwrap();
        assert_eq!(again.kid(), k.kid());
        drop(again);
        assert!(TpmDeviceKey::create_new(k.name()).is_err());
        // "Remove this device": the TPM key is deleted, cannot sign, cannot be reopened
        k.destroy().unwrap();
        assert!(k.sign_es256(b"m").is_err());
        assert!(TpmDeviceKey::open_inner(k.name(), false).is_err(), "the TPM key is gone");
    }

    /// Live: on this machine's TPM, the server's side (MakeCredential against the EK, test code) and the client's
    /// side (ActivateCredential, certify, v2 blob) run end to end, and the blob passes the dev server's checks
    /// (`attest::verify_v2`: activation HMAC, extraData, certify signature under aik_public). Reports and skips when
    /// the platform cannot do a step.
    #[test]
    fn tpm2_v2_blob_end_to_end_when_available() {
        let Some(k) = test_key("AttKey") else { return };
        let publics = match k.publics() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP: no EK / AIK on this TPM: {e}");
                let _ = k.destroy();
                return;
            }
        };
        let aik = attest::TpmPublic::parse(&publics.aik_public).unwrap();
        eprintln!(
            "AIK: {:?} scheme {:?}, attributes {:#010x}; EK {} B, EK cert {}",
            match &aik.key {
                attest::TpmKey::Rsa { modulus, .. } => format!("RSA-{}", modulus.len() * 8),
                attest::TpmKey::Ecc { curve, .. } => format!("ECC curve {curve:#06x}"),
            },
            aik.scheme,
            aik.attributes,
            publics.ek_public.len(),
            publics.ek_cert.is_some()
        );
        let secret = [0x5cu8; 32];
        let (cred, enc) = attest::make_credential(&publics.ek_public, &aik.name().unwrap(), &secret, &[0x11; 32]);
        let act = attest::TpmActivation { credential_blob: cred, encrypted_secret: enc };
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let nonce = [0x5a; 32];
        let r = attest::build_v2(&k, &publics, &challenge_id, &nonce, &act, &k.spki_der());
        let result = match r {
            Ok(a) => {
                let blob = a.to_cbor();
                let v = attest::verify_v2(&blob, &challenge_id, &nonce, &secret, &publics.ek_public);
                eprintln!("tpm2 v2 blob: {} B, certify_sig {} B, verified by the dev-vault checks: {:?}", blob.len(), a.certify_sig.len(), v.is_ok());
                v.map(|_| ()).map_err(|e| e.to_string())
            }
            Err(e) => {
                let msg = e.to_string();
                eprintln!("v2 flow on this TPM: {msg}");
                if msg.contains("ActivateCredential") {
                    // Measured on a Windows 11 machine with a firmware TPM: the provider's identity activation
                    // returns TPM_RC_SIZE, even for a credential the TPM made itself (TPM2_MakeCredential through TBS),
                    // and NCryptCreateClaim signs with a fresh ECC P-256 authority key per claim instead of the AIK.
                    // The v2 blob therefore cannot be built here and the client sends none (fail-closed). What still
                    // runs live: the claim is certified, its signature is wrapped and verified under the claim's own
                    // authority key, and the client's check refuses it for the AIK.
                    let claim = k.create_claim(&nonce).map_err(|e| e.to_string());
                    match claim.and_then(|c| attest::parse_kast(&c).map_err(|e| e.to_string())) {
                        Ok(st) => {
                            let authority = st.aik_public().unwrap();
                            let auth = attest::TpmPublic::parse(&authority).unwrap();
                            let raw = &st.certify.signature;
                            eprintln!(
                                "KNOWN PLATFORM LIMITATION: claim authority is {} (not the AIK: {}), raw signature {} B",
                                match &auth.key { attest::TpmKey::Ecc { .. } => "ECC P-256", attest::TpmKey::Rsa { .. } => "RSA" },
                                authority != publics.aik_public,
                                raw.len()
                            );
                            let sig = attest::wrap_certify_sig(&auth, raw).map_err(|e| e.to_string());
                            let verified = sig.clone().and_then(|s| attest::verify_certify(&auth, &st.certify.key_attest, &s).map_err(|e| e.to_string()));
                            eprintln!("certify_sig wrapped and verified under the claim's authority: {verified:?}");
                            let refused = k.certify(&nonce).is_err() == (authority != publics.aik_public);
                            verified.and_then(|_| if refused { Ok(()) } else { Err("a claim by another authority was not refused".into()) })
                        }
                        Err(e) if e.contains("NCryptCreateClaim") => {
                            eprintln!("SKIP: no key attestation claim here: {e}");
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                } else if msg.contains("NCryptCreateClaim") {
                    eprintln!("SKIP: this TPM/provider cannot produce a claim");
                    Ok(())
                } else {
                    Err(msg)
                }
            }
        };
        let _ = k.delete_aik();
        k.destroy().unwrap();
        result.unwrap();
    }

    /// One raw TPM command through TBS (tests only).
    fn tbs(cmd: &[u8]) -> Option<Vec<u8>> {
        use windows::Win32::System::TpmBaseServices::*;
        unsafe {
            let params = TBS_CONTEXT_PARAMS2 { version: TBS_CONTEXT_VERSION_TWO, Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 4 } };
            let mut ctx: *mut core::ffi::c_void = std::ptr::null_mut();
            if Tbsi_Context_Create(&params as *const _ as *const TBS_CONTEXT_PARAMS, &mut ctx) != 0 {
                return None;
            }
            let mut out = vec![0u8; 4096];
            let mut n = out.len() as u32;
            let r = Tbsip_Submit_Command(ctx, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd, out.as_mut_ptr(), &mut n);
            Tbsip_Context_Close(ctx);
            (r == 0).then(|| {
                out.truncate(n as usize);
                out
            })
        }
    }

    /// Live: the EK `TPM2B_PUBLIC` the client rebuilds from `PCP_EKPUB` (default RSA-2048 EK template) is
    /// byte for byte the TPM's own EK public (`TPM2_ReadPublic(0x81010001)`), so the server's `MakeCredential` targets the
    /// right EK name; and the TPM's own `TPM2_MakeCredential` output has the layout `make_credential` produces.
    #[test]
    fn ek_template_matches_the_tpms_ek_when_available() {
        let Some(k) = test_key("EkKey") else { return };
        let ek = match TpmDeviceKey::ek_public(&k) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("SKIP: no RSA EK here: {e}");
                let _ = k.destroy();
                return;
            }
        };
        let read_public = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x73, 0x81, 0x01, 0x00, 0x01];
        match tbs(&read_public) {
            Some(r) if r.len() > 12 && r[6..10] == [0, 0, 0, 0] => {
                let n = u16::from_be_bytes([r[10], r[11]]) as usize;
                assert_eq!(&r[10..12 + n], &ek[..], "rebuilt EK public == TPM2_ReadPublic(EK)");
                // TPM2_MakeCredential on the TPM: same structure sizes as the client's (the server's) implementation
                let name = attest::TpmPublic::parse(&ek).unwrap().name().unwrap();
                let mut body = vec![0x81, 0x01, 0x00, 0x01, 0x00, 0x20];
                body.extend_from_slice(&[0x5c; 32]);
                body.extend_from_slice(&(name.len() as u16).to_be_bytes());
                body.extend_from_slice(&name);
                let mut c = vec![0x80, 0x01];
                c.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
                c.extend_from_slice(&0x0000_0168u32.to_be_bytes());
                c.extend_from_slice(&body);
                if let Some(r) = tbs(&c).filter(|r| r.len() > 10 && r[6..10] == [0, 0, 0, 0]) {
                    let (ours_cred, ours_secret) = attest::make_credential(&ek, &name, &[0x5c; 32], &[1; 32]);
                    let n1 = u16::from_be_bytes([r[10], r[11]]) as usize;
                    let n2 = u16::from_be_bytes([r[12 + n1], r[13 + n1]]) as usize;
                    assert_eq!((n1 + 2, n2 + 2), (ours_cred.len(), ours_secret.len()));
                }
            }
            _ => eprintln!("SKIP: TPM2_ReadPublic not available through TBS here"),
        }
        k.destroy().unwrap();
    }
}
