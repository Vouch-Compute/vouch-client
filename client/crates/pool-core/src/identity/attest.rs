//! `tpm2` key-attestation blob **v2** (contract 2.1.0):
//!
//! ```text
//! key_attestation.blob = base64( CBOR { "v": 2, "ek_public": bstr, ? "ek_cert": bstr, "aik_public": bstr,
//!                                       "certify_info": bstr, "certify_sig": bstr, "activation": bstr .size 32 } )
//! ```
//!
//! * `ek_public`, `aik_public`: `TPM2B_PUBLIC`. the server runs `TPM2_MakeCredential(ek_public, name(aik_public), secret)`
//!   for `POST /v1/devices/enrollment-challenges {tpm}`; only the TPM holding that EK can recover `secret` with
//!   `TPM2_ActivateCredential`, which proves the AIK lives in that TPM.
//! * `certify_info`: TPMS_ATTEST of TPM2_Certify of the device key by the AIK, `qualifyingData = SHA-256(nonce)`.
//! * `certify_sig`: a `TPMT_SIGNATURE` in TPM wire format. Windows' provider returns the bare signature bytes, which
//!   [`wrap_certify_sig`] wraps after checking the length against the AIK, and [`verify_certify`] checks locally
//!   against `aik_public` before anything is sent.
//! * `activation = HMAC-SHA-256(secret, "pool/tpm-activate/v1" || challenge_id as 16 bytes)`.
//!
//! **The "64-byte RSA-AIK signature" finding (security review of M6B-prep).** The real claim in
//! `tests/data/ncrypt-claim-kast.bin` was certified by an **ECC P-256** AIK (restricted signing key, scheme ECDSA with
//! SHA-1): its `TPM2B_PUBLIC` is the first field of the KAST "authority" section, and the 64 bytes are that key's
//! ECDSA `r || s`, which verify over the certify statement (unit test `fixture_certify_sig_verifies_against_aik_public`).
//! The bytes were never an RSA signature. The rule is now enforced both ways: an RSA AIK signature must be exactly
//! the modulus length (256 bytes for RSA-2048), an ECC one exactly `2 x` the coordinate size, and nothing is sent
//! unless it verifies under `aik_public`.
//!
//! On Windows, `NCryptCreateClaim(NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT)` returns a `KAST` statement:
//!
//! ```text
//! u32 LE: magic 'KAST', version 1, platform 2 (TPM 2.0), header size 28, len_a, len_b, len_c
//! [len_a] authority (AIK) identity binding: TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_ATTEST, TPMT_SIGNATURE
//! [len_b] 'KADS' PCP key attestation blob: u32 LE magic, platform, header size, cbKeyAttest, cbSignature,
//!         cbKeyBlob, then TPMS_ATTEST (TPM_ST_ATTEST_CERTIFY, extraData = SHA-256(nonce)), signature, subject key blob
//! [len_c] 'PCPM' key blob of the authority (AIK)
//! ```
//!
//! This file is platform-neutral, so parsing, wrapping, verification and encoding are unit-tested everywhere.

use sha2::Digest;

/// `TPM_GENERATED_VALUE` (`0xff 'T' 'C' 'G'`), the first field of every TPMS_ATTEST.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_CERTIFY`.
pub const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_SHA256: u16 = 0x000b;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_CFB: u16 = 0x0043;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

/// TPMA_OBJECT bits the server checks.
pub const TPMA_FIXED_TPM: u32 = 1 << 1;
pub const TPMA_FIXED_PARENT: u32 = 1 << 4;
pub const TPMA_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPMA_RESTRICTED: u32 = 1 << 16;
pub const TPMA_SIGN: u32 = 1 << 18;

/// Domain separation for the activation proof.
pub const ACTIVATION_LABEL: &[u8] = b"pool/tpm-activate/v1";

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("tpm2 attestation: {0}")]
pub struct AttestError(pub String);

fn e(s: impl Into<String>) -> AttestError {
    AttestError(s.into())
}

// ------------------------------------------------------------------ TPM wire format reader

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestError> {
        let s = self.b.get(self.p..self.p.checked_add(n).ok_or_else(|| e("length overflow"))?).ok_or_else(|| e("truncated TPM structure"))?;
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, AttestError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, AttestError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], AttestError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.p == self.b.len()
    }
}

fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut v = (data.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

// ------------------------------------------------------------------ TPM2B_PUBLIC

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmKey {
    Rsa { modulus: Vec<u8>, exponent: u32 },
    Ecc { curve: u16, x: Vec<u8>, y: Vec<u8> },
}

/// A parsed `TPM2B_PUBLIC` (RSA or ECC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPublic {
    pub name_alg: u16,
    pub attributes: u32,
    /// The signing scheme's hash for restricted signing keys (`None` = scheme NULL).
    pub scheme: Option<(u16, u16)>,
    pub key: TpmKey,
    /// The marshalled TPMT_PUBLIC (without the 2-byte size), input of the TPM name.
    pub tpmt: Vec<u8>,
}

impl TpmPublic {
    /// Parse a `TPM2B_PUBLIC` (with its size prefix); trailing bytes are an error.
    pub fn parse(tpm2b_public: &[u8]) -> Result<Self, AttestError> {
        let mut outer = Rd::new(tpm2b_public);
        let tpmt = outer.tpm2b()?;
        if !outer.done() {
            return Err(e("bytes after TPM2B_PUBLIC"));
        }
        let mut r = Rd::new(tpmt);
        let ty = r.u16()?;
        let name_alg = r.u16()?;
        let attributes = r.u32()?;
        r.tpm2b()?; // authPolicy
        let sym = r.u16()?;
        if sym != TPM_ALG_NULL {
            r.u16()?; // keyBits
            r.u16()?; // mode
        }
        let scheme_alg = r.u16()?;
        let scheme = if scheme_alg != TPM_ALG_NULL { Some((scheme_alg, r.u16()?)) } else { None };
        let key = match ty {
            TPM_ALG_RSA => {
                let _bits = r.u16()?;
                let exponent = match r.u32()? {
                    0 => 65537,
                    x => x,
                };
                TpmKey::Rsa { modulus: r.tpm2b()?.to_vec(), exponent }
            }
            TPM_ALG_ECC => {
                let curve = r.u16()?;
                let kdf = r.u16()?;
                if kdf != TPM_ALG_NULL {
                    r.u16()?;
                }
                let x = r.tpm2b()?.to_vec();
                let y = r.tpm2b()?.to_vec();
                TpmKey::Ecc { curve, x, y }
            }
            other => return Err(e(format!("unsupported TPM key type {other:#06x}"))),
        };
        if !r.done() {
            return Err(e("bytes after TPMT_PUBLIC"));
        }
        Ok(Self { name_alg, attributes, scheme, key, tpmt: tpmt.to_vec() })
    }

    /// TPM name: `nameAlg || H_nameAlg(TPMT_PUBLIC)`.
    pub fn name(&self) -> Result<Vec<u8>, AttestError> {
        let mut n = self.name_alg.to_be_bytes().to_vec();
        match self.name_alg {
            TPM_ALG_SHA256 => n.extend_from_slice(&sha2::Sha256::digest(&self.tpmt)),
            TPM_ALG_SHA1 => n.extend_from_slice(&sha1::Sha1::digest(&self.tpmt)),
            other => return Err(e(format!("unsupported nameAlg {other:#06x}"))),
        }
        Ok(n)
    }

    /// The P-256 key, for an ECC NIST P-256 public.
    pub fn p256(&self) -> Result<p256::ecdsa::VerifyingKey, AttestError> {
        match &self.key {
            TpmKey::Ecc { curve: TPM_ECC_NIST_P256, x, y } if x.len() == 32 && y.len() == 32 => {
                let mut sec1 = vec![0x04];
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                pool_proto::keys::from_sec1(&sec1).map_err(|x| e(x.to_string()))
            }
            _ => Err(e("not an ECC NIST P-256 key")),
        }
    }

    /// Signature length the key produces as raw bytes: the modulus for RSA, `2 x` the coordinate for ECC.
    pub fn raw_signature_len(&self) -> usize {
        match &self.key {
            TpmKey::Rsa { modulus, .. } => modulus.len(),
            TpmKey::Ecc { x, .. } => 2 * x.len(),
        }
    }
}

/// The SHA-256 of the `TPM2B_PUBLIC` bytes: `HwIdentifiers.ek_pub_sha256` (self-reported; the same bytes are the v2
/// blob's `ek_public`, so the server can compare it once the activation verified the EK).
pub fn ek_pub_sha256(ek_tpm2b_public: &[u8]) -> [u8; 32] {
    pool_proto::sha256(ek_tpm2b_public)
}

/// The default RSA-2048 EK template of the TCG EK Credential Profile (template L-1), filled with the EK's modulus:
/// the `TPM2B_PUBLIC` the server uses for `TPM2_MakeCredential`. Windows exposes the EK only as an RSA public key
/// (`PCP_EKPUB`), so the structure is rebuilt; a wrong rebuild changes the EK name and the activation fails.
pub fn rsa_ek_template_public(modulus: &[u8], exponent: u32) -> Result<Vec<u8>, AttestError> {
    if modulus.len() != 256 {
        return Err(e(format!("EK modulus is {} bytes, expected RSA-2048", modulus.len())));
    }
    if exponent != 65537 {
        return Err(e("EK exponent is not 65537 (non-default EK template)"));
    }
    const EK_POLICY: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b,
        0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    ];
    let mut t = Vec::with_capacity(314);
    t.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    t.extend_from_slice(&0x0003_00b2u32.to_be_bytes()); // fixedTPM fixedParent sensitiveDataOrigin adminWithPolicy restricted decrypt
    t.extend_from_slice(&tpm2b(&EK_POLICY));
    t.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    t.extend_from_slice(&128u16.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    t.extend_from_slice(&2048u16.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes()); // exponent 0 = 65537
    t.extend_from_slice(&tpm2b(modulus));
    Ok(tpm2b(&t))
}

// ------------------------------------------------------------------ TPMS_ATTEST (certify)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifyInfo {
    pub extra_data: Vec<u8>,
    /// Name of the certified object (the device key).
    pub name: Vec<u8>,
}

pub fn parse_certify_info(attest: &[u8]) -> Result<CertifyInfo, AttestError> {
    let mut r = Rd::new(attest);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err(e("TPMS_ATTEST magic is not TPM_GENERATED_VALUE"));
    }
    if r.u16()? != TPM_ST_ATTEST_CERTIFY {
        return Err(e("TPMS_ATTEST is not a certify statement"));
    }
    r.tpm2b()?; // qualifiedSigner
    let extra_data = r.tpm2b()?.to_vec();
    r.take(17)?; // clockInfo
    r.take(8)?; // firmwareVersion
    let name = r.tpm2b()?.to_vec();
    r.tpm2b()?; // qualifiedName
    if !r.done() {
        return Err(e("bytes after TPMS_ATTEST"));
    }
    Ok(CertifyInfo { extra_data, name })
}

/// `extraData` (= qualifyingData) of a TPMS_ATTEST from TPM2_Certify.
pub fn certify_extra_data(attest: &[u8]) -> Result<Vec<u8>, AttestError> {
    let mut r = Rd::new(attest);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err(e("TPMS_ATTEST magic is not TPM_GENERATED_VALUE"));
    }
    if r.u16()? != TPM_ST_ATTEST_CERTIFY {
        return Err(e("TPMS_ATTEST is not a certify statement"));
    }
    r.tpm2b()?;
    Ok(r.tpm2b()?.to_vec())
}

/// `qualifyingData` the server expects: SHA-256 of the 32-byte enrollment nonce.
pub fn qualifying_data(nonce: &[u8]) -> [u8; 32] {
    pool_proto::sha256(nonce)
}

// ------------------------------------------------------------------ TPMT_SIGNATURE

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmSignature {
    Rsa { scheme: u16, hash: u16, sig: Vec<u8> },
    Ecdsa { hash: u16, r: Vec<u8>, s: Vec<u8> },
}

impl TpmSignature {
    pub fn parse(b: &[u8]) -> Result<Self, AttestError> {
        let mut rd = Rd::new(b);
        let alg = rd.u16()?;
        let hash = rd.u16()?;
        let s = match alg {
            TPM_ALG_RSASSA | TPM_ALG_RSAPSS => TpmSignature::Rsa { scheme: alg, hash, sig: rd.tpm2b()?.to_vec() },
            TPM_ALG_ECDSA => TpmSignature::Ecdsa { hash, r: rd.tpm2b()?.to_vec(), s: rd.tpm2b()?.to_vec() },
            other => return Err(e(format!("unsupported signature algorithm {other:#06x}"))),
        };
        if !rd.done() {
            return Err(e("bytes after TPMT_SIGNATURE"));
        }
        Ok(s)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TpmSignature::Rsa { scheme, hash, sig } => [&scheme.to_be_bytes()[..], &hash.to_be_bytes(), &tpm2b(sig)].concat(),
            TpmSignature::Ecdsa { hash, r, s } => [&TPM_ALG_ECDSA.to_be_bytes()[..], &hash.to_be_bytes(), &tpm2b(r), &tpm2b(s)].concat(),
        }
    }
}

/// `certify_sig` as a `TPMT_SIGNATURE` for `aik`: a signature that already is one (and matches the key type) is kept;
/// bare platform bytes are wrapped with the AIK's scheme hash, after checking their length against the key: an RSA
/// AIK's signature is exactly its modulus (256 bytes for RSA-2048), an ECC AIK's is `r || s`.
pub fn wrap_certify_sig(aik: &TpmPublic, raw: &[u8]) -> Result<Vec<u8>, AttestError> {
    if let Ok(sig) = TpmSignature::parse(raw) {
        let kind_ok = matches!((&sig, &aik.key), (TpmSignature::Rsa { .. }, TpmKey::Rsa { .. }) | (TpmSignature::Ecdsa { .. }, TpmKey::Ecc { .. }));
        if kind_ok {
            return Ok(sig.to_bytes());
        }
    }
    let hash = aik.scheme.map(|(_, h)| h).unwrap_or(TPM_ALG_SHA256);
    let want = aik.raw_signature_len();
    if raw.len() != want {
        let what = match &aik.key {
            TpmKey::Rsa { modulus, .. } => format!("RSA-{} AIK signature must be {} bytes", modulus.len() * 8, want),
            TpmKey::Ecc { .. } => format!("ECC AIK signature must be {want} bytes (r || s)"),
        };
        return Err(e(format!("{what}, the platform returned {}", raw.len())));
    }
    Ok(match &aik.key {
        TpmKey::Rsa { .. } => {
            let scheme = aik.scheme.map(|(s, _)| s).unwrap_or(TPM_ALG_RSASSA);
            TpmSignature::Rsa { scheme, hash, sig: raw.to_vec() }
        }
        TpmKey::Ecc { .. } => TpmSignature::Ecdsa { hash, r: raw[..want / 2].to_vec(), s: raw[want / 2..].to_vec() },
    }
    .to_bytes())
}

fn digest(hash: u16, msg: &[u8]) -> Result<Vec<u8>, AttestError> {
    Ok(match hash {
        TPM_ALG_SHA256 => sha2::Sha256::digest(msg).to_vec(),
        TPM_ALG_SHA1 => sha1::Sha1::digest(msg).to_vec(),
        other => return Err(e(format!("unsupported hash {other:#06x}"))),
    })
}

/// Verify a `TPMT_SIGNATURE` over `certify_info` with `aik` (what the server does; the client checks before sending).
pub fn verify_certify(aik: &TpmPublic, certify_info: &[u8], tpmt_signature: &[u8]) -> Result<(), AttestError> {
    match (TpmSignature::parse(tpmt_signature)?, &aik.key) {
        (TpmSignature::Ecdsa { hash, r, s }, TpmKey::Ecc { .. }) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let vk = aik.p256()?;
            let mut rs = [0u8; 64];
            if r.len() > 32 || s.len() > 32 {
                return Err(e("ECDSA r or s too long"));
            }
            rs[32 - r.len()..32].copy_from_slice(&r);
            rs[64 - s.len()..].copy_from_slice(&s);
            let sig = p256::ecdsa::Signature::from_slice(&rs).map_err(|x| e(x.to_string()))?;
            vk.verify_prehash(&digest(hash, certify_info)?, &sig).map_err(|_| e("certify_sig does not verify under aik_public"))
        }
        (TpmSignature::Rsa { scheme, hash, sig }, TpmKey::Rsa { modulus, exponent }) => {
            if sig.len() != modulus.len() {
                return Err(e(format!("RSA signature is {} bytes, the AIK modulus {}", sig.len(), modulus.len())));
            }
            let key = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(modulus), rsa::BigUint::from(*exponent)).map_err(|x| e(x.to_string()))?;
            let d = digest(hash, certify_info)?;
            let r = match (scheme, hash) {
                (TPM_ALG_RSASSA, TPM_ALG_SHA256) => key.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &d, &sig),
                (TPM_ALG_RSASSA, TPM_ALG_SHA1) => key.verify(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), &d, &sig),
                (TPM_ALG_RSAPSS, TPM_ALG_SHA256) => key.verify(rsa::Pss::new::<sha2::Sha256>(), &d, &sig),
                _ => return Err(e("unsupported RSA signature scheme")),
            };
            r.map_err(|_| e("certify_sig does not verify under aik_public"))
        }
        _ => Err(e("signature algorithm does not match the AIK key type")),
    }
}

// ------------------------------------------------------------------ activation and the v2 blob

/// `activation = HMAC-SHA-256(secret, "pool/tpm-activate/v1" || challenge_id as 16 bytes)`.
pub fn activation_hmac(secret: &[u8], challenge_id: &str) -> Result<[u8; 32], AttestError> {
    use hmac::Mac;
    let id = uuid::Uuid::parse_str(challenge_id).map_err(|_| e("challenge_id is not a uuid"))?;
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).map_err(|x| e(x.to_string()))?;
    m.update(ACTIVATION_LABEL);
    m.update(id.as_bytes());
    Ok(m.finalize().into_bytes().into())
}

/// `tpm_activation` from the enrollment challenge. the server's base64 values may carry the TPM2B size prefix or not;
/// both are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmActivation {
    pub credential_blob: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

impl TpmActivation {
    fn as_tpm2b(b: &[u8]) -> Vec<u8> {
        if b.len() >= 2 && u16::from_be_bytes([b[0], b[1]]) as usize == b.len() - 2 {
            b.to_vec()
        } else {
            tpm2b(b)
        }
    }
    /// `TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET`, the input of the PCP identity-activation property.
    pub fn pcp_activation_blob(&self) -> Vec<u8> {
        [Self::as_tpm2b(&self.credential_blob), Self::as_tpm2b(&self.encrypted_secret)].concat()
    }
}

/// The public halves an enrollment needs (`POST /v1/devices/enrollment-challenges {tpm}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPublics {
    pub ek_public: Vec<u8>,
    pub ek_cert: Option<Vec<u8>>,
    pub aik_public: Vec<u8>,
}

/// `(certify_info, raw signature, device key TPM2B_PUBLIC if the platform exposes it)`.
pub type CertifyOutput = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// What a TPM-backed device key can do for the v2 flow (Windows: `tpm.rs`; tests: a fake).
pub trait TpmAttester: Send + Sync {
    fn publics(&self) -> anyhow::Result<TpmPublics>;
    /// The EK's TPM2B_PUBLIC only (no AIK is created): `HwIdentifiers.ek_pub_sha256` is its SHA-256.
    fn ek_public(&self) -> anyhow::Result<Vec<u8>>;
    /// `TPM2_ActivateCredential` with the AIK: returns the secret the server sealed to the EK.
    fn activate(&self, activation: &TpmActivation) -> anyhow::Result<Vec<u8>>;
    /// TPM2_Certify of the device key by the AIK over `qualifying_data(nonce)`:
    /// `(certify_info, raw signature, device key TPM2B_PUBLIC if the platform exposes it)`.
    fn certify(&self, nonce: &[u8; 32]) -> anyhow::Result<CertifyOutput>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2AttestationV2 {
    pub ek_public: Vec<u8>,
    pub ek_cert: Option<Vec<u8>>,
    pub aik_public: Vec<u8>,
    pub certify_info: Vec<u8>,
    pub certify_sig: Vec<u8>,
    pub activation: [u8; 32],
}

impl Tpm2AttestationV2 {
    /// Deterministic CBOR of the closed v2 map.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut m = pool_proto::cbor::MapBuilder::default()
            .uint("v", 2)
            .bytes("ek_public", &self.ek_public)
            .bytes("aik_public", &self.aik_public)
            .bytes("certify_info", &self.certify_info)
            .bytes("certify_sig", &self.certify_sig)
            .bytes("activation", &self.activation);
        if let Some(c) = &self.ek_cert {
            m = m.bytes("ek_cert", c);
        }
        pool_proto::cbor::encode(&m.build())
    }

    pub fn from_cbor(b: &[u8]) -> Result<Self, AttestError> {
        let v = pool_proto::cbor::decode_deterministic(b).map_err(|x| e(x.to_string()))?;
        let r = pool_proto::cbor::MapReader::new(&v, &["v", "ek_public", "aik_public", "certify_info", "certify_sig", "activation"], &["ek_cert"])
            .map_err(|x| e(x.to_string()))?;
        if r.uint("v").map_err(|x| e(x.to_string()))? != 2 {
            return Err(e("not a v2 blob"));
        }
        let b = |k: &str| r.bytes(k).map_err(|x| e(x.to_string()));
        Ok(Self {
            ek_public: b("ek_public")?,
            ek_cert: r.get("ek_cert").map(|_| b("ek_cert")).transpose()?,
            aik_public: b("aik_public")?,
            certify_info: b("certify_info")?,
            certify_sig: b("certify_sig")?,
            activation: r.bytes_n("activation").map_err(|x| e(x.to_string()))?,
        })
    }
}

/// Check that a certify statement is about `device_spki`: when the platform gave the device key's TPM2B_PUBLIC, its
/// name must be the certified name, its point the SPKI's, and its attributes `fixedTPM` + `sensitiveDataOrigin`.
pub fn check_certified_key(info: &CertifyInfo, device_public: Option<&[u8]>, device_spki: &[u8]) -> Result<(), AttestError> {
    let Some(p) = device_public else { return Ok(()) };
    let pubk = TpmPublic::parse(p)?;
    if pubk.name()? != info.name {
        return Err(e("certified name is not the device key's name"));
    }
    let vk = pool_proto::keys::parse_spki(device_spki).map_err(|x| e(x.to_string()))?;
    if pubk.p256()? != vk {
        return Err(e("certified key is not the enrolled device key"));
    }
    let need = TPMA_FIXED_TPM | TPMA_SENSITIVE_DATA_ORIGIN;
    if pubk.attributes & need != need {
        return Err(e("device key lacks fixedTPM / sensitiveDataOrigin"));
    }
    Ok(())
}

/// Build the v2 blob: activate the credential, certify the device key, wrap `certify_sig` and check everything
/// locally (qualifying data, certified key, signature under `aik_public`) before it is sent.
pub fn build_v2(
    tpm: &dyn TpmAttester,
    publics: &TpmPublics,
    challenge_id: &str,
    nonce: &[u8; 32],
    activation: &TpmActivation,
    device_spki: &[u8],
) -> anyhow::Result<Tpm2AttestationV2> {
    let aik = TpmPublic::parse(&publics.aik_public)?;
    let restricted_sign = TPMA_RESTRICTED | TPMA_SIGN | TPMA_FIXED_TPM | TPMA_FIXED_PARENT;
    if aik.attributes & restricted_sign != restricted_sign {
        anyhow::bail!("the AIK is not a restricted fixedTPM/fixedParent signing key");
    }
    let secret = tpm.activate(activation)?;
    let (certify_info, raw_sig, device_public) = tpm.certify(nonce)?;
    let info = parse_certify_info(&certify_info)?;
    if info.extra_data != qualifying_data(nonce) {
        anyhow::bail!("TPMS_ATTEST.extraData is not SHA-256(nonce)");
    }
    check_certified_key(&info, device_public.as_deref(), device_spki)?;
    let certify_sig = wrap_certify_sig(&aik, &raw_sig)?;
    verify_certify(&aik, &certify_info, &certify_sig)?;
    Ok(Tpm2AttestationV2 {
        ek_public: publics.ek_public.clone(),
        ek_cert: publics.ek_cert.clone(),
        aik_public: publics.aik_public.clone(),
        certify_info,
        certify_sig,
        activation: activation_hmac(&secret, challenge_id)?,
    })
}

/// The checks a dev server makes on a v2 blob, given the secret it sealed (used by the tests; the server's own verifier is
/// task M9-V-*). The EK chain check is the server's alone (it gives a capped ceiling when the chain is unverifiable).
pub fn verify_v2(blob: &[u8], challenge_id: &str, nonce: &[u8; 32], secret: &[u8], ek_public: &[u8]) -> Result<Tpm2AttestationV2, AttestError> {
    let a = Tpm2AttestationV2::from_cbor(blob)?;
    if a.ek_public != ek_public {
        return Err(e("ek_public is not the EK the credential was made for"));
    }
    if a.activation != activation_hmac(secret, challenge_id)? {
        return Err(e("activation HMAC does not match"));
    }
    let aik = TpmPublic::parse(&a.aik_public)?;
    let info = parse_certify_info(&a.certify_info)?;
    if info.extra_data != qualifying_data(nonce) {
        return Err(e("extraData is not SHA-256(nonce)"));
    }
    verify_certify(&aik, &a.certify_info, &a.certify_sig)?;
    Ok(a)
}

// ------------------------------------------------------------------ Windows PCP containers

/// The parts of a `PCP_KEY_ATTESTATION_BLOB` (header: Magic, Platform, HeaderSize, cbKeyAttest, cbSignature,
/// cbKeyBlob, all little-endian u32; then the three byte ranges).
#[derive(Debug, Clone, PartialEq)]
pub struct PcpKeyAttestation {
    pub platform: u32,
    pub key_attest: Vec<u8>,
    pub signature: Vec<u8>,
    pub key_blob: Vec<u8>,
}

/// `'KADS'` (bytes `4b 41 44 53`) as written by the Platform Crypto Provider.
pub const PCP_KEY_ATTESTATION_MAGIC: u32 = 0x5344_414b;
/// `'KAST'` (bytes `4b 41 53 54`): the key attestation statement `NCryptCreateClaim` returns on Windows 11.
pub const KEY_ATTESTATION_STATEMENT_MAGIC: u32 = 0x5453_414b;
/// `'PCPM'`: a PCP key blob (`PCP_KEY_BLOB_WIN8`).
pub const PCP_KEY_BLOB_MAGIC: u32 = 0x4d50_4350;

/// A parsed `KAST` statement: the AIK's identity binding, the certify blob, the AIK's key blob.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyAttestationStatement {
    pub authority_binding: Vec<u8>,
    pub certify: PcpKeyAttestation,
    pub authority_key_blob: Vec<u8>,
}

impl KeyAttestationStatement {
    /// The AIK's TPM2B_PUBLIC: the first field of its identity binding.
    pub fn aik_public(&self) -> Result<Vec<u8>, AttestError> {
        let mut r = Rd::new(&self.authority_binding);
        Ok(tpm2b(r.tpm2b()?))
    }
}

fn le_u32(b: &[u8], i: usize) -> Result<u32, AttestError> {
    b.get(i * 4..i * 4 + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| e("short header"))
}

pub fn parse_kast(b: &[u8]) -> Result<KeyAttestationStatement, AttestError> {
    if le_u32(b, 0)? != KEY_ATTESTATION_STATEMENT_MAGIC {
        return Err(e("not a KAST statement"));
    }
    let header = le_u32(b, 3)? as usize;
    let lens = [le_u32(b, 4)? as usize, le_u32(b, 5)? as usize, le_u32(b, 6)? as usize];
    if header < 28 || lens.iter().try_fold(header, |acc, l| acc.checked_add(*l)) != Some(b.len()) {
        return Err(e("KAST sizes do not add up"));
    }
    let a = &b[header..header + lens[0]];
    let kads = &b[header + lens[0]..header + lens[0] + lens[1]];
    let c = &b[header + lens[0] + lens[1]..];
    Ok(KeyAttestationStatement { authority_binding: a.to_vec(), certify: parse_pcp_key_attestation(kads)?, authority_key_blob: c.to_vec() })
}

/// The `KADS` certify blob from an `NCryptCreateClaim(NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT)` output: inside a `KAST`
/// statement or given directly (older providers).
pub fn parse_ncrypt_claim(b: &[u8]) -> Result<PcpKeyAttestation, AttestError> {
    if le_u32(b, 0)? == KEY_ATTESTATION_STATEMENT_MAGIC {
        return parse_kast(b).map(|k| k.certify);
    }
    parse_pcp_key_attestation(b)
}

pub fn parse_pcp_key_attestation(b: &[u8]) -> Result<PcpKeyAttestation, AttestError> {
    let m = le_u32(b, 0)?;
    // the multi-character constant is written either way round by different SDK headers; accept both spellings
    if m != PCP_KEY_ATTESTATION_MAGIC && m != PCP_KEY_ATTESTATION_MAGIC.swap_bytes() {
        return Err(e("not a PCP key attestation blob"));
    }
    let (platform, header, n_att, n_sig, n_key) = (le_u32(b, 1)?, le_u32(b, 2)? as usize, le_u32(b, 3)? as usize, le_u32(b, 4)? as usize, le_u32(b, 5)? as usize);
    if header < 24 || header.checked_add(n_att).and_then(|x| x.checked_add(n_sig)).and_then(|x| x.checked_add(n_key)) != Some(b.len()) {
        return Err(e("PCP blob sizes do not add up"));
    }
    let att = &b[header..header + n_att];
    let sig = &b[header + n_att..header + n_att + n_sig];
    let key = &b[header + n_att + n_sig..];
    Ok(PcpKeyAttestation { platform, key_attest: att.to_vec(), signature: sig.to_vec(), key_blob: key.to_vec() })
}

/// The `TPM2B_PUBLIC` inside a `PCPM` key blob (`PCP_KEY_BLOB_WIN8`: magic, cbHeader, pcpType, flags, cbPublic, ...).
pub fn pcp_key_blob_public(b: &[u8]) -> Result<Vec<u8>, AttestError> {
    if le_u32(b, 0)? != PCP_KEY_BLOB_MAGIC {
        return Err(e("not a PCPM key blob"));
    }
    let header = le_u32(b, 1)? as usize;
    let n = le_u32(b, 4)? as usize;
    let p = b.get(header..header.checked_add(n).ok_or_else(|| e("overflow"))?).ok_or_else(|| e("short PCPM blob"))?;
    TpmPublic::parse(p)?;
    Ok(p.to_vec())
}

// ------------------------------------------------------------------ test support: the server's side of the activation

/// `TPM2_MakeCredential` as the server runs it (RSA EK): `(credential_blob TPM2B_ID_OBJECT, encrypted_secret TPM2B)`.
/// Test support only (unit tests and the live TPM test); the server's implementation is its own.
#[cfg(test)]
pub fn make_credential(ek_public: &[u8], aik_name: &[u8], secret: &[u8], seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use hmac::Mac;
    let ek = TpmPublic::parse(ek_public).unwrap();
    let TpmKey::Rsa { modulus, exponent } = &ek.key else { panic!("RSA EK only") };
    let key = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(modulus), rsa::BigUint::from(*exponent)).unwrap();
    let enc_seed =
        key.encrypt(&mut rand_core::OsRng, rsa::Oaep::new_with_label::<sha2::Sha256, _>("IDENTITY\0"), seed).unwrap();
    let sym = kdfa(seed, b"STORAGE", aik_name, &[], 128);
    let plain = tpm2b(secret);
    // AES-128-CFB, IV = 0, full-block feedback (the EK template's symmetric definition)
    let aes = aes::Aes128::new_from_slice(&sym).unwrap();
    let mut iv = [0u8; 16];
    let mut enc = Vec::with_capacity(plain.len());
    for chunk in plain.chunks(16) {
        let mut block = aes::Block::from(iv);
        aes.encrypt_block(&mut block);
        let c: Vec<u8> = chunk.iter().zip(block.iter()).map(|(p, k)| p ^ k).collect();
        if c.len() == 16 {
            iv.copy_from_slice(&c);
        }
        enc.extend_from_slice(&c);
    }
    let hkey = kdfa(seed, b"INTEGRITY", &[], &[], 256);
    let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&hkey).unwrap();
    m.update(&enc);
    m.update(aik_name);
    let integrity = m.finalize().into_bytes();
    let id_object = [tpm2b(&integrity), enc].concat();
    (tpm2b(&id_object), tpm2b(&enc_seed))
}

/// KDFa (TPM 2.0 part 1, 11.4.10.2) with SHA-256.
#[cfg(test)]
fn kdfa(key: &[u8], label: &[u8], ctx_u: &[u8], ctx_v: &[u8], bits: u32) -> Vec<u8> {
    use hmac::Mac;
    let mut out = Vec::new();
    let mut i = 1u32;
    while out.len() * 8 < bits as usize {
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        m.update(&i.to_be_bytes());
        m.update(label);
        m.update(&[0]);
        m.update(ctx_u);
        m.update(ctx_v);
        m.update(&bits.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
        i += 1;
    }
    out.truncate(bits as usize / 8);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    const KAST: &[u8] = include_bytes!("../../tests/data/ncrypt-claim-kast.bin");

    fn tpms_attest_certify(extra: &[u8], name: &[u8]) -> Vec<u8> {
        let mut v = TPM_GENERATED_VALUE.to_be_bytes().to_vec();
        v.extend_from_slice(&TPM_ST_ATTEST_CERTIFY.to_be_bytes());
        v.extend_from_slice(&tpm2b(&[0xAA; 34]));
        v.extend_from_slice(&tpm2b(extra));
        v.extend_from_slice(&[0; 17 + 8]);
        v.extend_from_slice(&tpm2b(name));
        v.extend_from_slice(&tpm2b(&[0xBB; 34]));
        v
    }

    #[test]
    fn parses_pcp_blob_and_certify_extra_data() {
        let qd = qualifying_data(&[7; 32]);
        let att = tpms_attest_certify(&qd, &[0x00, 0x0b, 1, 2]);
        let sig = vec![0x00, 0x14, 0x00, 0x0b, 0x00, 0x02, 0xde, 0xad];
        let key = vec![1, 2, 3];
        let mut blob = Vec::new();
        for x in [PCP_KEY_ATTESTATION_MAGIC, 2, 24, att.len() as u32, sig.len() as u32, key.len() as u32] {
            blob.extend_from_slice(&x.to_le_bytes());
        }
        blob.extend_from_slice(&att);
        blob.extend_from_slice(&sig);
        blob.extend_from_slice(&key);
        let p = parse_pcp_key_attestation(&blob).unwrap();
        assert_eq!((p.platform, &p.key_attest, &p.signature, &p.key_blob), (2, &att, &sig, &key));
        assert_eq!(certify_extra_data(&p.key_attest).unwrap(), qd.to_vec());
        assert_eq!(parse_certify_info(&att).unwrap(), CertifyInfo { extra_data: qd.to_vec(), name: vec![0x00, 0x0b, 1, 2] });
        assert!(parse_pcp_key_attestation(&blob[..blob.len() - 1]).is_err());
        assert!(parse_pcp_key_attestation(&blob[..10]).is_err());
        let mut wrong = blob.clone();
        wrong[0] ^= 1;
        assert!(parse_pcp_key_attestation(&wrong).is_err());
        assert!(certify_extra_data(&att[..12]).is_err());
        let mut quote = att.clone();
        quote[5] = 0x18; // TPM_ST_ATTEST_QUOTE
        assert!(certify_extra_data(&quote).is_err());
    }

    /// A real `NCryptCreateClaim(AUTHORITY_AND_SUBJECT)` output from the M6B-prep machine's firmware TPM, made with
    /// nonce = 32 x 0x5a (test keys, since deleted).
    #[test]
    fn parses_a_real_windows_kast_claim() {
        let k = parse_ncrypt_claim(KAST).unwrap();
        assert_eq!(k.platform, 2);
        assert_eq!(certify_extra_data(&k.key_attest).unwrap(), qualifying_data(&[0x5a; 32]).to_vec());
        // a bare KADS blob is accepted too, and a truncated statement is not
        let kads_start = 28 + u32::from_le_bytes(KAST[16..20].try_into().unwrap()) as usize;
        let kads_len = u32::from_le_bytes(KAST[20..24].try_into().unwrap()) as usize;
        assert_eq!(parse_ncrypt_claim(&KAST[kads_start..kads_start + kads_len]).unwrap(), k);
        assert!(parse_ncrypt_claim(&KAST[..KAST.len() - 1]).is_err());
        assert!(parse_ncrypt_claim(&KAST[..3]).is_err());
    }

    /// Acceptance test: `certify_sig` from the KAST fixture verifies against `aik_public` from the same
    /// fixture. Resolves the "64-byte RSA-AIK signature" finding: the AIK is ECC P-256 (ECDSA/SHA-1 scheme), the 64
    /// bytes are its `r || s`, and they are sent wrapped as a `TPMT_SIGNATURE`.
    #[test]
    fn fixture_certify_sig_verifies_against_aik_public() {
        let st = parse_kast(KAST).unwrap();
        let aik_public = st.aik_public().unwrap();
        let aik = TpmPublic::parse(&aik_public).unwrap();
        assert!(matches!(aik.key, TpmKey::Ecc { curve: TPM_ECC_NIST_P256, .. }), "{:?}", aik.key);
        assert_eq!(aik.scheme, Some((TPM_ALG_ECDSA, TPM_ALG_SHA1)));
        let restricted_sign = TPMA_RESTRICTED | TPMA_SIGN | TPMA_FIXED_TPM | TPMA_FIXED_PARENT;
        assert_eq!(aik.attributes & restricted_sign, restricted_sign);
        // the AIK key blob in section C holds the same public
        assert_eq!(pcp_key_blob_public(&st.authority_key_blob).unwrap(), aik_public);
        let raw = &st.certify.signature;
        assert_eq!(raw.len(), 64);
        let tpmt = wrap_certify_sig(&aik, raw).unwrap();
        assert_eq!(&tpmt[..4], &[0x00, 0x18, 0x00, 0x04], "TPMT_SIGNATURE ECDSA / SHA-1");
        assert_eq!(tpmt.len(), 4 + 2 + 32 + 2 + 32);
        verify_certify(&aik, &st.certify.key_attest, &tpmt).unwrap();
        // already wrapped: kept as it is
        assert_eq!(wrap_certify_sig(&aik, &tpmt).unwrap(), tpmt);
        // one flipped bit in the statement or the signature fails
        let mut bad = st.certify.key_attest.clone();
        bad[40] ^= 1;
        assert!(verify_certify(&aik, &bad, &tpmt).is_err());
        let mut bad_sig = tpmt.clone();
        bad_sig[10] ^= 1;
        assert!(verify_certify(&aik, &st.certify.key_attest, &bad_sig).is_err());
        // the certified object is the subject key in the KADS key blob, a fixedTPM, sensitiveDataOrigin key
        let info = parse_certify_info(&st.certify.key_attest).unwrap();
        let subject = TpmPublic::parse(&pcp_key_blob_public(&st.certify.key_blob).unwrap()).unwrap();
        assert_eq!(subject.name().unwrap(), info.name);
        assert!(subject.p256().is_ok());
        assert_eq!(subject.attributes & (TPMA_FIXED_TPM | TPMA_SENSITIVE_DATA_ORIGIN), TPMA_FIXED_TPM | TPMA_SENSITIVE_DATA_ORIGIN);
        let spki = pool_proto::keys::spki_der(&subject.p256().unwrap());
        check_certified_key(&info, Some(&pcp_key_blob_public(&st.certify.key_blob).unwrap()), &spki).unwrap();
        let other = pool_proto::keys::SoftwareKey::generate().spki_der();
        assert!(check_certified_key(&info, Some(&pcp_key_blob_public(&st.certify.key_blob).unwrap()), &other).is_err());
    }

    /// A throwaway RSA-2048 key, generated once per test process (no private key is stored in the repository).
    fn rsa_aik() -> (rsa::RsaPrivateKey, Vec<u8>) {
        use rsa::traits::PublicKeyParts;
        static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
        let k = KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap()).clone();
        let mut t = Vec::new();
        t.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        t.extend_from_slice(&(TPMA_RESTRICTED | TPMA_SIGN | TPMA_FIXED_TPM | TPMA_FIXED_PARENT | TPMA_SENSITIVE_DATA_ORIGIN).to_be_bytes());
        t.extend_from_slice(&tpm2b(&[]));
        t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        t.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
        t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        t.extend_from_slice(&2048u16.to_be_bytes());
        t.extend_from_slice(&0u32.to_be_bytes());
        t.extend_from_slice(&tpm2b(&k.n().to_bytes_be()));
        (k, tpm2b(&t))
    }

    /// An RSA-2048 AIK signs 256 bytes. A 64-byte "signature" is refused before anything is sent.
    #[test]
    fn rsa_aik_signatures_are_256_bytes() {
        let (k, public) = rsa_aik();
        let aik = TpmPublic::parse(&public).unwrap();
        assert_eq!(aik.raw_signature_len(), 256);
        let info = tpms_attest_certify(&qualifying_data(&[1; 32]), &[0, 0x0b, 9]);
        let err = wrap_certify_sig(&aik, &[7u8; 64]).unwrap_err();
        assert!(err.0.contains("RSA-2048 AIK signature must be 256 bytes"), "{err}");
        let sig = k.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &sha2::Sha256::digest(&info)).unwrap();
        assert_eq!(sig.len(), 256);
        let tpmt = wrap_certify_sig(&aik, &sig).unwrap();
        assert_eq!(&tpmt[..6], &[0x00, 0x14, 0x00, 0x0b, 0x01, 0x00], "TPMT_SIGNATURE RSASSA / SHA-256, 256 bytes");
        verify_certify(&aik, &info, &tpmt).unwrap();
        let mut other = info.clone();
        other[8] ^= 1;
        assert!(verify_certify(&aik, &other, &tpmt).is_err());
    }

    #[test]
    fn ek_template_and_name_and_activation_roundtrip() {
        use rsa::traits::PublicKeyParts;
        let (ek_priv, _) = rsa_aik();
        let ek_public = rsa_ek_template_public(&ek_priv.n().to_bytes_be(), 65537).unwrap();
        assert_eq!(ek_public.len(), 2 + 0x013a, "TCG RSA-2048 EK TPM2B_PUBLIC is 314 + 2 bytes");
        let ek = TpmPublic::parse(&ek_public).unwrap();
        assert_eq!(ek.attributes, 0x0003_00b2);
        assert!(rsa_ek_template_public(&[1; 128], 65537).is_err());
        // the server's MakeCredential, then the TPM's ActivateCredential done in software with the EK private key
        let aik_public = parse_kast(KAST).unwrap().aik_public().unwrap();
        let name = TpmPublic::parse(&aik_public).unwrap().name().unwrap();
        let secret = [0x42u8; 32];
        let (cred, enc_secret) = make_credential(&ek_public, &name, &secret, &[9; 32]);
        let mut rd = Rd::new(&enc_secret);
        let seed = ek_priv.decrypt(rsa::Oaep::new_with_label::<sha2::Sha256, _>("IDENTITY\0"), rd.tpm2b().unwrap()).unwrap();
        assert_eq!(seed, [9; 32]);
        let act = TpmActivation { credential_blob: cred.clone(), encrypted_secret: enc_secret.clone() };
        let blob = act.pcp_activation_blob();
        assert_eq!(blob, [cred.clone(), enc_secret.clone()].concat(), "TPM2B values are not wrapped twice");
        let bare = TpmActivation { credential_blob: cred[2..].to_vec(), encrypted_secret: enc_secret[2..].to_vec() };
        assert_eq!(bare.pcp_activation_blob(), blob, "bare values get their TPM2B size");
        let id = "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e";
        let h = activation_hmac(&secret, id).unwrap();
        assert_ne!(h, activation_hmac(&secret, "1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e").unwrap());
        assert!(activation_hmac(&secret, "not-a-uuid").is_err());
    }

    struct FakeTpm;
    impl TpmAttester for FakeTpm {
        fn publics(&self) -> anyhow::Result<TpmPublics> {
            unreachable!()
        }
        fn ek_public(&self) -> anyhow::Result<Vec<u8>> {
            unreachable!()
        }
        fn activate(&self, _a: &TpmActivation) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0x42; 32])
        }
        fn certify(&self, nonce: &[u8; 32]) -> anyhow::Result<CertifyOutput> {
            assert_eq!(nonce, &[0x5a; 32]);
            let st = parse_kast(KAST).unwrap();
            Ok((st.certify.key_attest.clone(), st.certify.signature.clone(), Some(pcp_key_blob_public(&st.certify.key_blob).unwrap())))
        }
    }

    #[test]
    fn v2_blob_is_the_closed_map_vault_parses_and_verifies() {
        use rsa::traits::PublicKeyParts;
        let st = parse_kast(KAST).unwrap();
        let subject = TpmPublic::parse(&pcp_key_blob_public(&st.certify.key_blob).unwrap()).unwrap();
        let spki = pool_proto::keys::spki_der(&subject.p256().unwrap());
        let (ek_priv, _) = rsa_aik();
        let ek_public = rsa_ek_template_public(&ek_priv.n().to_bytes_be(), 65537).unwrap();
        let publics = TpmPublics { ek_public: ek_public.clone(), ek_cert: None, aik_public: st.aik_public().unwrap() };
        let id = "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e";
        let act = TpmActivation { credential_blob: vec![1], encrypted_secret: vec![2] };
        let a = build_v2(&FakeTpm, &publics, id, &[0x5a; 32], &act, &spki).unwrap();
        let blob = a.to_cbor();
        let v = pool_proto::cbor::decode_deterministic(&blob).unwrap();
        let Value::Map(m) = &v else { panic!() };
        let keys: Vec<_> = m.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["v", "ek_public", "activation", "aik_public", "certify_sig", "certify_info"]);
        assert_eq!(Tpm2AttestationV2::from_cbor(&blob).unwrap(), a);
        verify_v2(&blob, id, &[0x5a; 32], &[0x42; 32], &ek_public).unwrap();
        assert!(verify_v2(&blob, id, &[0x5a; 32], &[0x43; 32], &ek_public).is_err(), "wrong secret");
        assert!(verify_v2(&blob, id, &[0x5b; 32], &[0x42; 32], &ek_public).is_err(), "wrong nonce");
        // a device key that is not the certified one is refused before sending
        assert!(build_v2(&FakeTpm, &publics, id, &[0x5a; 32], &act, &pool_proto::keys::SoftwareKey::generate().spki_der()).is_err());
        // the v1 map is not a v2 blob
        let v1 = pool_proto::cbor::encode(&pool_proto::cbor::MapBuilder::default().bytes("certify_info", &[1]).bytes("certify_sig", &[2]).build());
        assert!(Tpm2AttestationV2::from_cbor(&v1).is_err());
    }
}
