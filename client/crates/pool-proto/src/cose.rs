//! COSE_Sign1 (RFC 9052, tag 18) with ES256, exactly as `proto/signed-objects.cddl` profiles it:
//! protected header `{1: -7, 4: kid}`, empty unprotected header, empty external AAD, attached payload,
//! payload = deterministic CBOR of one closed claims map with a `type` string.
//! Byte-compatible with the server's Python implementation (cbor2 canonical + cryptography).

use ciborium::value::{Integer, Value};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::{cbor, Error};

pub const ALG_ES256: i64 = -7;
pub const COSE_SIGN1_TAG: u64 = 18;

/// Something that can produce an ES256 signature (raw `r || s`, 64 bytes) over a message.
/// Implemented by the software key and by the TPM-backed key in `pool-core`.
pub trait Es256Signer {
    /// The COSE `kid` (UTF-8 string; device keys use `device_key_id`).
    fn kid(&self) -> String;
    /// Sign `msg` (the signer hashes it with SHA-256).
    fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64], Error>;
}

fn protected_header(kid: &str) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (Value::Integer(Integer::from(1)), Value::Integer(Integer::from(ALG_ES256))),
        (Value::Integer(Integer::from(4)), Value::Bytes(kid.as_bytes().to_vec())),
    ]))
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// Produce a tagged COSE_Sign1 over the deterministic encoding of `claims`.
pub fn sign1(claims: &Value, signer: &dyn Es256Signer) -> Result<Vec<u8>, Error> {
    let protected = protected_header(&signer.kid());
    let payload = cbor::encode(claims);
    let sig = signer.sign_es256(&sig_structure(&protected, &payload))?;
    Ok(cbor::encode(&Value::Tag(
        COSE_SIGN1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(sig.to_vec()),
        ])),
    )))
}

/// COSE_Sign1 whose payload is raw bytes, not a claims map. Was used for the enrollment `nonce_sig` over the raw
/// 32-byte nonce, which contract 2.0.0 deprecates. The agent now signs `objects::EnrollClaims`; this
/// stays only for its unit test until the server drops the old payload. Do not use it for new signatures.
pub fn sign1_raw(payload: &[u8], signer: &dyn Es256Signer) -> Result<Vec<u8>, Error> {
    let protected = protected_header(&signer.kid());
    let sig = signer.sign_es256(&sig_structure(&protected, payload))?;
    Ok(cbor::encode(&Value::Tag(
        COSE_SIGN1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig.to_vec()),
        ])),
    )))
}

/// A parsed (not yet verified) COSE_Sign1.
#[derive(Debug, Clone)]
pub struct Sign1 {
    pub kid: String,
    pub claims: Value,
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl Sign1 {
    /// SHA-256 of the payload bytes (the `model_hash` of a ModelManifest is defined this way).
    pub fn payload_sha256(&self) -> [u8; 32] {
        crate::sha256(&self.payload)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Error> {
        let sig = Signature::from_slice(&self.signature).map_err(|_| Error::BadSignature)?;
        key.verify(&sig_structure(&self.protected, &self.payload), &sig)
            .map_err(|_| Error::BadSignature)
    }

    /// Verify against any of `keys` (used for the two embedded KeySet roots).
    pub fn verify_any(&self, keys: &[VerifyingKey]) -> Result<(), Error> {
        if keys.iter().any(|k| self.verify(k).is_ok()) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

/// Parse a tagged COSE_Sign1, enforcing the profile and determinism, and check the claims `type`.
pub fn parse_sign1(bytes: &[u8], expected_type: &str) -> Result<Sign1, Error> {
    let outer = cbor::decode_any(bytes)?;
    let Value::Tag(COSE_SIGN1_TAG, inner) = outer else {
        return Err(Error::Malformed("not a tagged COSE_Sign1"));
    };
    let Value::Array(arr) = *inner else {
        return Err(Error::Malformed("bad COSE_Sign1 structure"));
    };
    let [Value::Bytes(protected), unprotected, Value::Bytes(payload), Value::Bytes(signature)] =
        <[Value; 4]>::try_from(arr).map_err(|_| Error::Malformed("bad COSE_Sign1 structure"))?
    else {
        return Err(Error::Malformed("bad COSE_Sign1 field types"));
    };
    if unprotected != Value::Map(vec![]) {
        return Err(Error::Malformed("unprotected header must be empty"));
    }
    if signature.len() != 64 {
        return Err(Error::Malformed("bad signature length"));
    }
    let header = cbor::decode_deterministic(&protected)?;
    let Value::Map(h) = &header else {
        return Err(Error::Malformed("protected header must be a map"));
    };
    if h.len() != 2 {
        return Err(Error::Malformed("unexpected header parameters"));
    }
    let mut alg = None;
    let mut kid = None;
    for (k, v) in h {
        match (k, v) {
            (Value::Integer(i), Value::Integer(a)) if i128::from(*i) == 1 => alg = Some(i128::from(*a)),
            (Value::Integer(i), Value::Bytes(b)) if i128::from(*i) == 4 => kid = Some(b.clone()),
            _ => return Err(Error::Malformed("unexpected header parameters")),
        }
    }
    if alg != Some(ALG_ES256 as i128) {
        return Err(Error::Malformed("unsupported alg"));
    }
    let kid = String::from_utf8(kid.ok_or(Error::Malformed("missing kid"))?)
        .map_err(|_| Error::Malformed("kid not UTF-8"))?;
    let claims = cbor::decode_deterministic(&payload)?;
    let Value::Map(_) = &claims else {
        return Err(Error::Malformed("claims must be a map"));
    };
    let type_ok = match &claims {
        Value::Map(m) => m
            .iter()
            .any(|(k, v)| matches!((k, v), (Value::Text(k), Value::Text(t)) if k == "type" && t == expected_type)),
        _ => false,
    };
    if !type_ok {
        return Err(Error::WrongType);
    }
    Ok(Sign1 { kid, claims, protected, payload, signature })
}

/// Parse and verify against one key; returns the claims map.
pub fn verify_sign1(bytes: &[u8], key: &VerifyingKey, expected_type: &str) -> Result<Sign1, Error> {
    let s = parse_sign1(bytes, expected_type)?;
    s.verify(key)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::MapBuilder;
    use crate::keys::SoftwareKey;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let k = SoftwareKey::generate();
        let claims = MapBuilder::new("pool/test/v1").uint("x", 7).build();
        let bytes = sign1(&claims, &k).unwrap();
        let s = verify_sign1(&bytes, &k.verifying_key(), "pool/test/v1").unwrap();
        assert_eq!(s.kid, k.kid());
        // wrong type is rejected before any use
        assert!(matches!(parse_sign1(&bytes, "pool/other/v1"), Err(Error::WrongType)));
        // other key fails
        let k2 = SoftwareKey::generate();
        assert!(verify_sign1(&bytes, &k2.verifying_key(), "pool/test/v1").is_err());
        // flip one bit anywhere in the payload/signature -> invalid
        for i in (bytes.len() - 70)..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(verify_sign1(&t, &k.verifying_key(), "pool/test/v1").is_err(), "byte {i}");
        }
    }

    /// Interop vector produced by the server's Python reference (cbor2 +
    /// cryptography): a ResultClaims signed with a fresh device key.
    #[test]
    fn verifies_python_reference_vector() {
        let spki = crate::keys::b64_decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8tkdE1PJl878CPy+mljAEUuULFlLtbp+BeyLAKuqraJ9pn9ejgLX/igOBzTFkebUquBUZZQjzQJpsdP5c/kkEw==").unwrap();
        let key = crate::keys::parse_spki(&spki).unwrap();
        let hexs = "d2845834a2012604582e646b5f552d4158744462786c4d57514a72734334494e6a334f50743637354c5f717751617165746f306f62566e38a059012da964747970656e706f6f6c2f726573756c742f763165745f656e641b0000019a9668cd10666a6f625f6964782430623065386630652d356333612d346235322d396238652d31663261336234633564366567745f73746172741b0000019a96682900686c656173655f6964782431623065386630652d356333612d346235322d396238652d3166326133623463356436656a6d6f64656c5f68617368582001010101010101010101010101010101010101010101010101010101010101016c696e7075745f736861323536582002020202020202020202020202020202020202020202020202020202020202026c756e6974735f646576696365192ee06d6f75747075745f7368613235365820030303030303030303030303030303030303030303030303030303030303030358404106a4fac5eacebe4a04a031a159de94a2e034fd4af6a6c1c405ebbb7661e68225f751f4827d64ea60c1545d3b1dab646e530dadc7ac44fdb3f43fecc1fe26f8";
        let bytes: Vec<u8> = (0..hexs.len()).step_by(2).map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).unwrap()).collect();
        let s = verify_sign1(&bytes, &key, crate::object_types::RESULT_CLAIMS).unwrap();
        assert_eq!(s.kid, crate::keys::device_key_id(&key));
        let rc = crate::objects::ResultClaims::from_value(&s.claims).unwrap();
        assert_eq!(rc.units_device, Some(12000));
        assert_eq!(rc.t_end - rc.t_start, 42_000);
        // and our own encoder produces byte-identical payloads for the same claims
        assert_eq!(cbor::encode(&rc.to_value()), cbor::encode(&s.claims));
    }

    #[test]
    fn raw_payload_signature_verifies() {
        use p256::ecdsa::signature::Verifier;
        let k = SoftwareKey::generate();
        let nonce = [42u8; 32];
        let bytes = sign1_raw(&nonce, &k).unwrap();
        let Value::Tag(18, inner) = cbor::decode_any(&bytes).unwrap() else { panic!() };
        let Value::Array(a) = *inner else { panic!() };
        assert_eq!(a[2], Value::Bytes(nonce.to_vec()), "payload is the raw nonce");
        let (Value::Bytes(p), Value::Bytes(s)) = (&a[0], &a[3]) else { panic!() };
        let sig = Signature::from_slice(s).unwrap();
        k.verifying_key().verify(&sig_structure(p, &nonce), &sig).unwrap();
    }

    #[test]
    fn protected_header_layout_matches_contract() {
        // a1? no: {1: -7, 4: h'6b6964'} -> a2 01 26 04 43 6b 69 64
        assert_eq!(protected_header("kid"), vec![0xa2, 0x01, 0x26, 0x04, 0x43, b'k', b'i', b'd']);
    }

    #[test]
    fn rejects_non_empty_unprotected_header() {
        let k = SoftwareKey::generate();
        let claims = MapBuilder::new("pool/test/v1").build();
        let bytes = sign1(&claims, &k).unwrap();
        let Value::Tag(_, inner) = cbor::decode_any(&bytes).unwrap() else { panic!() };
        let Value::Array(mut arr) = *inner else { panic!() };
        arr[1] = Value::Map(vec![(Value::Integer(1.into()), Value::Integer((-7).into()))]);
        let evil = cbor::encode(&Value::Tag(18, Box::new(Value::Array(arr))));
        assert!(parse_sign1(&evil, "pool/test/v1").is_err());
    }
}
