//! Lease-bound HTTP: input GET and output PUT, each carrying a
//! `Pool-Lease-Proof` header = base64url(COSE LeaseProof) signed by the device key, with a fresh 16-byte
//! nonce per request (never reused within a lease). Input stays in memory; it is never written to disk.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use pool_proto::objects::LeaseProof;
use crate::clock::server_now_ms as now_ms;
use pool_proto::{cose, keys, sha256};
use rand_core::RngCore;

use crate::identity::DeviceKey;
use crate::jobs::LeaseTicket;

pub const PROOF_HEADER: &str = "Pool-Lease-Proof";

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("input rejected: {0}")]
    InputRejected(String),
    #[error("http: {0}")]
    Http(String),
    #[error("lease expired")]
    Expired,
    #[error("signing: {0}")]
    Sign(String),
}

/// Remembers every proof nonce used per lease, so none is ever reused (replay protection on our side).
/// Kept per lease and dropped when the lease's job ends ([`NonceBook::forget`]); before, the book lived as long
/// as the agent and grew by one entry per HTTP proof forever.
#[derive(Default)]
pub struct NonceBook(Mutex<HashMap<String, HashSet<[u8; 16]>>>);

impl NonceBook {
    pub fn fresh(&self, lease_id: &str) -> [u8; 16] {
        loop {
            let mut n = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut n);
            if self.0.lock().unwrap().entry(lease_id.to_string()).or_default().insert(n) {
                return n;
            }
        }
    }
    /// The lease is over (result sent or abandoned): its proofs can no longer be used, so its nonces are dropped.
    pub fn forget(&self, lease_id: &str) {
        self.0.lock().unwrap().remove(lease_id);
    }
    /// Leases currently tracked (tests, soak checks).
    pub fn leases(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

fn url_path(url: &str) -> Result<String, LeaseError> {
    let u = url::Url::parse(url).map_err(|e| LeaseError::Http(format!("bad url: {e}")))?;
    Ok(u.path().to_string())
}

pub fn make_proof(
    key: &dyn DeviceKey,
    nonces: &NonceBook,
    lease_id: &str,
    method: &str,
    url: &str,
    body_sha256: Option<[u8; 32]>,
) -> Result<String, LeaseError> {
    let proof = LeaseProof {
        lease_id: lease_id.into(),
        method: method.into(),
        path: url_path(url)?,
        body_sha256,
        ts: now_ms(),
        nonce: nonces.fresh(lease_id),
    };
    let cose = cose::sign1(&proof.to_value(), key).map_err(|e| LeaseError::Sign(e.to_string()))?;
    Ok(keys::b64url(&cose))
}

/// GET the input into memory and check it against the signed envelope: exact size, SHA-256 and the
/// canonical format. Requires a [`LeaseTicket`], i.e. an accepted job with a verified envelope.
pub async fn fetch_input(
    http: &reqwest::Client,
    key: &dyn DeviceKey,
    nonces: &NonceBook,
    t: &LeaseTicket,
) -> Result<Vec<u8>, LeaseError> {
    if now_ms() >= t.deadline_ms {
        return Err(LeaseError::Expired);
    }
    let proof = make_proof(key, nonces, &t.lease_id, "GET", &t.input_url, None)?;
    let mut resp = http
        .get(&t.input_url)
        .header(PROOF_HEADER, proof)
        .header("Cache-Control", "no-store")
        .send()
        .await
        .map_err(|e| LeaseError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(LeaseError::Http(format!("input GET {}", resp.status())));
    }
    let limit = t.envelope.input_bytes as usize;
    let mut body = Vec::with_capacity(limit.min(64 << 20));
    while let Some(chunk) = resp.chunk().await.map_err(|e| LeaseError::Http(e.to_string()))? {
        body.extend_from_slice(&chunk);
        if body.len() > limit {
            return Err(LeaseError::InputRejected("input larger than the envelope says".into()));
        }
    }
    if body.len() != limit {
        return Err(LeaseError::InputRejected("input size differs from the envelope".into()));
    }
    if sha256(&body) != t.envelope.input_sha256 {
        return Err(LeaseError::InputRejected("input SHA-256 differs from the envelope".into()));
    }
    pool_runner::input::validate(&t.envelope.input_format, &body).map_err(|e| LeaseError::InputRejected(e.to_string()))?;
    Ok(body)
}

/// PUT the output once, with `body_sha256` in the proof.
pub async fn put_output(
    http: &reqwest::Client,
    key: &dyn DeviceKey,
    nonces: &NonceBook,
    t: &LeaseTicket,
    content_type: &str,
    body: Vec<u8>,
) -> Result<[u8; 32], LeaseError> {
    if now_ms() >= t.deadline_ms {
        return Err(LeaseError::Expired);
    }
    let digest = sha256(&body);
    let proof = make_proof(key, nonces, &t.lease_id, "PUT", &t.output_url, Some(digest))?;
    let resp = http
        .put(&t.output_url)
        .header(PROOF_HEADER, proof)
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await
        .map_err(|e| LeaseError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(LeaseError::Http(format!("output PUT {}", resp.status())));
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SoftwareDeviceKey;

    #[test]
    fn proof_is_signed_bound_and_nonces_never_repeat() {
        let k = SoftwareDeviceKey::generate();
        let book = NonceBook::default();
        let lease = uuid::Uuid::new_v4().to_string();
        let url = format!("https://engine.test/node/v1/outputs/{lease}?t=secret-token");
        let h = make_proof(&k, &book, &lease, "PUT", &url, Some([9; 32])).unwrap();
        let cose = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, h).unwrap();
        let vk = pool_proto::keys::parse_spki(&crate::identity::DeviceKey::spki_der(&k)).unwrap();
        let s = pool_proto::cose::verify_sign1(&cose, &vk, pool_proto::object_types::LEASE_PROOF).unwrap();
        let p = LeaseProof::from_value(&s.claims).unwrap();
        assert_eq!(p.path, format!("/node/v1/outputs/{lease}"), "path excludes the query token");
        assert_eq!(p.body_sha256, Some([9; 32]));
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(book.fresh(&lease)));
        }
        // The book forgets a lease when its job ends (bounded memory over a long run)
        book.fresh("other-lease");
        assert_eq!(book.leases(), 2);
        book.forget(&lease);
        book.forget("other-lease");
        assert_eq!(book.leases(), 0);
    }
}
