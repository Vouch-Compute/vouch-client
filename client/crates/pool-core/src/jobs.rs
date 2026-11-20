//! Job state machine seen by the node:
//! `offered -> accepted -> leased -> (result_sent -> received) | abandoned | revoked | expired`.
//!
//! "No input before Accept" is enforced by construction: the input URL is only reachable through a [`LeaseTicket`], and the
//! only way to get a ticket is [`JobTracker::on_lease_grant`] for a job this node **accepted**, with a
//! LeaseEnvelope that verified against the server's `dispatch` key and matches this device, job, lease and model.

use std::collections::HashMap;

use pool_proto::objects::LeaseEnvelope;
use pool_proto::pb;

/// Offer answer deadline.
pub const ACCEPT_DEADLINE_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq)]
pub enum JobState {
    Offered { at_ms: u64 },
    Declined,
    Accepted,
    Leased { lease_id: String },
    ResultSent { lease_id: String },
    Received { lease_id: String },
    Abandoned { lease_id: String },
    Revoked { lease_id: String },
    Expired,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub offer: pb::Offer,
    pub state: JobState,
}

/// Proof that a job was accepted and leased with a verified envelope. Required to fetch input.
#[derive(Debug, Clone)]
pub struct LeaseTicket {
    pub job_id: String,
    pub lease_id: String,
    pub input_url: String,
    pub output_url: String,
    pub deadline_ms: u64,
    pub envelope: LeaseEnvelope,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JobError {
    #[error("duplicate offer for job {0}")]
    DuplicateOffer(String),
    #[error("malformed offer")]
    MalformedOffer,
    #[error("unknown job {0}")]
    UnknownJob(String),
    #[error("job {0} is not in a state that allows this")]
    BadState(String),
    #[error("offer {0} answered after the 5 s deadline")]
    AcceptTooLate(String),
    /// A LeaseGrant arrived for a job we did not accept: no input is ever fetched for it.
    #[error("lease grant for a job that was not accepted: {0}")]
    NotAccepted(String),
    /// The envelope did not verify or does not match: the node abandons with ENVELOPE_INVALID.
    #[error("lease envelope invalid for job {job_id}: {why}")]
    EnvelopeInvalid { job_id: String, lease_id: String, why: String },
}

/// Who this node is (for envelope matching).
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub device_id: String,
    pub device_key_id: String,
}

#[derive(Default)]
pub struct JobTracker {
    jobs: HashMap<String, Job>,
    /// lease ids ever granted to this node (a re-used lease id is a replay)
    seen_leases: std::collections::HashSet<String>,
}

impl JobTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, job_id: &str) -> Option<&Job> {
        self.jobs.get(job_id)
    }

    pub fn active_count(&self) -> usize {
        self.jobs.values().filter(|j| matches!(j.state, JobState::Accepted | JobState::Leased { .. })).count()
    }

    pub fn on_offer(&mut self, offer: pb::Offer, now_ms: u64) -> Result<(), JobError> {
        if offer.job_id.is_empty() || offer.model_hash.len() != 32 || offer.model_id.is_empty() {
            return Err(JobError::MalformedOffer);
        }
        if self.jobs.contains_key(&offer.job_id) {
            return Err(JobError::DuplicateOffer(offer.job_id));
        }
        self.jobs.insert(offer.job_id.clone(), Job { offer, state: JobState::Offered { at_ms: now_ms } });
        Ok(())
    }

    /// Accept within the 5 s answer window. Produces the Accept message.
    pub fn accept(&mut self, job_id: &str, now_ms: u64) -> Result<pb::Accept, JobError> {
        let job = self.jobs.get_mut(job_id).ok_or_else(|| JobError::UnknownJob(job_id.into()))?;
        match job.state {
            JobState::Offered { at_ms } if now_ms.saturating_sub(at_ms) <= ACCEPT_DEADLINE_MS => {
                job.state = JobState::Accepted;
                Ok(pb::Accept { job_id: job_id.into() })
            }
            JobState::Offered { .. } => {
                job.state = JobState::Declined;
                Err(JobError::AcceptTooLate(job_id.into()))
            }
            _ => Err(JobError::BadState(job_id.into())),
        }
    }

    pub fn decline(&mut self, job_id: &str, reason: pb::DeclineReason) -> Result<pb::Decline, JobError> {
        let job = self.jobs.get_mut(job_id).ok_or_else(|| JobError::UnknownJob(job_id.into()))?;
        if !matches!(job.state, JobState::Offered { .. }) {
            return Err(JobError::BadState(job_id.into()));
        }
        job.state = JobState::Declined;
        Ok(pb::Decline { job_id: job_id.into(), reason: reason as i32 })
    }

    /// Handle a LeaseGrant. `verify` checks the COSE signature with the server's dispatch key and returns the
    /// claims. Only an accepted job with a matching, unexpired envelope yields a ticket.
    pub fn on_lease_grant(
        &mut self,
        grant: &pb::LeaseGrant,
        me: &NodeIdentity,
        now_ms: u64,
        verify: impl FnOnce(&[u8]) -> Result<LeaseEnvelope, pool_proto::Error>,
    ) -> Result<LeaseTicket, JobError> {
        let job = self.jobs.get_mut(&grant.job_id).ok_or_else(|| JobError::NotAccepted(grant.job_id.clone()))?;
        if job.state != JobState::Accepted {
            return Err(JobError::NotAccepted(grant.job_id.clone()));
        }
        let invalid = |why: &str| JobError::EnvelopeInvalid {
            job_id: grant.job_id.clone(),
            lease_id: grant.lease_id.clone(),
            why: why.into(),
        };
        let env = match verify(&grant.lease_envelope) {
            Ok(e) => e,
            Err(e) => {
                job.state = JobState::Abandoned { lease_id: grant.lease_id.clone() };
                return Err(invalid(&format!("signature: {e}")));
            }
        };
        let deadline = u64::try_from(grant.lease_deadline_ms).unwrap_or(0);
        let why = if env.job_id != grant.job_id {
            Some("job_id mismatch")
        } else if env.lease_id != grant.lease_id {
            Some("lease_id mismatch")
        } else if env.device_id != me.device_id {
            Some("device_id mismatch")
        } else if env.device_key_id != me.device_key_id {
            Some("device_key_id mismatch")
        } else if env.model_hash[..] != job.offer.model_hash[..] || env.model_id != job.offer.model_id {
            Some("model mismatch with offer")
        } else if env.deadline <= now_ms || deadline <= now_ms {
            Some("deadline passed")
        } else if deadline > env.deadline {
            Some("grant deadline later than envelope")
        } else if self.seen_leases.contains(&grant.lease_id) {
            Some("lease id replayed")
        } else if !grant.input_url.starts_with("https://") && !grant.input_url.starts_with("http://") {
            Some("bad input url")
        } else {
            None
        };
        if let Some(why) = why {
            job.state = JobState::Abandoned { lease_id: grant.lease_id.clone() };
            return Err(invalid(why));
        }
        self.seen_leases.insert(grant.lease_id.clone());
        job.state = JobState::Leased { lease_id: grant.lease_id.clone() };
        Ok(LeaseTicket {
            job_id: grant.job_id.clone(),
            lease_id: grant.lease_id.clone(),
            input_url: grant.input_url.clone(),
            output_url: grant.output_url.clone(),
            deadline_ms: deadline,
            envelope: env,
        })
    }

    pub fn on_result_sent(&mut self, job_id: &str) -> Result<(), JobError> {
        let job = self.jobs.get_mut(job_id).ok_or_else(|| JobError::UnknownJob(job_id.into()))?;
        match &job.state {
            JobState::Leased { lease_id } => {
                job.state = JobState::ResultSent { lease_id: lease_id.clone() };
                Ok(())
            }
            _ => Err(JobError::BadState(job_id.into())),
        }
    }

    pub fn on_abandon(&mut self, job_id: &str) -> Option<pb::Abandon> {
        let job = self.jobs.get_mut(job_id)?;
        match &job.state {
            JobState::Leased { lease_id } => {
                let lease_id = lease_id.clone();
                job.state = JobState::Abandoned { lease_id: lease_id.clone() };
                Some(pb::Abandon { job_id: job_id.into(), lease_id, reason: 0 })
            }
            JobState::Accepted => {
                job.state = JobState::Abandoned { lease_id: String::new() };
                Some(pb::Abandon { job_id: job_id.into(), lease_id: String::new(), reason: 0 })
            }
            _ => None,
        }
    }

    pub fn on_revoked(&mut self, r: &pb::LeaseRevoked) -> bool {
        match self.jobs.get_mut(&r.job_id) {
            // A late Accept is answered with `LeaseRevoked{job_id, lease_id: ""}`; the offer is
            // over and its grant will never come (a grant arriving later anyway is refused as not accepted)
            Some(job) if r.lease_id.is_empty() && matches!(job.state, JobState::Accepted | JobState::Offered { .. }) => {
                job.state = JobState::Declined;
                true
            }
            Some(job) if matches!(&job.state, JobState::Leased { lease_id } | JobState::ResultSent { lease_id } if *lease_id == r.lease_id) => {
                job.state = JobState::Revoked { lease_id: r.lease_id.clone() };
                true
            }
            _ => false,
        }
    }

    pub fn on_receipt(&mut self, r: &pb::ResultReceipt) {
        // REJECTED_MALFORMED (also for a Result more than 300 s after the lease ended) and LATE are
        // final like RECEIVED: the node never re-sends a Result, it only notes the outcome
        if r.status != pb::ReceiptStatus::Received as i32 {
            tracing::warn!("result for job {} not accepted by the hub (receipt status {})", r.job_id, r.status);
        }
        if let Some(job) = self.jobs.get_mut(&r.job_id) {
            if let JobState::ResultSent { lease_id } = &job.state {
                if *lease_id == r.lease_id {
                    job.state = JobState::Received { lease_id: lease_id.clone() };
                }
            }
        }
    }

    /// Expire offers that were never answered and leases past their deadline; drop finished jobs after
    /// a while (lease ids are remembered forever for replay detection).
    pub fn sweep(&mut self, now_ms: u64) -> Vec<String> {
        let mut expired = vec![];
        for (id, job) in self.jobs.iter_mut() {
            match &job.state {
                JobState::Offered { at_ms } if now_ms.saturating_sub(*at_ms) > ACCEPT_DEADLINE_MS => {
                    job.state = JobState::Expired;
                }
                JobState::Accepted if u64::try_from(job.offer.deadline_ms).unwrap_or(0) < now_ms => {
                    job.state = JobState::Expired;
                    expired.push(id.clone());
                }
                _ => {}
            }
        }
        self.jobs.retain(|_, j| {
            !matches!(j.state, JobState::Received { .. } | JobState::Expired | JobState::Declined)
                || u64::try_from(j.offer.deadline_ms).unwrap_or(0) + 600_000 > now_ms
        });
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool_proto::testkit::FakeVault;

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    struct Fx {
        vault: FakeVault,
        me: NodeIdentity,
        offer: pb::Offer,
        now: u64,
    }

    fn fx() -> Fx {
        let vault = FakeVault::new();
        let now = vault.now();
        Fx {
            me: NodeIdentity { device_id: uuid(), device_key_id: format!("dk_{}", "Q".repeat(43)) },
            offer: pb::Offer { job_id: uuid(), model_id: "m1".into(), model_hash: vec![7; 32], est_units: 30, deadline_ms: (now + 60_000) as i64 },
            vault,
            now,
        }
    }

    fn envelope(f: &Fx, lease_id: &str) -> LeaseEnvelope {
        LeaseEnvelope {
            job_id: f.offer.job_id.clone(),
            lease_id: lease_id.into(),
            device_id: f.me.device_id.clone(),
            device_key_id: f.me.device_key_id.clone(),
            model_id: "m1".into(),
            model_hash: [7; 32],
            input_sha256: [1; 32],
            input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
            input_bytes: 10,
            unit_type: "token".into(),
            issued_at: f.now,
            deadline: f.now + 60_000,
            language: Some("tr".into()),
        }
    }

    fn grant(f: &Fx, env: &LeaseEnvelope, signed: Vec<u8>) -> pb::LeaseGrant {
        pb::LeaseGrant {
            job_id: env.job_id.clone(),
            lease_id: env.lease_id.clone(),
            lease_envelope: signed,
            input_url: format!("https://engine.test/node/v1/inputs/{}?t=abc", env.lease_id),
            output_url: format!("https://engine.test/node/v1/outputs/{}?t=def", env.lease_id),
            lease_deadline_ms: (f.now + 50_000) as i64,
        }
    }

    fn verifier(v: &FakeVault) -> impl Fn(&[u8]) -> Result<LeaseEnvelope, pool_proto::Error> + '_ {
        move |b| {
            let ks = pool_proto::trust::verify_keyset(&v.keyset_bytes(1), &v.roots(), 0)?;
            ks.verify_lease_envelope(b, v.now())
        }
    }

    #[test]
    fn happy_path_offer_accept_lease_result_receipt() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now + 100).unwrap();
        let lease = uuid();
        let env = envelope(&f, &lease);
        let g = grant(&f, &env, f.vault.sign_envelope(&env));
        let ticket = t.on_lease_grant(&g, &f.me, f.now + 200, verifier(&f.vault)).unwrap();
        assert_eq!(ticket.lease_id, lease);
        assert_eq!(ticket.envelope, env);
        t.on_result_sent(&f.offer.job_id).unwrap();
        t.on_receipt(&pb::ResultReceipt { job_id: f.offer.job_id.clone(), lease_id: lease.clone(), status: 1 });
        assert_eq!(t.get(&f.offer.job_id).unwrap().state, JobState::Received { lease_id: lease });
    }

    /// No input before Accept. A grant for an offered-but-not-accepted, declined or unknown job
    /// yields no ticket (so nothing can be fetched) and does not change the job.
    #[test]
    fn no_ticket_and_no_fetch_before_accept() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        let lease = uuid();
        let env = envelope(&f, &lease);
        let g = grant(&f, &env, f.vault.sign_envelope(&env));
        let mut verify_called = false;
        let r = t.on_lease_grant(&g, &f.me, f.now, |_| {
            verify_called = true;
            Err(pool_proto::Error::BadSignature)
        });
        assert_eq!(r.unwrap_err(), JobError::NotAccepted(f.offer.job_id.clone()));
        assert!(!verify_called, "envelope must not even be processed for an unaccepted job");
        assert!(matches!(t.get(&f.offer.job_id).unwrap().state, JobState::Offered { .. }));
        // declined
        t.decline(&f.offer.job_id, pb::DeclineReason::Busy).unwrap();
        assert!(matches!(t.on_lease_grant(&g, &f.me, f.now, verifier(&f.vault)), Err(JobError::NotAccepted(_))));
        // unknown job
        let mut g2 = g.clone();
        g2.job_id = uuid();
        assert!(matches!(t.on_lease_grant(&g2, &f.me, f.now, verifier(&f.vault)), Err(JobError::NotAccepted(_))));
    }

    /// A late Accept is answered with `LeaseRevoked{lease_id: ""}`: the accepted offer is cleared,
    /// a grant arriving afterwards is refused (no input fetch), and a revoke with an empty id never touches a lease.
    #[test]
    fn revoke_with_empty_lease_id_clears_the_accepted_offer() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now).unwrap();
        let r = pb::LeaseRevoked { job_id: f.offer.job_id.clone(), lease_id: String::new(), reason: pb::RevokeReason::Cancelled as i32 };
        assert!(t.on_revoked(&r));
        let env = envelope(&f, &uuid());
        let g = grant(&f, &env, f.vault.sign_envelope(&env));
        assert!(matches!(t.on_lease_grant(&g, &f.me, f.now, verifier(&f.vault)), Err(JobError::NotAccepted(_))));
        // a leased job is not affected by an empty-id revoke
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now).unwrap();
        t.on_lease_grant(&g, &f.me, f.now, verifier(&f.vault)).unwrap();
        assert!(!t.on_revoked(&r), "an empty lease id must not revoke a running lease");
        // unknown job: ignored
        assert!(!JobTracker::new().on_revoked(&r));
    }

    #[test]
    fn accept_window_is_five_seconds_and_answers_once() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        assert_eq!(t.accept(&f.offer.job_id, f.now + 5_001), Err(JobError::AcceptTooLate(f.offer.job_id.clone())));
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now).unwrap();
        assert!(t.accept(&f.offer.job_id, f.now).is_err(), "double accept");
        assert!(t.decline(&f.offer.job_id, pb::DeclineReason::Busy).is_err(), "decline after accept");
        assert_eq!(t.on_offer(f.offer.clone(), f.now), Err(JobError::DuplicateOffer(f.offer.job_id.clone())));
    }

    #[test]
    fn envelope_must_verify_and_match() {
        let f = fx();
        type Mutate = Box<dyn Fn(&mut LeaseEnvelope)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("device", Box::new(|e| e.device_id = uuid())),
            ("key", Box::new(|e| e.device_key_id = format!("dk_{}", "Z".repeat(43)))),
            ("job", Box::new(|e| e.job_id = uuid())),
            ("model", Box::new(|e| e.model_hash = [8; 32])),
            ("deadline", Box::new(|e| e.deadline = 1)),
        ];
        for (name, mutate) in cases {
            let mut t = JobTracker::new();
            t.on_offer(f.offer.clone(), f.now).unwrap();
            t.accept(&f.offer.job_id, f.now).unwrap();
            let lease = uuid();
            let mut env = envelope(&f, &lease);
            mutate(&mut env);
            let mut g = grant(&f, &env, f.vault.sign_envelope(&env));
            g.job_id = f.offer.job_id.clone();
            let r = t.on_lease_grant(&g, &f.me, f.now, verifier(&f.vault));
            assert!(matches!(r, Err(JobError::EnvelopeInvalid { .. })), "{name}: {r:?}");
            assert!(t.on_abandon(&f.offer.job_id).is_none(), "already abandoned");
        }
        // signed by the wrong the server key (registry instead of dispatch)
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now).unwrap();
        let lease = uuid();
        let env = envelope(&f, &lease);
        let forged = pool_proto::cose::sign1(&env.to_value(), &f.vault.registry).unwrap();
        let r = t.on_lease_grant(&grant(&f, &env, forged), &f.me, f.now, verifier(&f.vault));
        assert!(matches!(r, Err(JobError::EnvelopeInvalid { .. })));
    }

    #[test]
    fn replayed_lease_id_is_refused() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.accept(&f.offer.job_id, f.now).unwrap();
        let lease = uuid();
        let env = envelope(&f, &lease);
        let g = grant(&f, &env, f.vault.sign_envelope(&env));
        t.on_lease_grant(&g, &f.me, f.now, verifier(&f.vault)).unwrap();
        // a second offer for a different job id, but the server replays the old lease
        let mut o2 = f.offer.clone();
        o2.job_id = uuid();
        t.on_offer(o2.clone(), f.now).unwrap();
        t.accept(&o2.job_id, f.now).unwrap();
        let mut env2 = env.clone();
        env2.job_id = o2.job_id.clone();
        let g2 = grant(&f, &env2, f.vault.sign_envelope(&env2));
        assert!(matches!(t.on_lease_grant(&g2, &f.me, f.now, verifier(&f.vault)), Err(JobError::EnvelopeInvalid { .. })));
    }

    #[test]
    fn unanswered_offers_expire() {
        let f = fx();
        let mut t = JobTracker::new();
        t.on_offer(f.offer.clone(), f.now).unwrap();
        t.sweep(f.now + 6_000);
        assert_eq!(t.get(&f.offer.job_id).unwrap().state, JobState::Expired);
    }
}
