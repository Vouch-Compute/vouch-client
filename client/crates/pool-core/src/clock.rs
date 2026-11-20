//! Server clock (clock-skew handling).
//!
//! the server meters only results whose `t_start`/`t_end` fall inside its own view of the lease (5 s tolerance), and
//! refuses Hello, LeaseProof, DeviceControl and RecoveryProof timestamps more than 60 s (10 min for some) away
//! from its clock. A contributor whose PC clock is a few seconds off would do the work and never be paid, without
//! any visible error. So every timestamp the agent signs or compares with a server deadline uses the **server
//! clock**: the local clock plus the offset measured from `Challenge.server_time_ms` / `Welcome.server_time_ms`.
//!
//! Bounds: offsets above [`MAX_OFFSET_MS`] (24 h) are not applied (TLS certificate checks on the local clock fail
//! long before that, and a server must not be able to move the agent's time arbitrarily); such a clock is reported in
//! the status instead. Durations are unaffected (the offset is constant within a session).

use std::sync::atomic::{AtomicI64, Ordering};

pub const MAX_OFFSET_MS: i64 = 24 * 3600 * 1000;
/// Offsets above this are shown to the user ("your computer's clock is off").
pub const REPORT_OFFSET_MS: i64 = 5_000;

static OFFSET_MS: AtomicI64 = AtomicI64::new(0);

/// `local + offset`, saturating at 0 and u64::MAX.
pub fn apply(local_ms: u64, offset_ms: i64) -> u64 {
    if offset_ms >= 0 {
        local_ms.saturating_add(offset_ms as u64)
    } else {
        local_ms.saturating_sub(offset_ms.unsigned_abs())
    }
}

/// The offset a server timestamp implies at local time `local_ms`, or `None` for an absent/implausible one.
pub fn offset_for(server_ms: i64, local_ms: u64) -> Option<i64> {
    if server_ms <= 0 {
        return None; // field not set
    }
    let off = i128::from(server_ms) - i128::from(local_ms);
    let off = i64::try_from(off).ok()?;
    (off.abs() <= MAX_OFFSET_MS).then_some(off)
}

/// Record a server timestamp received just now. Returns the raw offset (also when it was too large to apply).
pub fn observe(server_ms: i64) -> Option<i64> {
    let local = pool_proto::now_ms();
    match offset_for(server_ms, local) {
        Some(off) => {
            OFFSET_MS.store(off, Ordering::Relaxed);
            if off.abs() > REPORT_OFFSET_MS {
                tracing::warn!("local clock is {} ms off the server clock; using server time for signed timestamps", off);
            }
            Some(off)
        }
        None if server_ms > 0 => {
            tracing::warn!("server time {server_ms} is more than 24 h from the local clock; not applied");
            i64::try_from(i128::from(server_ms) - i128::from(local)).ok()
        }
        None => None,
    }
}

pub fn offset_ms() -> i64 {
    OFFSET_MS.load(Ordering::Relaxed)
}

/// The current time on the server's clock (ms since the epoch).
pub fn server_now_ms() -> u64 {
    apply(pool_proto::now_ms(), offset_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn offsets_are_bounded_and_unset_fields_ignored() {
        assert_eq!(offset_for(0, 1_000), None, "proto default 0 = not sent");
        assert_eq!(offset_for(-5, 1_000), None);
        assert_eq!(offset_for(1_000 + 7_000, 1_000), Some(7_000));
        assert_eq!(offset_for(1_000_000, 1_000_000 + 90_000), Some(-90_000));
        assert_eq!(offset_for(i64::MAX, 1), None, "a day or more is never applied");
        assert_eq!(offset_for(MAX_OFFSET_MS + 2, 1), None);
        assert_eq!(apply(10, -20), 0);
        assert_eq!(apply(u64::MAX - 1, 5), u64::MAX);
    }

    proptest! {
        #[test]
        fn applying_the_offset_recovers_server_time(local in 0u64..(1u64 << 50), off in -MAX_OFFSET_MS..=MAX_OFFSET_MS) {
            let server = apply(local, off);
            prop_assume!(server > 0);
            let o = offset_for(server as i64, local).unwrap();
            prop_assert_eq!(apply(local, o), server);
        }

        #[test]
        fn never_panics(server in any::<i64>(), local in any::<u64>()) {
            if let Some(o) = offset_for(server, local) {
                prop_assert!(o.abs() <= MAX_OFFSET_MS);
                let _ = apply(local, o);
            }
        }
    }
}
