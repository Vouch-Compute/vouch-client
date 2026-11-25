//! `pool-core`: the Vouch Compute contributor agent.
//!
//! Wire format: proto/node.proto and the signed objects in pool-proto.
//!
//! * [`identity`]: TPM-backed (Windows) or DEV software ES256 device key.
//! * [`session`]: job-server WebSocket, signed nonce + TLS exporter session proof, framing, work loop.
//! * [`jobs`]: offer -> accept -> lease state machine; no input before Accept.
//! * [`lease`]: lease-bound input GET / output PUT with `Pool-Lease-Proof`.
//! * [`registry`]: signed model cache. [`runner_client`]: sandboxed runner per job.
//! * [`governor`] + [`platform`]: idle, fullscreen, thermal, power, battery, schedule, daily cap.
//! * [`agent`]: sign-in (RFC 8628), enrollment, KeySet trust and rollback protection, reconnect loop.
//! * [`control`]: local IPC for the app (per-user ACL). [`money`]: exact decimal USD amounts (contract 2.0.0, no floats).
//! * [`hwids`]: hardware identifiers after consent (2.1.0). [`device_view`]: the display filter for the server's DeviceView.

pub mod agent;
pub mod clock;
pub mod config;
pub mod control;
pub mod device_view;
#[cfg(windows)]
pub mod dpapi;
pub mod governor;
pub mod hwids;
pub mod identity;
pub mod jobs;
pub mod lease;
pub mod money;
pub mod platform;
pub mod registry;
pub mod runner_client;
pub mod session;
pub mod status;
pub mod vault;

/// The version shown to the user and in the log: the package version, or `<version>-test.<sha>` for a test build
/// (T-227: built from a branch with `POOL_TEST_BUILD=<short commit>`, never published or offered as an update). The
/// server always gets the plain package version.
pub fn display_version() -> String {
    test_build_suffix(option_env!("POOL_TEST_BUILD")).map_or_else(|| env!("CARGO_PKG_VERSION").to_string(), |s| format!("{}-test.{s}", env!("CARGO_PKG_VERSION")))
}

/// A short commit id (4 to 12 hex digits), or nothing.
fn test_build_suffix(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| (4..=12).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn test_build_suffix_is_a_short_commit_only() {
        assert_eq!(super::test_build_suffix(Some("16bebc8")), Some("16bebc8"));
        for bad in [None, Some(""), Some("abc"), Some("16bebc8!"), Some("0123456789abc"), Some("main")] {
            assert_eq!(super::test_build_suffix(bad), None, "{bad:?}");
        }
        assert!(super::display_version().starts_with(env!("CARGO_PKG_VERSION")));
    }
}
