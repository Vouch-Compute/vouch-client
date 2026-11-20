//! Shared protocol types for the contributor client.
//!
//! Frozen contracts:
//! * transport messages: `proto/node.proto` (package `pool.node.v1`), generated with prost ([`pb`])
//! * signed objects: `proto/signed-objects.cddl` (COSE_Sign1 over deterministic CBOR; ES256/P-256)
//!   ([`cbor`], [`cose`], [`objects`], [`trust`])

pub mod cbor;
pub mod cose;
pub mod frame;
pub mod keys;
pub mod objects;
pub mod outputs;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod trust;

/// Generated from `proto/node.proto` (node protocol 1.2.0).
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/v120/pool.node.v1.rs"));
}

/// Node protocol 1.1.0 types (test fixture `tests/data/node-1.1.0.proto`), for the cross-version tests only.
#[cfg(any(test, feature = "testkit"))]
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb_v110 {
    include!(concat!(env!("OUT_DIR"), "/v110/pool.node.v1.rs"));
}

// Release guard: the release-signing configuration (`POOL_RELEASE=1` or the `release`
// feature) never compiles together with `dev-trust` (POOL_DEV_TRUST_ROOTS, short benchmarks, the dev reference backend).
#[cfg(all(feature = "dev-trust", any(pool_release, feature = "release")))]
compile_error!(
    "dev-trust is enabled in a release-signing build (POOL_RELEASE=1 / feature `release`): build with --no-default-features"
);

/// Embedded build information. The release signing step refuses any binary that contains `dev-trust=yes`
/// (`client/ci/release-marker-check.sh`, security review R1 (b)). Binaries print it with `version`.
#[cfg(feature = "dev-trust")]
pub const BUILD_INFO: &str = "VOUCH-BUILD-INFO dev-trust=yes channel=dev";
#[cfg(not(feature = "dev-trust"))]
pub const BUILD_INFO: &str = "VOUCH-BUILD-INFO dev-trust=no channel=release";
/// The app's bundle identifier. Dev builds use their own, so a dev build never shares a data dir,
/// keychain entries or update channel with a release. The data dir is `<local data dir>/<BUNDLE_ID>`.
#[cfg(feature = "dev-trust")]
pub const BUNDLE_ID: &str = "com.vouchcompute.app.dev";
#[cfg(not(feature = "dev-trust"))]
pub const BUNDLE_ID: &str = "com.vouchcompute.app";
/// OS keychain / Credential Manager service name for the device key. Keys from before the rename are never
/// migrated: a renamed install enrolls as a new device.
pub const KEYCHAIN_SERVICE: &str = "com.vouchcompute.app.device-key";
/// `true` in dev-trust builds: they show a permanent "DEV BUILD" marker and use the dev updater channel.
pub const DEV_BUILD: bool = cfg!(feature = "dev-trust");

/// Protocol version string sent in `Hello.protocol_version`.
pub const PROTOCOL_VERSION: &str = "pool.node.v1";
/// WebSocket subprotocol.
pub const WS_SUBPROTOCOL: &str = "pool.node.v1";
/// TLS exporter label for the session proof.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-pool-node-hello";

/// Domain-separation `type` strings for signed objects (see `proto/signed-objects.cddl`).
pub mod object_types {
    pub const HELLO: &str = "pool/hello/v1";
    pub const LEASE_ENVELOPE: &str = "pool/lease-envelope/v1";
    pub const RESULT_CLAIMS: &str = "pool/result/v1";
    pub const LEASE_PROOF: &str = "pool/lease-proof/v1";
    pub const BENCHMARK_WORKLOAD: &str = "pool/benchmark-workload/v1";
    pub const BENCHMARK_RESULT: &str = "pool/benchmark-result/v1";
    pub const MODEL_MANIFEST: &str = "pool/model-manifest/v1";
    pub const KEY_SET: &str = "pool/keyset/v1";
    /// 1.1.0: `nonce_sig` payload for `POST /v1/devices`.
    pub const ENROLL: &str = "pool/enroll/v1";
    /// 1.2.0: hardware identifiers, sent only to the server.
    pub const HW_IDS: &str = "pool/hw-ids/v1";
    /// 1.2.0: pause / resume / self-revoke from the app.
    pub const DEVICE_CONTROL: &str = "pool/device-control/v1";
    /// 1.2.0: device signature for an account recovery case.
    pub const RECOVERY: &str = "pool/recovery/v1";
    /// `POST /v1/devices/{id}/key-rotations`.
    pub const KEY_ROTATION: &str = "pool/key-rotation/v1";
}

/// `AccountNotice.kind` values (node protocol 1.2.0, `proto/node.proto` `AccountNoticeKind`). Used as numbers so the
/// code does not depend on how prost names the enum variants.
pub mod account_notice {
    pub const PAUSED_BY_USER: i32 = 1;
    pub const PAUSED_BY_TALLY: i32 = 2;
    pub const RESUMED: i32 = 3;
    pub const RECOVERY_IN_PROGRESS: i32 = 4;
    pub const REVERIFY_REQUIRED: i32 = 5;
}

/// `Heartbeat.governor_state` values (node protocol 1.2.0, `GovernorState`); self-reported, informational only.
pub mod governor_state {
    pub const RUNNING: i32 = 1;
    pub const IDLE_WAIT: i32 = 2;
    pub const THERMAL: i32 = 3;
    pub const BATTERY: i32 = 4;
    pub const SCHEDULE: i32 = 5;
    pub const USER_PAUSED: i32 = 6;
}

/// The only audio input format a runner accepts.
pub const CANONICAL_AUDIO_FORMAT: &str = "audio/flac;rate=16000;channels=1";
/// The only text input format (UTF-8 NFC JSON `{"inputs":[...]}`).
pub const EMBED_BATCH_FORMAT: &str = "application/vnd.pool.embed-batch.v1+json";
/// Output content types (cddl 1.1.0 `EmbedResult` / `Transcript`, closed objects). See [`outputs`].
pub const EMBED_RESULT_FORMAT: &str = "application/vnd.pool.embed-result.v1+json";
pub const TRANSCRIPT_FORMAT: &str = "application/vnd.pool.transcript.v1+json";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("wrong object type")]
    WrongType,
    #[error("signature invalid")]
    BadSignature,
    #[error("unknown signing key")]
    UnknownKey,
    #[error("expired or not yet valid")]
    Expired,
    #[error("keyset rollback")]
    Rollback,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("signer error: {0}")]
    Signer(String),
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_v1() {
        assert_eq!(super::PROTOCOL_VERSION, "pool.node.v1");
    }
}
