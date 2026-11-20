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
