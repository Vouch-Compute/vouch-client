//! `pool-runner`: one job per process, inside the OS sandbox.
//!
//! * [`ipc`]: memory-only pipe protocol with `pool-core`.
//! * the OS sandbox the runner is started in lives in the `pool-sandbox` crate (AppContainer/Job Object,
//!   namespaces, sandbox-exec), so this binary links none of that code.
//! * [`harden`]: what the runner applies to itself (Landlock/seccomp on Linux, no dumps everywhere).
//! * [`bundle`]: signed model bundle verification; [`input`]: canonical input gate.
//! * [`backends`]: candle (CPU, default), ONNX Runtime (`onnx`), whisper.cpp (`whisper`).
//! * [`probe`]: sandbox self-test used by the tests.

pub mod accel;
pub mod backends;
pub mod bundle;
pub mod harden;
pub mod input;
pub mod ipc;
pub mod probe;
#[cfg(any(test, feature = "testkit"))]
pub mod testutil;

use std::io::{Read, Write};
use std::path::Path;

use ipc::{read_frame, write_frame, RunRequest, RunResponse};

/// Largest input chunk accepted over the pipe.
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Handle one job: read the request and input from `r`, write the response and output to `w`.
pub fn serve(r: &mut impl Read, w: &mut impl Write) -> std::io::Result<bool> {
    let (resp, out) = handle(r);
    let ok = resp.ok;
    write_frame(w, &serde_json::to_vec(&resp).unwrap_or_default())?;
    write_frame(w, &out)?;
    Ok(ok)
}

fn handle(r: &mut impl Read) -> (RunResponse, Vec<u8>) {
    let req: RunRequest = match read_frame(r, 1 << 20).ok().and_then(|h| serde_json::from_slice(&h).ok()) {
        Some(req) => req,
        None => return (RunResponse::error("runtime_error", "bad request header"), vec![]),
    };
    // Lock the process down before any input or model byte is read.
    let hardening = harden::apply(Path::new(&req.model_dir));
    // Fail closed when the in-process sandbox layer did not apply (Linux: seccomp + Landlock)
    if let Err(e) = hardening.job_allowed() {
        return (RunResponse::error("sandbox_error", e), vec![]);
    }
    let input = match read_frame(r, MAX_INPUT_BYTES) {
        Ok(i) => i,
        Err(e) => return (RunResponse::error("runtime_error", format!("input frame: {e}")), vec![]),
    };
    if let Err(e) = input::validate(&req.input_format, &input) {
        return (RunResponse::error("input_rejected", e.to_string()), vec![]);
    }
    let parsed = (|| {
        Ok::<_, bundle::BundleError>((
            bundle::decode_b64(&req.keyset_b64)?,
            bundle::decode_b64(&req.manifest_b64)?,
            bundle::decode_hash_hex(&req.expected_model_hash_hex)?,
        ))
    })();
    let (keyset, manifest, hash) = match parsed {
        Ok(p) => p,
        Err(e) => return (RunResponse::error("bundle_invalid", e.to_string()), vec![]),
    };
    let mut b = match bundle::load(&keyset, &manifest, &hash, Path::new(&req.model_dir)) {
        Ok(b) => b,
        Err(e) => return (RunResponse::error("bundle_invalid", e.to_string()), vec![]),
    };
    if b.manifest.input_format != req.input_format {
        return (RunResponse::error("input_rejected", "input format does not match the model"), vec![]);
    }
    match backends::run(&mut b, &input, req.language.as_deref()) {
        Ok(out) if out.bytes.len() as u64 > req.max_output_bytes => {
            (RunResponse::error("runtime_error", "output exceeds limit"), vec![])
        }
        Ok(out) => (
            RunResponse {
                ok: true,
                output_format: Some(out.format.into()),
                units_device_milli: Some(out.units_device_milli),
                backend: Some(out.backend.into()),
                ..Default::default()
            },
            out.bytes,
        ),
        Err(backends::BackendError::Unsupported(r, f)) => {
            (RunResponse::error("unsupported_runtime", format!("{r}/{f}")), vec![])
        }
        Err(backends::BackendError::Input(e)) => (RunResponse::error("input_rejected", e.to_string()), vec![]),
        Err(e) => (RunResponse::error("runtime_error", e.to_string()), vec![]),
    }
}
