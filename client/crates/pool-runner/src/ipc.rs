//! Memory-only pipe protocol between `pool-core` (parent) and `pool-runner` (sandboxed child).
//!
//! parent -> child (stdin):  frame(RunRequest JSON) frame(input bytes), then EOF
//! child -> parent (stdout): frame(RunResponse JSON) frame(output bytes)
//! frame = u32 little-endian length + bytes. Nothing touches the disk.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Hard ceiling for any single frame (inputs are canonical chunks of a few MB at most).
pub const MAX_FRAME: u32 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunRequest {
    /// Root-signed KeySet (COSE, base64). The runner re-verifies it against its own embedded roots.
    pub keyset_b64: String,
    /// Server-signed ModelManifest (COSE, base64), verified with the KeySet's `registry` key.
    pub manifest_b64: String,
    /// `model_hash` from the Offer / LeaseEnvelope (hex): must equal SHA-256 of the manifest payload.
    pub expected_model_hash_hex: String,
    /// Directory holding the bundle files (read-only for the sandbox).
    pub model_dir: String,
    /// `input_format` from the LeaseEnvelope.
    pub input_format: String,
    /// Upper bound for the output frame.
    pub max_output_bytes: u64,
    /// Optional BCP 47 transcription hint from the signed `LeaseEnvelope` (node protocol 1.1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RunResponse {
    pub ok: bool,
    /// `input_rejected` | `bundle_invalid` | `unsupported_runtime` | `runtime_error` | `sandbox_error`
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub output_format: Option<String>,
    /// Diagnostic only (never billed): audio milliseconds or tokens x 1000.
    pub units_device_milli: Option<u64>,
    pub backend: Option<String>,
}

impl RunResponse {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self { ok: false, error_code: Some(code.into()), message: Some(message.into()), ..Default::default() }
    }
}

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| io::Error::other("frame too large"))?;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read, max: u64) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME || u64::from(len) > max {
        return Err(io::Error::other("frame exceeds limit"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 10).unwrap(), b"hello");
        assert_eq!(read_frame(&mut r, 10).unwrap(), b"");
        let mut r = &buf[..];
        assert!(read_frame(&mut r, 4).is_err());
    }
}
