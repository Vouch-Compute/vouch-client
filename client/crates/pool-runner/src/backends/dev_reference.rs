//! the server's deterministic **dev reference model**, compiled only into dev builds
//! (`dev-trust`). The shared dev catalog (`whisper-large-v3-turbo`, `whisper-tiny`: `ct2`; `bge-m3`,
//! `bge-small-en-v1.5`: `onnx`) ships tiny placeholder bundles whose `config.json` carries
//! `"dev_reference": true` and no real weights. With this backend the real contributor app can run the live
//! end-to-end flow and produce exactly what the server's dev reference checks expect (the server's `StubBackend` does the
//! same in Python). Release builds do not contain this file, so a production node can never answer with it.
//!
//! The bundle still went through the full signed-bundle chain (KeySet -> registry-signed manifest -> per-file SHA-256 ->
//! file-type policy, including the `model.bin` header check) before this code sees it; it executes
//! nothing from the bundle and only reads `config.json`.
//!
//! * Embeddings: for input `s`, concatenate `SHA-256(f"{counter}:{s}")` for counter = 0, 1, ..., map each byte `b`
//!   to `(b - 127.5) / 127.5`, take the first `D` values (`config.json` `dim`) and normalise to unit length.
//! * Transcripts: `h = SHA-256(chunk bytes)`; text = `WORDS[h[i] % 20]` for `i` in `0..16` joined by single spaces;
//!   one segment `{0, chunk duration rounded to ms, text}`; `language` = the lease hint, else `"en"`.

use pool_proto::outputs::{encode_embed_result, Transcript};
use pool_proto::sha256;

use super::{BackendError, Output};
use crate::bundle::VerifiedBundle;

pub const WORDS: [&str; 20] = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima", "mike",
    "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
];

fn config(bundle: &VerifiedBundle) -> Option<serde_json::Value> {
    serde_json::from_slice(bundle.files.get("config.json")?).ok()
}

/// Marker string the release CI job looks for: a packaged release binary must not contain it (security review R1 (b),
/// `client/ci/release-marker-check.sh`). It is part of every dev reference output path, so it cannot be optimised out
/// while this backend is compiled in.
pub const DEV_REFERENCE_MARKER: &str = "VOUCH-DEV-REFERENCE-BACKEND";

/// Only `ct2` / `onnx` bundles whose verified `config.json` says `"dev_reference": true` **and** whose manifest chain
/// was verified under a dev KeySet root. A production-signed bundle never triggers this backend,
/// even in a dev build, whatever its `config.json` says.
pub fn is_dev_reference(bundle: &VerifiedBundle) -> bool {
    bundle.dev_root
        && matches!(bundle.manifest.format.as_str(), "ct2" | "onnx")
        && config(bundle).and_then(|c| c.get("dev_reference").and_then(|v| v.as_bool())) == Some(true)
}

pub fn ref_embed(text: &str, dim: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(dim + 32);
    let mut counter = 0u64;
    while out.len() < dim {
        out.extend(sha256(format!("{counter}:{text}").as_bytes()).iter().map(|b| (f64::from(*b) - 127.5) / 127.5));
        counter += 1;
    }
    out.truncate(dim);
    let n = out.iter().map(|x| x * x).sum::<f64>().sqrt();
    let n = if n == 0.0 { 1.0 } else { n };
    out.iter().map(|x| x / n).collect()
}

pub fn ref_transcript(chunk: &[u8]) -> String {
    sha256(chunk)[..16].iter().map(|b| WORDS[usize::from(*b) % WORDS.len()]).collect::<Vec<_>>().join(" ")
}

/// Emulated device throughput. The reference model itself is instant, which no real device is: a dev node that
/// answers a 10-minute chunk in a few milliseconds would not match a real device's timing.
/// The dev reference backend therefore takes the time a device running at the server's dev benchmark rate would take:
/// 60 audio seconds and 2,500 tokens per second, the rate the server derives from a sustained benchmark whose 20 slices
/// each carry 1 h audio / 150k tokens per 60 s. The e2e
/// reference worker paces its stub the same way. Dev builds only.
pub const DEV_AUDIO_S_PER_S: f64 = 60.0;
pub const DEV_TOKENS_PER_S: f64 = 2500.0;

fn pace(started: std::time::Instant, seconds: f64) {
    let target = std::time::Duration::from_secs_f64(seconds.clamp(0.0, 3600.0));
    if let Some(left) = target.checked_sub(started.elapsed()) {
        std::thread::sleep(left);
    }
}

pub fn run(bundle: &VerifiedBundle, input: &[u8], language: Option<&str>) -> Result<Output, BackendError> {
    let started = std::time::Instant::now();
    let _ = std::hint::black_box(DEV_REFERENCE_MARKER);
    let out = run_instant(bundle, input, language)?;
    if out.format == pool_proto::TRANSCRIPT_FORMAT {
        pace(started, out.units_device_milli as f64 / 1000.0 / DEV_AUDIO_S_PER_S);
    } else {
        // input bytes bound the server's dev token count from above, so the emulated rate never exceeds 2,500/s
        pace(started, input.len() as f64 / DEV_TOKENS_PER_S);
    }
    Ok(out)
}

fn run_instant(bundle: &VerifiedBundle, input: &[u8], language: Option<&str>) -> Result<Output, BackendError> {
    let m = &bundle.manifest;
    if m.input_format == pool_proto::CANONICAL_AUDIO_FORMAT {
        let info = crate::input::validate_flac_header(input)?;
        // the server meters `total_samples * 1000 // sample_rate` milliseconds
        let duration_milli = info.total_samples * 1000 / u64::from(info.sample_rate);
        let text = ref_transcript(input);
        let lang = language.filter(|l| !l.is_empty()).unwrap_or("en");
        let t = Transcript::from_raw_segments(
            &m.model_id,
            Some(lang),
            [(0.0, duration_milli as f64 / 1000.0, text)],
            duration_milli as f64 / 1000.0,
        );
        return Ok(Output { bytes: t.to_json(), format: pool_proto::TRANSCRIPT_FORMAT, units_device_milli: duration_milli, backend: "dev-reference" });
    }
    let dim = config(bundle)
        .and_then(|c| c.get("dim").and_then(|d| d.as_u64()))
        .filter(|d| (1..=16_384).contains(d))
        .ok_or_else(|| BackendError::Runtime("dev reference bundle lacks a valid dim".into()))? as usize;
    let inputs = crate::input::parse_embed_batch(input)?;
    let vectors: Vec<Vec<f64>> = inputs.iter().map(|s| ref_embed(s, dim)).collect();
    let bytes = encode_embed_result(&m.model_id, dim, &vectors).map_err(|e| BackendError::Runtime(e.to_string()))?;
    let words: u64 = inputs.iter().map(|s| s.split_whitespace().count() as u64).sum();
    Ok(Output { bytes, format: pool_proto::EMBED_RESULT_FORMAT, units_device_milli: words * 1000, backend: "dev-reference" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(format: &str, dev_root: bool) -> VerifiedBundle {
        let m = pool_proto::objects::ModelManifest {
            model_id: "bge-small-en-v1.5".into(),
            version: "1".into(),
            source_repo: "dev/reference".into(),
            source_commit: "0".repeat(40),
            license: "Apache-2.0".into(),
            format: format.into(),
            runtime: "onnxruntime".into(),
            quantization: "f32".into(),
            files: vec![],
            min_vram_mb: 0,
            min_ram_mb: 1,
            tolerance_class: "cosine-0.999".into(),
            tiers: vec!["cpu".into()],
            input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
            issued_at: 1,
            approvals: vec![],
            approval_mode: None,
        };
        let mut files = std::collections::BTreeMap::new();
        files.insert("config.json".to_string(), br#"{"dev_reference": true, "dim": 8}"#.to_vec());
        VerifiedBundle { manifest: m, model_hash: [0; 32], files, dev_root }
    }

    /// security review R1 (d): `config.json` alone is not enough; the manifest chain must end at a dev KeySet root.
    #[test]
    fn dev_reference_needs_a_dev_keyset_root() {
        assert!(is_dev_reference(&bundle("onnx", true)));
        assert!(!is_dev_reference(&bundle("onnx", false)), "a production-signed bundle never runs the dev backend");
        assert!(!is_dev_reference(&bundle("safetensors", true)));
    }

    /// Expected values printed by the server's own Python reference, so both sides agree:
    /// `ref_embed("hello world", 4)` and `ref_transcript(b"tally")`.
    #[test]
    fn matches_vaults_python_reference() {
        let expected = [-0.47419640420228004, -0.7596350164405458, -0.3452886438366117, 0.2808347636537775];
        let v = ref_embed("hello world", 4);
        for (a, b) in v.iter().zip(expected) {
            assert!((a - b).abs() < 1e-15, "{a} vs {b}");
        }
        assert!((ref_embed("x", 384).iter().map(|x| x * x).sum::<f64>() - 1.0).abs() < 1e-9);
        assert_eq!(
            ref_transcript(b"tally"),
            "quebec kilo sierra lima foxtrot foxtrot tango lima romeo bravo kilo india kilo romeo romeo lima"
        );
    }
}
