//! Runtime backends, chosen by the signed manifest's `runtime` + `format`:
//!
//! | manifest runtime | format       | feature   | notes |
//! |------------------|--------------|-----------|-------|
//! | `candle`         | safetensors  | `candle`  | pure-Rust CPU fallback; embeddings (BERT) and Whisper; always builds |
//! | `onnxruntime`    | onnx         | `onnx`    | ONNX Runtime via `ort` (load-dynamic: library from a signed backend pack) |
//! | `whisper.cpp`    | gguf         | `whisper` | whisper.cpp via `whisper-rs` (needs cmake + C++; not on the Windows GNU toolchain) |
//! | any (dev builds) | ct2 / onnx   | `dev-trust` | the server's deterministic dev reference model, only for bundles whose `config.json` says `"dev_reference": true` |
//!
//! The task (embed vs transcribe) follows the manifest's `input_format`. Outputs are the closed 1.1.0 objects
//! (`pool_proto::outputs`).

#[cfg(any(feature = "candle", feature = "onnx"))]
pub mod wordpiece;

#[cfg(feature = "candle")]
pub mod candle_embed;
#[cfg(feature = "candle")]
pub mod candle_whisper;
#[cfg(feature = "onnx")]
pub mod onnx;
#[cfg(feature = "whisper")]
pub mod whisper_cpp;
#[cfg(feature = "dev-trust")]
pub mod dev_reference;

use pool_proto::outputs::{encode_embed_result, Transcript};

use crate::bundle::VerifiedBundle;

pub struct Output {
    pub bytes: Vec<u8>,
    pub format: &'static str,
    pub units_device_milli: u64,
    pub backend: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("unsupported runtime {0} (format {1}) in this build")]
    Unsupported(String, String),
    #[error("input rejected: {0}")]
    Input(#[from] crate::input::Rejected),
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// Whisper language code for a BCP 47 hint from the signed `LeaseEnvelope`: the primary subtag,
/// lower-cased (`pt-BR` -> `pt`). Anything that is not 2-3 ASCII letters is ignored (the field is a hint).
pub fn whisper_language(hint: Option<&str>) -> Option<String> {
    let primary = hint?.split(['-', '_']).next()?.to_ascii_lowercase();
    ((2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_lowercase())).then_some(primary)
}

/// `EmbedResult` (closed: model_id, dim, embeddings). `dim` is the model's dimension.
#[allow(dead_code)]
fn embed_output(model_id: &str, vectors: &[Vec<f32>], tokens: u64, backend: &'static str) -> Result<Output, BackendError> {
    let dim = vectors.first().map(Vec::len).unwrap_or(0);
    let bytes = encode_embed_result(model_id, dim, vectors).map_err(rt)?;
    Ok(Output { bytes, format: pool_proto::EMBED_RESULT_FORMAT, units_device_milli: tokens * 1000, backend })
}

/// `Transcript` (closed). Segment times are chunk-relative, ordered and clamped to the chunk; `text` is the
/// segment texts joined by single spaces (`pool_proto::outputs::Transcript::from_raw_segments`).
#[allow(dead_code)]
fn transcript_output(
    model_id: &str,
    language: Option<&str>,
    segs: Vec<(f64, f64, String)>,
    samples: u64,
    backend: &'static str,
) -> Result<Output, BackendError> {
    let duration_milli = samples * 1000 / 16_000;
    let t = Transcript::from_raw_segments(model_id, language, segs, duration_milli as f64 / 1000.0);
    Ok(Output { bytes: t.to_json(), format: pool_proto::TRANSCRIPT_FORMAT, units_device_milli: duration_milli, backend })
}

#[allow(dead_code)]
fn rt<E: std::fmt::Display>(e: E) -> BackendError {
    BackendError::Runtime(e.to_string())
}

/// Run one job on a verified bundle. `input` has already passed `input::validate`. `language` is the lease's
/// optional BCP 47 hint (transcription only).
pub fn run(bundle: &mut VerifiedBundle, input: &[u8], language: Option<&str>) -> Result<Output, BackendError> {
    let m = bundle.manifest.clone();
    let audio = m.input_format == pool_proto::CANONICAL_AUDIO_FORMAT;
    #[cfg(feature = "dev-trust")]
    if dev_reference::is_dev_reference(bundle) {
        return dev_reference::run(bundle, input, language);
    }
    let _ = language;
    match (m.runtime.as_str(), m.format.as_str(), audio) {
        #[cfg(feature = "candle")]
        ("candle", "safetensors", false) => {
            let inputs = crate::input::parse_embed_batch(input)?;
            let e = candle_embed::Embedder::load(bundle).map_err(rt)?;
            let out = e.embed(&inputs).map_err(rt)?;
            embed_output(&m.model_id, &out.vectors, out.tokens, e.backend)
        }
        #[cfg(feature = "candle")]
        ("candle", "safetensors", true) => {
            let pcm = crate::input::decode_flac(input)?;
            let mut t = candle_whisper::Transcriber::load(bundle).map_err(rt)?;
            let out = t.transcribe(&pcm, whisper_language(language).as_deref()).map_err(rt)?;
            let segs = out.segments.into_iter().map(|s| (f64::from(s.start_s), f64::from(s.end_s), s.text)).collect();
            transcript_output(&m.model_id, out.language.as_deref(), segs, pcm.len() as u64, t.backend)
        }
        #[cfg(feature = "onnx")]
        ("onnxruntime", "onnx", false) => {
            let inputs = crate::input::parse_embed_batch(input)?;
            let (vectors, tokens, backend) = onnx::embed(bundle, &inputs).map_err(rt)?;
            embed_output(&m.model_id, &vectors, tokens, backend)
        }
        #[cfg(feature = "whisper")]
        ("whisper.cpp", "gguf", true) => {
            let pcm = crate::input::decode_flac(input)?;
            let (lang, segs) = whisper_cpp::transcribe(bundle, &pcm, whisper_language(language).as_deref()).map_err(rt)?;
            transcript_output(&m.model_id, lang.as_deref(), segs, pcm.len() as u64, "whisper.cpp")
        }
        _ => {
            let _ = input;
            Err(BackendError::Unsupported(m.runtime.clone(), m.format.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_hint_to_whisper_code() {
        assert_eq!(whisper_language(Some("tr")).as_deref(), Some("tr"));
        assert_eq!(whisper_language(Some("pt-BR")).as_deref(), Some("pt"));
        assert_eq!(whisper_language(Some("EN_us")).as_deref(), Some("en"));
        assert_eq!(whisper_language(Some("yue")).as_deref(), Some("yue"));
        for bad in [None, Some(""), Some("x"), Some("english"), Some("e1"), Some("<|en|>"), Some("-en")] {
            assert_eq!(whisper_language(bad), None, "{bad:?}");
        }
    }
}
