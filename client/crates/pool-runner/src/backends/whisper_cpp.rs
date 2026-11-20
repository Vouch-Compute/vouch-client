//! whisper.cpp transcription (feature `whisper`, via `whisper-rs`). Bundle file: `model.gguf`
//! (a whisper.cpp ggml/gguf model). Builds on Linux/macOS CI (cmake + clang). On the Windows GNU
//! toolchain whisper-rs-sys passes the MSVC-only flag `/utf-8` and needs libclang, so the candle
//! backend is used there.

use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

use crate::bundle::VerifiedBundle;

/// Returns `(language used, segments)`. `language_hint` is a Whisper code (`super::whisper_language`); when
/// whisper.cpp knows it, auto-detection is skipped.
#[allow(clippy::type_complexity)]
pub fn transcribe(
    bundle: &VerifiedBundle,
    pcm: &[f32],
    language_hint: Option<&str>,
) -> anyhow::Result<(Option<String>, Vec<(f64, f64, String)>)> {
    let ctx = WhisperContext::new_from_buffer_with_params(bundle.file("model.gguf")?, WhisperContextParameters::default())
        .map_err(|e| anyhow::anyhow!("whisper init: {e:?}"))?;
    let mut state = ctx.create_state().map_err(|e| anyhow::anyhow!("whisper state: {e:?}"))?;
    let hint = language_hint.filter(|h| whisper_rs::get_lang_id(h).is_some());
    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
    params.set_language(Some(hint.unwrap_or("auto")));
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_special(false);
    params.set_print_timestamps(false);
    state.full(params, pcm).map_err(|e| anyhow::anyhow!("whisper run: {e:?}"))?;
    let language = match hint {
        Some(h) => Some(h.to_string()),
        None => whisper_rs::get_lang_str(state.full_lang_id_from_state()).map(str::to_string),
    };
    let mut segs = Vec::new();
    for i in 0..state.full_n_segments() {
        if let Some(seg) = state.get_segment(i) {
            let text = seg.to_str_lossy().map_err(|e| anyhow::anyhow!("{e:?}"))?.trim().to_string();
            // whisper.cpp timestamps are in centiseconds
            segs.push((seg.start_timestamp() as f64 / 100.0, seg.end_timestamp() as f64 / 100.0, text));
        }
    }
    Ok((language, segs))
}
