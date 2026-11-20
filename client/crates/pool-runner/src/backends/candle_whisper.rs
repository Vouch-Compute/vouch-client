//! CPU transcription with candle (pure Rust Whisper) from a `safetensors` bundle. This is the fallback
//! when whisper.cpp (feature `whisper`) is not available, e.g. on the Windows GNU toolchain.
//! Bundle files: `config.json` (HF WhisperConfig), `model.safetensors`, `tokenizer.json` (HF byte-level BPE).
//! Greedy decoding without timestamps, one 30 s window at a time; for multilingual models the language is the
//! lease's hint when present (1.1.0), else auto-detected on the first window.

use std::collections::HashMap;

use candle_core::{DType, Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::whisper::{self as w, audio, model::Whisper, Config};

use crate::bundle::VerifiedBundle;

pub struct Transcriber {
    model: Whisper,
    filters: Vec<f32>,
    vocab: HashMap<u32, String>,
    special: HashMap<String, u32>,
    device: Device,
    /// `candle-cuda` or `candle-cpu`: what really ran, reported with the job.
    pub backend: &'static str,
    /// Upper bound on generated tokens per 30 s window.
    pub max_tokens_per_window: usize,
}

pub struct Segment {
    pub start_s: f32,
    pub end_s: f32,
    pub text: String,
}

pub struct Transcript {
    pub text: String,
    pub language: Option<String>,
    pub segments: Vec<Segment>,
}

/// librosa `filters.mel(sr=16000, n_fft=400, n_mels)` with Slaney scale and norm (what Whisper uses).
pub fn mel_filters(n_mels: usize) -> Vec<f32> {
    let sr = 16_000f64;
    let n_fft = 400usize;
    let n_freq = n_fft / 2 + 1;
    let f_sp = 200.0 / 3.0;
    let min_log_hz = 1000.0;
    let min_log_mel = min_log_hz / f_sp;
    let logstep = (6.4f64).ln() / 27.0;
    let hz_to_mel = |f: f64| if f < min_log_hz { f / f_sp } else { min_log_mel + (f / min_log_hz).ln() / logstep };
    let mel_to_hz = |m: f64| if m < min_log_mel { f_sp * m } else { min_log_hz * (logstep * (m - min_log_mel)).exp() };
    let (mmin, mmax) = (hz_to_mel(0.0), hz_to_mel(sr / 2.0));
    let mel_f: Vec<f64> =
        (0..n_mels + 2).map(|i| mel_to_hz(mmin + (mmax - mmin) * i as f64 / (n_mels + 1) as f64)).collect();
    let fft_f: Vec<f64> = (0..n_freq).map(|j| sr / 2.0 * j as f64 / (n_freq - 1) as f64).collect();
    let mut out = vec![0f32; n_mels * n_freq];
    for i in 0..n_mels {
        let enorm = 2.0 / (mel_f[i + 2] - mel_f[i]);
        for (j, f) in fft_f.iter().enumerate() {
            let lower = (f - mel_f[i]) / (mel_f[i + 1] - mel_f[i]);
            let upper = (mel_f[i + 2] - f) / (mel_f[i + 2] - mel_f[i + 1]);
            out[i * n_freq + j] = (lower.min(upper).max(0.0) * enorm) as f32;
        }
    }
    out
}

/// GPT-2 byte-level BPE: unicode char -> byte.
fn byte_decoder() -> HashMap<char, u8> {
    let mut bs: Vec<u32> = (b'!' as u32..=b'~' as u32).chain(0xA1..=0xAC).chain(0xAE..=0xFF).collect();
    let mut cs = bs.clone();
    let mut n = 0;
    for b in 0..256u32 {
        if !bs.contains(&b) {
            bs.push(b);
            cs.push(256 + n);
            n += 1;
        }
    }
    bs.into_iter().zip(cs).map(|(b, c)| (char::from_u32(c).unwrap(), b as u8)).collect()
}

impl Transcriber {
    pub fn load(bundle: &mut VerifiedBundle) -> anyhow::Result<Self> {
        let (device, backend) = crate::accel::candle_device();
        let config: Config = serde_json::from_slice(bundle.file("config.json")?)?;
        let tj: serde_json::Value = serde_json::from_slice(bundle.file("tokenizer.json")?)?;
        let mut vocab = HashMap::new();
        if let Some(v) = tj.pointer("/model/vocab").and_then(|v| v.as_object()) {
            for (tok, id) in v {
                if let Some(id) = id.as_u64() {
                    vocab.insert(id as u32, tok.clone());
                }
            }
        }
        let mut special = HashMap::new();
        if let Some(arr) = tj.get("added_tokens").and_then(|v| v.as_array()) {
            for t in arr {
                if let (Some(id), Some(c)) = (t.get("id").and_then(|x| x.as_u64()), t.get("content").and_then(|x| x.as_str())) {
                    special.insert(c.to_string(), id as u32);
                }
            }
        }
        for needed in [w::SOT_TOKEN, w::TRANSCRIBE_TOKEN, w::NO_TIMESTAMPS_TOKEN, w::EOT_TOKEN] {
            if !special.contains_key(needed) {
                anyhow::bail!("tokenizer lacks {needed}");
            }
        }
        let filters = mel_filters(config.num_mel_bins);
        let weights = bundle.files.remove("model.safetensors").ok_or_else(|| anyhow::anyhow!("bundle lacks model.safetensors"))?;
        let vb = VarBuilder::from_buffered_safetensors(weights, DType::F32, &device)?;
        let max_tokens_per_window = config.max_target_positions / 2;
        let model = Whisper::load(&vb, config)?;
        Ok(Self { model, filters, vocab, special, device, backend, max_tokens_per_window })
    }

    fn decode_tokens(&self, ids: &[u32]) -> String {
        let bd = byte_decoder();
        let specials: std::collections::HashSet<u32> = self.special.values().copied().collect();
        let mut bytes = Vec::new();
        for id in ids {
            if specials.contains(id) {
                continue;
            }
            if let Some(t) = self.vocab.get(id) {
                bytes.extend(t.chars().filter_map(|c| bd.get(&c).copied()));
            }
        }
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    fn language_tokens(&self) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self
            .special
            .iter()
            .filter(|(k, _)| {
                k.len() >= 6 && k.len() <= 9 && k.starts_with("<|") && k.ends_with("|>") && k[2..k.len() - 2].chars().all(|c| c.is_ascii_lowercase())
                    && !matches!(&k[2..k.len() - 2], "transcribe" | "translate" | "notimestamps" | "nospeech" | "nocaptions" | "endoftext")
            })
            .map(|(k, v)| (k[2..k.len() - 2].to_string(), *v))
            .collect();
        v.sort_by_key(|x| x.1);
        v
    }

    fn logits_last(&mut self, tokens: &[u32], features: &Tensor, flush: bool) -> anyhow::Result<Vec<f32>> {
        let t = Tensor::new(tokens, &self.device)?.unsqueeze(0)?;
        let ys = self.model.decoder.forward(&t, features, flush)?;
        let (_, seq_len, _) = ys.dims3()?;
        let logits = self.model.decoder.final_linear(&ys.i((..1, seq_len - 1..))?)?.i(0)?.i(0)?;
        Ok(logits.to_vec1::<f32>()?)
    }

    /// `language`: the lease's hint as a Whisper code (`super::whisper_language`). When the model knows that
    /// language token it is forced and auto-detection is skipped; otherwise the model detects.
    pub fn transcribe(&mut self, pcm: &[f32], language_hint: Option<&str>) -> anyhow::Result<Transcript> {
        let sot = self.special[w::SOT_TOKEN];
        let eot = self.special[w::EOT_TOKEN];
        let transcribe = self.special[w::TRANSCRIBE_TOKEN];
        let no_ts = self.special[w::NO_TIMESTAMPS_TOKEN];
        let langs = self.language_tokens();
        let n_mels = self.model.config.num_mel_bins;
        let max_ctx = self.model.config.max_target_positions;
        let suppress: Vec<u32> = self.model.config.suppress_tokens.clone();
        let mut language: Option<(String, u32)> =
            language_hint.and_then(|h| langs.iter().find(|(code, _)| code == h).cloned());
        let mut segments = Vec::new();
        for (wi, window) in pcm.chunks(w::N_SAMPLES).enumerate() {
            let mel = audio::pcm_to_mel(&self.model.config, window, &self.filters);
            let frames = mel.len() / n_mels;
            let mel = Tensor::from_vec(mel, (1, n_mels, frames), &self.device)?;
            let mel = mel.narrow(2, 0, frames.min(w::N_FRAMES))?;
            let features = self.model.encoder.forward(&mel, true)?;
            if language.is_none() && !langs.is_empty() {
                let logits = self.logits_last(&[sot], &features, true)?;
                language = langs
                    .iter()
                    .filter(|(_, id)| (*id as usize) < logits.len())
                    .max_by(|a, b| logits[a.1 as usize].total_cmp(&logits[b.1 as usize]))
                    .cloned();
            }
            let mut tokens = vec![sot];
            if let Some((_, id)) = &language {
                tokens.push(*id);
            }
            tokens.extend([transcribe, no_ts]);
            let prefix = tokens.len();
            for i in 0..self.max_tokens_per_window {
                if tokens.len() >= max_ctx {
                    break;
                }
                let mut logits = self.logits_last(&tokens, &features, i == 0)?;
                for &s in &suppress {
                    if let Some(x) = logits.get_mut(s as usize) {
                        *x = f32::NEG_INFINITY;
                    }
                }
                // never emit start/language/task tokens inside the text
                for &s in [sot, transcribe, no_ts].iter().chain(langs.iter().map(|(_, id)| id)) {
                    if let Some(x) = logits.get_mut(s as usize) {
                        *x = f32::NEG_INFINITY;
                    }
                }
                let next = logits
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.total_cmp(b.1))
                    .map(|(i, _)| i as u32)
                    .unwrap_or(eot);
                if next == eot {
                    break;
                }
                tokens.push(next);
            }
            self.model.reset_kv_cache();
            let start_s = (wi * w::N_SAMPLES) as f32 / w::SAMPLE_RATE as f32;
            segments.push(Segment {
                start_s,
                end_s: start_s + window.len() as f32 / w::SAMPLE_RATE as f32,
                text: self.decode_tokens(&tokens[prefix..]),
            });
        }
        let text = segments.iter().map(|s| s.text.as_str()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
        Ok(Transcript { text, language: language.map(|l| l.0), segments })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mel_filters_match_librosa_shape_and_norm() {
        let f = mel_filters(80);
        assert_eq!(f.len(), 80 * 201);
        // every filter has positive area and no negative weights
        for i in 0..80 {
            let row = &f[i * 201..(i + 1) * 201];
            assert!(row.iter().all(|x| *x >= 0.0));
            assert!(row.iter().sum::<f32>() > 0.0, "row {i}");
        }
        // librosa reference value: filters[0][1] for sr=16000, n_fft=400, n_mels=80 = 0.02486259
        assert!((f[1] - 0.024_862_59).abs() < 1e-5, "{}", f[1]);
    }

    #[test]
    fn byte_level_decoder_covers_all_bytes() {
        let d = byte_decoder();
        assert_eq!(d.len(), 256);
        assert_eq!(d[&'Ġ'], b' ');
        assert_eq!(d[&'a'], b'a');
    }
}
