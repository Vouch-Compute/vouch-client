//! CPU embeddings with candle (pure Rust): BERT-family encoders from a `safetensors` bundle.
//! Bundle files: `config.json` (HF BertConfig), `model.safetensors`, `vocab.txt`, optional `pooling.json`
//! (`{"mode":"mean"|"cls","normalize":true,"lowercase":true,"max_len":256}`).

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use serde::Deserialize;

use super::wordpiece::WordPiece;
use crate::bundle::VerifiedBundle;

#[derive(Deserialize)]
#[serde(default)]
struct Pooling {
    mode: String,
    normalize: bool,
    lowercase: bool,
    max_len: usize,
}

impl Default for Pooling {
    fn default() -> Self {
        Self { mode: "mean".into(), normalize: true, lowercase: true, max_len: 256 }
    }
}

pub struct Embedder {
    model: BertModel,
    tok: WordPiece,
    pooling: Pooling,
    device: Device,
    /// `candle-cuda` or `candle-cpu`: what really ran, reported with the job.
    pub backend: &'static str,
}

pub struct Embeddings {
    pub vectors: Vec<Vec<f32>>,
    pub tokens: u64,
}

impl Embedder {
    pub fn load(bundle: &mut VerifiedBundle) -> anyhow::Result<Self> {
        let (device, backend) = crate::accel::candle_device();
        let config: Config = serde_json::from_slice(bundle.file("config.json")?)?;
        let pooling: Pooling = match bundle.files.get("pooling.json") {
            Some(b) => serde_json::from_slice(b)?,
            None => Pooling::default(),
        };
        let tok = WordPiece::from_vocab_txt(
            std::str::from_utf8(bundle.file("vocab.txt")?)?,
            pooling.lowercase,
            pooling.max_len.min(config.max_position_embeddings),
        )
        .map_err(anyhow::Error::msg)?;
        let weights = bundle.files.remove("model.safetensors").ok_or_else(|| anyhow::anyhow!("bundle lacks model.safetensors"))?;
        let vb = VarBuilder::from_buffered_safetensors(weights, DType::F32, &device)?;
        let model = BertModel::load(vb, &config)?;
        Ok(Self { model, tok, pooling, device, backend })
    }

    pub fn embed(&self, inputs: &[String]) -> anyhow::Result<Embeddings> {
        let mut vectors = Vec::with_capacity(inputs.len());
        let mut tokens = 0u64;
        for chunk in inputs.chunks(32) {
            let ids: Vec<Vec<u32>> = chunk.iter().map(|s| self.tok.encode(s)).collect();
            tokens += ids.iter().map(|v| v.len() as u64).sum::<u64>();
            let max = ids.iter().map(Vec::len).max().unwrap_or(2);
            let mut flat = Vec::with_capacity(ids.len() * max);
            let mut mask = Vec::with_capacity(ids.len() * max);
            for v in &ids {
                flat.extend(v.iter().copied());
                flat.extend(std::iter::repeat_n(self.tok.pad, max - v.len()));
                mask.extend(std::iter::repeat_n(1u32, v.len()));
                mask.extend(std::iter::repeat_n(0u32, max - v.len()));
            }
            let b = ids.len();
            let input_ids = Tensor::from_vec(flat, (b, max), &self.device)?;
            let mask_t = Tensor::from_vec(mask, (b, max), &self.device)?;
            let token_type = input_ids.zeros_like()?;
            let hidden = self.model.forward(&input_ids, &token_type, Some(&mask_t))?; // (b, l, h)
            let pooled = if self.pooling.mode == "cls" {
                hidden.narrow(1, 0, 1)?.squeeze(1)?
            } else {
                let m = mask_t.to_dtype(DType::F32)?.unsqueeze(2)?; // (b, l, 1)
                let summed = hidden.broadcast_mul(&m)?.sum(1)?; // (b, h)
                let counts = m.sum(1)?; // (b, 1)
                summed.broadcast_div(&counts)?
            };
            let pooled = if self.pooling.normalize {
                let norm = pooled.sqr()?.sum_keepdim(1)?.sqrt()?.clamp(1e-12, f64::MAX)?;
                pooled.broadcast_div(&norm)?
            } else {
                pooled
            };
            vectors.extend(pooled.to_vec2::<f32>()?);
        }
        Ok(Embeddings { vectors, tokens })
    }
}
