//! Hugging Face `tokenizer.json` tokenizers (XLM-R SentencePiece-Unigram for bge-m3, and any other pipeline the
//! `tokenizers` library describes), through the same Rust library the engine reference worker uses from Python.
//!
//! * Built from the signed, hash-checked bundle bytes only: no download, no file access, no network
//!   (the `http` feature and the `hf-hub` client are not compiled in).
//! * Same settings as the reference worker (`engine/src/engine/refworker/gpu.py`, `OnnxEmbedder`): the file's own
//!   pipeline, special tokens added, truncation to the model's maximum length.
//! * The maximum length comes from the bundle's `tokenizer_config.json` (`model_max_length`), capped at
//!   [`MAX_LEN_CAP`]; without one, [`DEFAULT_MAX_LEN`].

use tokenizers::{Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};

/// Upper bound on the sequence length, whatever the bundle says (bge-m3's catalog `max_input`).
pub const MAX_LEN_CAP: usize = 8192;
/// Sequence length when the bundle has no usable `model_max_length`.
pub const DEFAULT_MAX_LEN: usize = 512;

pub struct HfTokenizer {
    inner: Tokenizer,
    pub pad: u32,
    pub max_len: usize,
}

#[derive(serde::Deserialize, Default)]
struct TokenizerConfig {
    model_max_length: Option<serde_json::Value>,
    pad_token: Option<serde_json::Value>,
}

impl HfTokenizer {
    /// `tokenizer_json`: the bundle's `tokenizer.json`; `config`: its `tokenizer_config.json`, if any.
    pub fn from_bytes(tokenizer_json: &[u8], config: Option<&[u8]>) -> Result<Self, String> {
        let cfg: TokenizerConfig = match config {
            Some(b) => serde_json::from_slice(b).map_err(|e| format!("tokenizer_config.json: {e}"))?,
            None => TokenizerConfig::default(),
        };
        // HF writes 1e30 for "no limit"; anything that is not a positive integer falls back to the default
        let max_len = cfg
            .model_max_length
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .filter(|n| *n >= 2)
            .map_or(DEFAULT_MAX_LEN, |n| n.min(MAX_LEN_CAP as u64) as usize);
        let mut inner = Tokenizer::from_bytes(tokenizer_json).map_err(|e| format!("tokenizer.json: {e}"))?;
        inner
            .with_truncation(Some(TruncationParams {
                max_length: max_len,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
                direction: TruncationDirection::Right,
            }))
            .map_err(|e| format!("truncation: {e}"))?;
        // padding is done by the caller, per length group, with the model's own pad token
        inner.with_padding(None);
        let pad_name = match cfg.pad_token {
            Some(serde_json::Value::String(s)) => s,
            Some(serde_json::Value::Object(o)) => o.get("content").and_then(|c| c.as_str()).unwrap_or("<pad>").to_string(),
            _ => "<pad>".to_string(),
        };
        let pad = inner.token_to_id(&pad_name).unwrap_or(0);
        Ok(Self { inner, pad, max_len })
    }

    /// Token ids with special tokens, truncated to `max_len`.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>, String> {
        let enc = self.inner.encode(text, true).map_err(|e| e.to_string())?;
        Ok(enc.get_ids().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xlmr-tiny")
    }

    fn expected() -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(fixture_dir().join("expected.json")).unwrap()).unwrap()
    }

    fn ids_of(v: &serde_json::Value) -> Vec<Vec<u32>> {
        v.as_array().unwrap().iter().map(|r| r.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect()).collect()
    }

    /// bge-m3's pipeline (Precompiled + Replace normaliser, Metaspace, Unigram, <s> .. </s>) with a cut vocabulary:
    /// the ids and the truncation match the Python `tokenizers` used by the reference worker.
    #[test]
    fn xlmr_pipeline_matches_the_reference_ids() {
        let d = fixture_dir().join("onnx");
        let t = HfTokenizer::from_bytes(
            &std::fs::read(d.join("tokenizer.json")).unwrap(),
            Some(&std::fs::read(d.join("tokenizer_config.json")).unwrap()),
        )
        .unwrap();
        let exp = expected();
        assert_eq!(t.max_len, exp["max_len"].as_u64().unwrap() as usize);
        assert_eq!(t.pad, 1, "XLM-R <pad>");
        let inputs: Vec<&str> = exp["inputs"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        for (text, want) in inputs.iter().zip(ids_of(&exp["ids"])) {
            assert_eq!(t.encode(text).unwrap(), want, "{text:?}");
        }
    }

    /// The real bge-m3 `tokenizer.json` (17 MB, not committed). Run with
    /// `POOL_BGE_M3_TOKENIZER=<path to bge-m3 onnx/tokenizer.json> cargo test -p pool-runner real_bge_m3 -- --ignored`.
    #[test]
    #[ignore = "needs bge-m3's tokenizer.json (POOL_BGE_M3_TOKENIZER)"]
    fn real_bge_m3_tokenizer_matches_the_reference_ids() {
        let path = std::env::var_os("POOL_BGE_M3_TOKENIZER").expect("set POOL_BGE_M3_TOKENIZER");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(pool_proto::sha256(&bytes)),
            "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
            "not bge-m3's pinned tokenizer.json"
        );
        let cfg = br#"{"model_max_length": 8192, "pad_token": "<pad>"}"#;
        let t = HfTokenizer::from_bytes(&bytes, Some(cfg)).unwrap();
        let exp: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture_dir().join("real_tokenizer_ids.json")).unwrap()).unwrap();
        let inputs: Vec<&str> = exp["inputs"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        for (text, want) in inputs.iter().zip(ids_of(&exp["ids"])) {
            assert_eq!(t.encode(text).unwrap(), want, "{text:?}");
        }
        // 8192-token cap: a very long input is cut to exactly the maximum, ending with </s>
        let long = "word ".repeat(20_000);
        let ids = t.encode(&long).unwrap();
        assert_eq!(ids.len(), 8192);
        assert_eq!((ids[0], ids[8191]), (0, 2));
    }

    #[test]
    fn max_length_comes_from_the_config_and_is_capped() {
        let tok = std::fs::read(fixture_dir().join("onnx/tokenizer.json")).unwrap();
        let len = |cfg: Option<&[u8]>| HfTokenizer::from_bytes(&tok, cfg).unwrap().max_len;
        assert_eq!(len(None), DEFAULT_MAX_LEN);
        assert_eq!(len(Some(br#"{"model_max_length": 8192}"#)), 8192);
        assert_eq!(len(Some(br#"{"model_max_length": 1000000}"#)), MAX_LEN_CAP);
        assert_eq!(len(Some(br#"{"model_max_length": 1e30}"#)), DEFAULT_MAX_LEN);
        assert_eq!(len(Some(br#"{"model_max_length": 1}"#)), DEFAULT_MAX_LEN);
        assert!(HfTokenizer::from_bytes(&tok, Some(b"not json")).is_err());
        assert!(HfTokenizer::from_bytes(b"{}", None).is_err());
    }
}
