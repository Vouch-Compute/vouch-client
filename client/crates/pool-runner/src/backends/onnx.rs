//! ONNX Runtime embeddings (feature `onnx`). `ort` is built with `load-dynamic`: the ONNX Runtime shared library
//! comes from the pinned backend pack ([`crate::accel`]), whose verified directory pool-core passes in
//! `POOL_ORT_PACK_DIR`. With the pack, the DirectML execution provider (any DX12 GPU) runs the model; without it,
//! or if the GPU provider fails, the CPU provider does. Bundle files: `model.onnx`, `vocab.txt`, optional
//! `pooling.json` (same schema as the candle backend).

use std::borrow::Cow;

use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;

use super::wordpiece::WordPiece;
use crate::bundle::VerifiedBundle;

#[derive(serde::Deserialize)]
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

/// Which ONNX Runtime provider ran the job (reported as the backend; diagnostic, never billed).
pub const BACKEND_DIRECTML: &str = "onnxruntime-directml";
pub const BACKEND_CPU: &str = "onnxruntime-cpu";

/// Build the session: DirectML when the pinned pack loaded, the CPU provider otherwise (or if DirectML fails).
fn session(model: &[u8], gpu: bool) -> anyhow::Result<(Session, &'static str)> {
    #[cfg(windows)]
    if gpu {
        use ort::execution_providers::DirectMLExecutionProvider;
        // DirectML needs sequential execution and no memory-pattern optimisation (ONNX Runtime docs)
        let built = Session::builder()
            .and_then(|b| b.with_memory_pattern(false))
            .and_then(|b| b.with_parallel_execution(false))
            .and_then(|b| b.with_execution_providers([DirectMLExecutionProvider::default().build().error_on_failure()]))
            .and_then(|b| b.commit_from_memory(model));
        match built {
            Ok(s) => return Ok((s, BACKEND_DIRECTML)),
            Err(e) => eprintln!("DirectML unavailable, using the CPU provider: {e}"),
        }
    }
    let _ = gpu;
    Ok((Session::builder()?.commit_from_memory(model)?, BACKEND_CPU))
}

pub fn embed(bundle: &mut VerifiedBundle, inputs: &[String]) -> anyhow::Result<(Vec<Vec<f32>>, u64, &'static str)> {
    // The ONNX Runtime library comes only from the pinned pack. Without one, `ort` would LoadLibrary
    // "onnxruntime.dll" from the default search path (System32 ships one on some Windows builds; the runner's own
    // directory): an unpinned library. So no pack, or a refused pack, means no ONNX job at all.
    let gpu = match crate::accel::init_from_env() {
        Ok(true) => std::env::var(crate::accel::FORCE_CPU_ENV).as_deref() != Ok("1"),
        Ok(false) => anyhow::bail!("no ONNX Runtime backend pack: onnxruntime jobs need the pinned pack"),
        Err(e) => anyhow::bail!("{e}"),
    };
    let pooling: Pooling = match bundle.files.get("pooling.json") {
        Some(b) => serde_json::from_slice(b)?,
        None => Pooling::default(),
    };
    let tok = WordPiece::from_vocab_txt(std::str::from_utf8(bundle.file("vocab.txt")?)?, pooling.lowercase, pooling.max_len)
        .map_err(anyhow::Error::msg)?;
    let (mut session, backend) = session(bundle.file("model.onnx")?, gpu)?;
    let has_type_ids = session.inputs.iter().any(|i| i.name == "token_type_ids");
    let mut vectors = Vec::with_capacity(inputs.len());
    let mut tokens = 0u64;
    for chunk in inputs.chunks(32) {
        let ids: Vec<Vec<u32>> = chunk.iter().map(|s| tok.encode(s)).collect();
        tokens += ids.iter().map(|v| v.len() as u64).sum::<u64>();
        let b = ids.len();
        let l = ids.iter().map(Vec::len).max().unwrap_or(2);
        let mut flat = Vec::with_capacity(b * l);
        let mut mask = Vec::with_capacity(b * l);
        for v in &ids {
            flat.extend(v.iter().map(|x| i64::from(*x)));
            flat.extend(std::iter::repeat_n(i64::from(tok.pad), l - v.len()));
            mask.extend(std::iter::repeat_n(1i64, v.len()));
            mask.extend(std::iter::repeat_n(0i64, l - v.len()));
        }
        let mut feed: Vec<(Cow<'_, str>, SessionInputValue<'_>)> = vec![
            ("input_ids".into(), Tensor::from_array(([b, l], flat))?.into()),
            ("attention_mask".into(), Tensor::from_array(([b, l], mask.clone()))?.into()),
        ];
        if has_type_ids {
            feed.push(("token_type_ids".into(), Tensor::from_array(([b, l], vec![0i64; b * l]))?.into()));
        }
        let outputs = session.run(feed)?;
        let (shape, data) = outputs[0].try_extract_tensor::<f32>()?;
        let h = *shape.last().ok_or_else(|| anyhow::anyhow!("bad output shape"))? as usize;
        for (bi, ids_row) in ids.iter().enumerate() {
            let mut v = vec![0f32; h];
            if pooling.mode == "cls" {
                v.copy_from_slice(&data[bi * l * h..bi * l * h + h]);
            } else {
                for t in 0..ids_row.len() {
                    let base = (bi * l + t) * h;
                    for k in 0..h {
                        v[k] += data[base + k];
                    }
                }
                let n = ids_row.len() as f32;
                v.iter_mut().for_each(|x| *x /= n);
            }
            if pooling.normalize {
                let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
                v.iter_mut().for_each(|x| *x /= norm);
            }
            vectors.push(v);
        }
    }
    Ok((vectors, tokens, backend))
}
