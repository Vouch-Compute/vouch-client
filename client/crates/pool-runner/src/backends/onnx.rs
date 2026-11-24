//! ONNX Runtime embeddings (feature `onnx`). `ort` is built with `load-dynamic`: the ONNX Runtime shared library
//! comes from this OS's pinned runtime pack ([`crate::accel`]), whose verified directory pool-core passes in
//! `POOL_ORT_PACK_DIR`; without a pack no ONNX job runs. Windows: the DirectML execution provider (any DX12 GPU)
//! runs the model, or the CPU provider if DirectML fails or the GPU is switched off. macOS arm64 and Linux x64: the
//! pack is CPU-only, so the CPU provider runs it.
//!
//! Two bundle layouts:
//! * **WordPiece**: `model.onnx` + `vocab.txt` at the bundle root, optional `pooling.json` (same schema as the candle
//!   backend). Unchanged.
//! * **Hugging Face export** (bge-m3): exactly one `*.onnx` graph, a `tokenizer.json` next to it (or at the root), an
//!   optional `tokenizer_config.json`, and the graph's external weights (`*.onnx_data` / `*.data` next to the graph,
//!   e.g. `onnx/model.onnx` + `onnx/model.onnx_data`). The external weights reach ONNX Runtime **from memory** (the
//!   bytes the runner already hash-checked), so ONNX Runtime opens no weight file itself. Tokenisation, batching and
//!   pooling follow the engine reference worker: [`super::hf_tokenizer`], [`super::hf_export`].

use std::borrow::Cow;

use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;

use super::hf_tokenizer::HfTokenizer;
use super::hf_export::{self, hf_layout};
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

/// External weight files handed to ONNX Runtime from memory: (name as the graph refers to it, bytes).
type External = [(String, &'static [u8])];

fn builder(external: &External) -> ort::Result<ort::session::builder::SessionBuilder> {
    let mut b = Session::builder()?;
    for (name, bytes) in external {
        b = b.with_external_initializer_file_in_memory(name, Cow::Borrowed(*bytes))?;
    }
    Ok(b)
}

/// Build the session: DirectML when the pinned pack loaded, the CPU provider otherwise (or if DirectML fails).
fn session(model: &[u8], external: &External, gpu: bool) -> anyhow::Result<(Session, &'static str)> {
    #[cfg(windows)]
    if gpu {
        use ort::execution_providers::DirectMLExecutionProvider;
        // DirectML needs sequential execution and no memory-pattern optimisation (ONNX Runtime docs)
        let built = builder(external)
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
    Ok((builder(external)?.commit_from_memory(model)?, BACKEND_CPU))
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
    if bundle.files.contains_key("model.onnx") && bundle.files.contains_key("vocab.txt") {
        embed_wordpiece(bundle, inputs, gpu)
    } else {
        embed_hf(bundle, inputs, gpu)
    }
}

fn embed_hf(bundle: &mut VerifiedBundle, inputs: &[String], gpu: bool) -> anyhow::Result<(Vec<Vec<f32>>, u64, &'static str)> {
    let layout = hf_layout(bundle.files.keys()).map_err(anyhow::Error::msg)?;
    let tok = HfTokenizer::from_bytes(
        bundle.file(&layout.tokenizer)?,
        layout.tokenizer_config.as_deref().map(|p| bundle.file(p)).transpose()?,
    )
    .map_err(anyhow::Error::msg)?;
    // The weights (2.3 GB for bge-m3) move out of the bundle without a copy and live as long as this one-job process:
    // ONNX Runtime reads them from memory, and a DirectML attempt that fails can hand the same bytes to the CPU session.
    let mut external = Vec::with_capacity(layout.external.len());
    for (path, name) in &layout.external {
        let bytes = bundle.files.remove(path).ok_or_else(|| anyhow::anyhow!("bundle lacks {path}"))?;
        let leaked: &'static [u8] = bytes.leak();
        external.push((name.clone(), leaked));
    }
    let (mut session, backend) = session(bundle.file(&layout.graph)?, &external, gpu)?;
    let has_type_ids = session.inputs.iter().any(|i| i.name == "token_type_ids");

    let ids: Vec<Vec<u32>> = inputs.iter().map(|s| tok.encode(s)).collect::<Result<_, _>>().map_err(anyhow::Error::msg)?;
    let tokens = ids.iter().map(|v| v.len() as u64).sum::<u64>();
    let lens: Vec<usize> = ids.iter().map(Vec::len).collect();
    let mut out: Vec<Option<Vec<f32>>> = vec![None; inputs.len()];
    for group in hf_export::length_groups(&lens, hf_export::MAX_BATCH, hf_export::TOKEN_BUDGET) {
        let b = group.len();
        let l = group.iter().map(|&i| lens[i]).max().unwrap_or(0).max(1);
        let mut flat = Vec::with_capacity(b * l);
        let mut mask = Vec::with_capacity(b * l);
        for &i in &group {
            flat.extend(ids[i].iter().map(|x| i64::from(*x)));
            flat.extend(std::iter::repeat_n(i64::from(tok.pad), l - lens[i]));
            mask.extend(std::iter::repeat_n(1i64, lens[i]));
            mask.extend(std::iter::repeat_n(0i64, l - lens[i]));
        }
        let mut feed: Vec<(Cow<'_, str>, SessionInputValue<'_>)> = vec![
            ("input_ids".into(), Tensor::from_array(([b, l], flat))?.into()),
            ("attention_mask".into(), Tensor::from_array(([b, l], mask))?.into()),
        ];
        if has_type_ids {
            feed.push(("token_type_ids".into(), Tensor::from_array(([b, l], vec![0i64; b * l]))?.into()));
        }
        let outputs = session.run(feed)?;
        let (shape, data) = outputs[0].try_extract_tensor::<f32>()?;
        let vecs = hf_export::cls_normalized(shape, data).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(vecs.len() == b, "embedding output has {} rows for {b} inputs", vecs.len());
        for (&i, v) in group.iter().zip(vecs) {
            out[i] = Some(v);
        }
    }
    let vectors = out.into_iter().map(|v| v.ok_or_else(|| anyhow::anyhow!("missing embedding"))).collect::<anyhow::Result<_>>()?;
    Ok((vectors, tokens, backend))
}

fn embed_wordpiece(bundle: &mut VerifiedBundle, inputs: &[String], gpu: bool) -> anyhow::Result<(Vec<Vec<f32>>, u64, &'static str)> {
    let pooling: Pooling = match bundle.files.get("pooling.json") {
        Some(b) => serde_json::from_slice(b)?,
        None => Pooling::default(),
    };
    let tok = WordPiece::from_vocab_txt(std::str::from_utf8(bundle.file("vocab.txt")?)?, pooling.lowercase, pooling.max_len)
        .map_err(anyhow::Error::msg)?;
    let (mut session, backend) = session(bundle.file("model.onnx")?, &[], gpu)?;
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
