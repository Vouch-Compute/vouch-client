//! The Hugging Face ONNX export layout (bge-m3) without ONNX Runtime, so the default test build checks it: which
//! bundle files are the graph, its tokenizer and its external weights, and how inputs are batched and pooled.
//! Batching and pooling follow the engine reference worker (`engine/src/engine/refworker/gpu.py`, `OnnxEmbedder`):
//!
//! * inputs are grouped by token length, at most [`MAX_BATCH`] per run and at most [`TOKEN_BUDGET`] padded tokens
//!   per run (a single input never exceeds it: inputs are truncated to at most 8,192 tokens);
//! * the first graph output is pooled: the first (CLS) token of a `[batch, seq, hidden]` output, or the row itself
//!   when the graph already returns `[batch, hidden]`; then L2-normalised with the norm clamped at 1e-12.

/// Most inputs per ONNX run.
pub const MAX_BATCH: usize = 32;
/// Most padded tokens per ONNX run (the reference worker's bge-m3 budget): bounds activation memory on long inputs.
pub const TOKEN_BUDGET: usize = 8192;

/// The Hugging Face export layout of a bundle (paths are bundle paths).
#[derive(Debug, PartialEq, Eq)]
pub struct HfLayout {
    pub graph: String,
    pub tokenizer: String,
    pub tokenizer_config: Option<String>,
    /// (bundle path, name relative to the graph's directory, as the graph refers to it)
    pub external: Vec<(String, String)>,
}

pub fn hf_layout<'a>(paths: impl IntoIterator<Item = &'a String>) -> Result<HfLayout, String> {
    let paths: Vec<&String> = paths.into_iter().collect();
    let graphs: Vec<&String> = paths.iter().copied().filter(|p| p.to_ascii_lowercase().ends_with(".onnx")).collect();
    let [graph] = graphs.as_slice() else {
        return Err(format!("the bundle must hold exactly one .onnx graph, found {}", graphs.len()));
    };
    let dir = graph.rfind('/').map_or("", |i| &graph[..=i]);
    let find = |name: &str| [format!("{dir}{name}"), name.to_string()].into_iter().find(|c| paths.contains(&c));
    let tokenizer = find("tokenizer.json").ok_or("the bundle has no tokenizer.json")?;
    let external = paths
        .iter()
        .filter_map(|p| {
            let rel = p.strip_prefix(dir)?;
            let lower = rel.to_ascii_lowercase();
            (!rel.contains('/') && (lower.ends_with(".onnx_data") || lower.ends_with(".data")))
                .then(|| ((*p).clone(), rel.to_string()))
        })
        .collect();
    Ok(HfLayout { graph: (*graph).clone(), tokenizer, tokenizer_config: find("tokenizer_config.json"), external })
}

/// Index groups in ascending length order (stable), each within `max_batch` items and `budget` padded tokens.
pub fn length_groups(lens: &[usize], max_batch: usize, budget: usize) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..lens.len()).collect();
    order.sort_by_key(|&i| lens[i]);
    let mut groups = vec![];
    let mut group: Vec<usize> = vec![];
    for i in order {
        // ascending order: the newcomer is the longest of the group
        if !group.is_empty() && (group.len() + 1 > max_batch || lens[i] * (group.len() + 1) > budget) {
            groups.push(std::mem::take(&mut group));
        }
        group.push(i);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups
}

/// Pool one run's first output (`shape` = `[b, l, h]` or `[b, h]`, row-major `data`) to `b` unit vectors.
pub fn cls_normalized(shape: &[i64], data: &[f32]) -> Result<Vec<Vec<f32>>, String> {
    let dims: Vec<usize> = shape.iter().map(|&d| usize::try_from(d).map_err(|_| "negative dimension".to_string())).collect::<Result<_, _>>()?;
    let (b, row_stride, h) = match dims.as_slice() {
        [b, l, h] if *l > 0 => (*b, l * h, *h),
        [b, h] => (*b, *h, *h),
        _ => return Err(format!("unexpected embedding output shape {shape:?}")),
    };
    if h == 0 || data.len() != b * row_stride {
        return Err(format!("embedding output has {} values for shape {shape:?}", data.len()));
    }
    Ok((0..b)
        .map(|r| {
            let mut v = data[r * row_stride..r * row_stride + h].to_vec();
            let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
            v.iter_mut().for_each(|x| *x /= norm);
            v
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_follow_length_count_and_budget() {
        let lens = [5, 1, 3, 3, 8192, 2];
        let g = length_groups(&lens, 3, 8192);
        assert_eq!(g, vec![vec![1, 5, 2], vec![3, 0], vec![4]]);
        // budget: 4 inputs of 3000 tokens never share a run with an 8192 budget beyond two
        assert_eq!(length_groups(&[3000; 4], 32, 8192), vec![vec![0, 1], vec![2, 3]]);
        // every index appears exactly once
        let lens: Vec<usize> = (0..100).map(|i| (i * 37) % 300 + 1).collect();
        let mut all: Vec<usize> = length_groups(&lens, MAX_BATCH, TOKEN_BUDGET).concat();
        all.sort_unstable();
        assert_eq!(all, (0..100).collect::<Vec<_>>());
        assert!(length_groups(&[], 32, 8192).is_empty());
    }

    #[test]
    fn cls_row_is_taken_and_normalised() {
        // b=2, l=2, h=2: CLS rows are [3,4] and [0,0]
        let v = cls_normalized(&[2, 2, 2], &[3., 4., 9., 9., 0., 0., 1., 1.]).unwrap();
        assert_eq!(v, vec![vec![0.6, 0.8], vec![0., 0.]]);
        // already pooled [b, h]
        let v = cls_normalized(&[1, 2], &[0., 2.]).unwrap();
        assert_eq!(v, vec![vec![0., 1.]]);
        assert!(cls_normalized(&[2, 2, 2], &[1.; 7]).is_err());
        assert!(cls_normalized(&[2], &[1.; 2]).is_err());
        assert!(cls_normalized(&[1, 0, 2], &[]).is_err());
    }

    fn layout(paths: &[&str]) -> Result<HfLayout, String> {
        let owned: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        hf_layout(&owned)
    }

    #[test]
    fn bge_m3_layout_is_found() {
        // bge-m3's pinned files (engine registry catalog, PINNED_FILES)
        let l = layout(&[
            "onnx/config.json",
            "onnx/model.onnx",
            "onnx/model.onnx_data",
            "onnx/special_tokens_map.json",
            "onnx/tokenizer.json",
            "onnx/tokenizer_config.json",
        ])
        .unwrap();
        assert_eq!(l.graph, "onnx/model.onnx");
        assert_eq!(l.tokenizer, "onnx/tokenizer.json");
        assert_eq!(l.tokenizer_config.as_deref(), Some("onnx/tokenizer_config.json"));
        assert_eq!(l.external, vec![("onnx/model.onnx_data".to_string(), "model.onnx_data".to_string())]);
    }

    #[test]
    fn layout_rules() {
        // a root tokenizer is used when none sits next to the graph; no external data is fine
        let l = layout(&["model.onnx", "tokenizer.json"]).unwrap();
        assert_eq!((l.tokenizer.as_str(), l.tokenizer_config, l.external.len()), ("tokenizer.json", None, 0));
        let l = layout(&["onnx/model.onnx", "tokenizer.json"]).unwrap();
        assert_eq!(l.tokenizer, "tokenizer.json");
        // weights in another directory are not handed to the graph
        let l = layout(&["onnx/model.onnx", "onnx/tokenizer.json", "other/model.onnx_data", "onnx/sub/x.data"]).unwrap();
        assert!(l.external.is_empty());
        assert!(layout(&["a.onnx", "b.onnx", "tokenizer.json"]).is_err());
        assert!(layout(&["tokenizer.json"]).is_err());
        assert!(layout(&["model.onnx"]).is_err());
    }
}
