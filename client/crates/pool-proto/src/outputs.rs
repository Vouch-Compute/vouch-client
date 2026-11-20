//! Output objects a node PUTs to `output_url` (cddl 1.1.0 `EmbedResult` / `Transcript`).
//! They are **closed**: the server rejects (unpaid) any object with a key
//! outside these sets, a wrong `model_id` or `dim`, bad segment times, or segment texts that do not join to `text`.
//!
//! The runner builds them with [`Transcript::from_raw_segments`] / [`encode_embed_result`]; pool-core re-checks
//! the runner's bytes with [`check_output`] before the PUT, so a schema slip abandons the lease instead of
//! producing a result the server will reject.

use serde::{Deserialize, Serialize};

use crate::{EMBED_RESULT_FORMAT, TRANSCRIPT_FORMAT};

/// the server allows `end_s <= metered chunk duration + 1.0`.
pub const SEGMENT_SLACK_S: f64 = 1.0;
/// the server's unit-norm tolerance for embeddings (a content check).
pub const NORM_TOL: f64 = 0.1;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("output object invalid: {0}")]
pub struct OutputError(pub &'static str);

/// Whitespace normalisation used by the server to compare `text` with the joined segment texts.
pub fn norm_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn round_ms(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

// ------------------------------------------------------------------ transcripts

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSegment {
    pub start_s: f64,
    pub end_s: f64,
    pub text: String,
}

/// `application/vnd.pool.transcript.v1+json`: `{"model_id", "language"?, "text", "segments"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub model_id: String,
    /// The BCP 47 language used: the lease's hint when the model took it, else the detected one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub text: String,
    pub segments: Vec<TranscriptSegment>,
}

impl Transcript {
    /// Build a conforming transcript from a runtime's raw segments `(start_s, end_s, text)`:
    /// whitespace-normalised texts, empty segments dropped, times made finite, ordered, clamped to
    /// `0..=duration_s` and rounded to the millisecond, and `text` = the segment texts joined by single spaces.
    pub fn from_raw_segments(
        model_id: &str,
        language: Option<&str>,
        raw: impl IntoIterator<Item = (f64, f64, String)>,
        duration_s: f64,
    ) -> Self {
        let duration = if duration_s.is_finite() && duration_s > 0.0 { round_ms(duration_s) } else { 0.0 };
        let mut last_start = 0.0f64;
        let mut segments = Vec::new();
        for (s, e, t) in raw {
            let text = norm_ws(&t);
            if text.is_empty() {
                continue;
            }
            let s = if s.is_finite() { s } else { last_start };
            let start = round_ms(s.clamp(last_start, duration));
            let e = if e.is_finite() { e } else { start };
            let end = round_ms(e.clamp(start, duration));
            segments.push(TranscriptSegment { start_s: start, end_s: end, text });
            last_start = start;
        }
        let text = segments.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join(" ");
        Self { model_id: model_id.into(), language: language.map(str::to_string), text, segments }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The schema checks the server applies (verdict `rejected` when they fail).
    pub fn check(&self, model_id: &str, duration_s: f64) -> Result<(), OutputError> {
        if self.model_id != model_id {
            return Err(OutputError("model_id_mismatch"));
        }
        let mut prev = 0.0f64;
        for s in &self.segments {
            if !(s.start_s.is_finite() && s.end_s.is_finite())
                || s.start_s < 0.0
                || s.start_s > s.end_s
                || s.end_s > duration_s + SEGMENT_SLACK_S
            {
                return Err(OutputError("segment_times"));
            }
            if s.start_s < prev {
                return Err(OutputError("segment_order"));
            }
            prev = s.start_s;
        }
        let joined = self.segments.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join(" ");
        if norm_ws(&joined) != norm_ws(&self.text) {
            return Err(OutputError("segment_text_mismatch"));
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ embeddings

/// `application/vnd.pool.embed-result.v1+json`: exactly `{"model_id", "dim", "embeddings"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbedResult {
    pub model_id: String,
    pub dim: u64,
    pub embeddings: Vec<Vec<f64>>,
}

#[derive(Serialize)]
struct EmbedResultOut<'a, T: Serialize> {
    model_id: &'a str,
    dim: usize,
    embeddings: &'a [Vec<T>],
}

/// Encode an `EmbedResult` (f32 vectors from real runtimes, f64 from the dev reference model). `dim` is the
/// model's dimension; every vector must have that length or the call fails.
pub fn encode_embed_result<T: Serialize>(model_id: &str, dim: usize, vectors: &[Vec<T>]) -> Result<Vec<u8>, OutputError> {
    if dim == 0 || vectors.iter().any(|v| v.len() != dim) {
        return Err(OutputError("embedding_dim"));
    }
    serde_json::to_vec(&EmbedResultOut { model_id, dim, embeddings: vectors }).map_err(|_| OutputError("encode"))
}

impl EmbedResult {
    /// the server's schema checks plus the count / finiteness / norm content checks.
    pub fn check(&self, model_id: &str, n_inputs: Option<usize>) -> Result<(), OutputError> {
        if self.model_id != model_id {
            return Err(OutputError("model_id_mismatch"));
        }
        if self.dim == 0 {
            return Err(OutputError("dim_mismatch"));
        }
        if self.embeddings.iter().any(|v| v.len() as u64 != self.dim) {
            return Err(OutputError("embedding_dim"));
        }
        if let Some(n) = n_inputs {
            if self.embeddings.len() != n {
                return Err(OutputError("embedding_count"));
            }
        }
        for v in &self.embeddings {
            if !v.iter().all(|x| x.is_finite()) {
                return Err(OutputError("embedding_non_finite"));
            }
            if (v.iter().map(|x| x * x).sum::<f64>().sqrt() - 1.0).abs() > NORM_TOL {
                return Err(OutputError("embedding_norm"));
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ pre-PUT check

/// What the node knows about the leased work when it checks an output.
#[derive(Debug, Clone, Copy)]
pub struct OutputContext<'a> {
    pub model_id: &'a str,
    /// Transcripts: the chunk duration in seconds.
    pub duration_s: Option<f64>,
    /// Embeddings: the number of inputs in the batch.
    pub n_inputs: Option<usize>,
}

/// Parse `bytes` as the closed object for `content_type` and run the checks the server runs.
pub fn check_output(content_type: &str, bytes: &[u8], ctx: OutputContext<'_>) -> Result<(), OutputError> {
    match content_type {
        TRANSCRIPT_FORMAT => {
            let t: Transcript = serde_json::from_slice(bytes).map_err(|_| OutputError("transcript_schema"))?;
            t.check(ctx.model_id, ctx.duration_s.unwrap_or(f64::INFINITY))
        }
        EMBED_RESULT_FORMAT => {
            let e: EmbedResult = serde_json::from_slice(bytes).map_err(|_| OutputError("embed_schema"))?;
            e.check(ctx.model_id, ctx.n_inputs)
        }
        _ => Err(OutputError("unknown_content_type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(model_id: &str, duration_s: f64) -> OutputContext<'_> {
        OutputContext { model_id, duration_s: Some(duration_s), n_inputs: None }
    }

    #[test]
    fn transcript_builder_produces_a_closed_conforming_object() {
        let raw = vec![
            (0.0, 4.2, "  Hello\tworld ".to_string()),
            (4.2, 4.1, "".to_string()),                 // empty: dropped
            (3.0, 9.87654, "second  part".to_string()), // overlaps the previous one: allowed (starts are ordered)
            (f64::NAN, 99.0, "tail".to_string()),        // non-finite start, end past the chunk: clamped
        ];
        let t = Transcript::from_raw_segments("whisper-tiny", Some("tr"), raw, 10.0);
        assert_eq!(t.text, "Hello world second part tail");
        assert_eq!(t.segments.len(), 3);
        assert_eq!(t.segments[1].start_s, 3.0);
        assert_eq!(t.segments[1].end_s, 9.877);
        assert_eq!(t.segments[2].end_s, 10.0);
        t.check("whisper-tiny", 10.0).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&t.to_json()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["language", "model_id", "segments", "text"]);
        for s in v["segments"].as_array().unwrap() {
            let mut k: Vec<_> = s.as_object().unwrap().keys().cloned().collect();
            k.sort();
            assert_eq!(k, ["end_s", "start_s", "text"]);
        }
        check_output(TRANSCRIPT_FORMAT, &t.to_json(), ctx("whisper-tiny", 10.0)).unwrap();
        // language is optional and omitted when unknown
        let t = Transcript::from_raw_segments("m", None, vec![], 1.0);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&t.to_json()).unwrap(), serde_json::json!({"model_id": "m", "text": "", "segments": []}));
    }

    #[test]
    fn transcript_checks_match_vault() {
        let ok = br#"{"model_id":"m","language":null,"text":"a  b","segments":[{"start_s":0,"end_s":1.5,"text":"a"},{"start_s":1.5,"end_s":2,"text":"b"}]}"#;
        check_output(TRANSCRIPT_FORMAT, ok, ctx("m", 2.0)).unwrap();
        let cases: [(&[u8], &str); 8] = [
            (br#"{"model_id":"m","text":"a","segments":[],"duration":1}"#, "unknown key"),
            (br#"{"model_id":"m","text":"a","segments":[{"start_s":0,"end_s":1,"text":"a","words":[]}]}"#, "segment key"),
            (br#"{"model_id":"m","segments":[]}"#, "missing text"),
            (br#"{"model_id":"x","text":"a","segments":[{"start_s":0,"end_s":1,"text":"a"}]}"#, "model id"),
            (br#"{"model_id":"m","text":"a","segments":[{"start_s":0,"end_s":3.5,"text":"a"}]}"#, "end past slack"),
            (br#"{"model_id":"m","text":"a b","segments":[{"start_s":1,"end_s":1.5,"text":"a"},{"start_s":0.5,"end_s":1,"text":"b"}]}"#, "order"),
            (br#"{"model_id":"m","text":"a c","segments":[{"start_s":0,"end_s":1,"text":"a"},{"start_s":1,"end_s":2,"text":"b"}]}"#, "text mismatch"),
            (br#"{"model_id":"m","text":"a","segments":[{"start_s":1,"end_s":0.5,"text":"a"}]}"#, "start > end"),
        ];
        for (bytes, why) in cases {
            assert!(check_output(TRANSCRIPT_FORMAT, bytes, ctx("m", 2.0)).is_err(), "{why}");
        }
    }

    #[test]
    fn embed_result_encode_and_checks() {
        let s = std::f32::consts::FRAC_1_SQRT_2;
        let bytes = encode_embed_result("bge", 2, &[vec![s, s], vec![1.0f32, 0.0]]).unwrap();
        let c = OutputContext { model_id: "bge", duration_s: None, n_inputs: Some(2) };
        check_output(EMBED_RESULT_FORMAT, &bytes, c).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 3);
        assert_eq!(v["dim"], 2);
        assert!(encode_embed_result("bge", 3, &[vec![1.0f32, 0.0]]).is_err());
        assert!(encode_embed_result::<f32>("bge", 0, &[]).is_err());
        // wrong count, wrong model, extra key, bad norm, dim mismatch
        assert!(check_output(EMBED_RESULT_FORMAT, &bytes, OutputContext { n_inputs: Some(3), ..c }).is_err());
        assert!(check_output(EMBED_RESULT_FORMAT, &bytes, OutputContext { model_id: "x", ..c }).is_err());
        assert!(check_output(EMBED_RESULT_FORMAT, br#"{"model_id":"bge","dim":1,"embeddings":[[1.0]],"usage":{}}"#, OutputContext { n_inputs: Some(1), ..c }).is_err());
        assert!(check_output(EMBED_RESULT_FORMAT, br#"{"model_id":"bge","dim":1,"embeddings":[[0.5]]}"#, OutputContext { n_inputs: Some(1), ..c }).is_err());
        assert!(check_output(EMBED_RESULT_FORMAT, br#"{"model_id":"bge","dim":2,"embeddings":[[1.0]]}"#, OutputContext { n_inputs: Some(1), ..c }).is_err());
        assert!(check_output("application/json", &bytes, c).is_err());
    }
}
