//! security review R2 conditions on the pre-PUT output check:
//! (a) client tolerances are identical to the server's published output rules, never stricter;
//! (b) no known-answer comparison: nothing in pool-core or pool-proto (outside tests) compares outputs with known answers,
//!     expected or reference outputs;
//! (c) a non-conforming output is abandoned with `ABANDON_REASON_ERROR` (no new reason code exists).

use pool_proto::outputs::{check_output, OutputContext, NORM_TOL, SEGMENT_SLACK_S};
use pool_proto::{EMBED_RESULT_FORMAT, TRANSCRIPT_FORMAT};

/// Published output rules: segments end at most `metered chunk duration + 1.0`; embeddings are unit norm ±0.1.
#[test]
fn tolerances_are_pinned_to_vaults_published_values() {
    assert_eq!(SEGMENT_SLACK_S, 1.0);
    assert_eq!(NORM_TOL, 0.1);
    let ctx = |d| OutputContext { model_id: "w", duration_s: Some(d), n_inputs: Some(1) };
    let t = |end: f64, text: &str| {
        serde_json::to_vec(&serde_json::json!({"model_id": "w", "text": text, "segments": [{"start_s": 0.0, "end_s": end, "text": text}]})).unwrap()
    };
    // exactly at the server's limit passes, beyond fails
    assert!(check_output(TRANSCRIPT_FORMAT, &t(11.0, "hello"), ctx(10.0)).is_ok());
    assert!(check_output(TRANSCRIPT_FORMAT, &t(11.01, "hello"), ctx(10.0)).is_err());
    // the server's content checks (words per second, URL/e-mail injection) go to a later review, not `rejected`: the client
    // never discards such output (that would be stricter than the server and lose honest work)
    let many_words = vec!["word"; 200].join(" ");
    assert!(check_output(TRANSCRIPT_FORMAT, &t(2.0, &many_words), ctx(2.0)).is_ok());
    assert!(check_output(TRANSCRIPT_FORMAT, &t(2.0, "visit https://example.com or mail a@b.co"), ctx(2.0)).is_ok());
    let e = |norm: f64| {
        let x = norm / 2f64.sqrt();
        serde_json::to_vec(&serde_json::json!({"model_id": "w", "dim": 2, "embeddings": [[x, x]]})).unwrap()
    };
    assert!(check_output(EMBED_RESULT_FORMAT, &e(1.099), ctx(0.0)).is_ok());
    assert!(check_output(EMBED_RESULT_FORMAT, &e(0.901), ctx(0.0)).is_ok());
    assert!(check_output(EMBED_RESULT_FORMAT, &e(1.11), ctx(0.0)).is_err());
}

fn source_without_tests(path: &std::path::Path) -> String {
    let s = std::fs::read_to_string(path).unwrap();
    match s.find("#[cfg(test)]") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// A code scan of the node's output path finds no known-answer, expected- or reference-output
/// comparison (comments included).
#[test]
fn no_known_answer_comparison_in_pool_core_or_pool_proto() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![];
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("../pool-proto/src"), &mut files);
    assert!(files.len() > 20, "scanned {}", files.len());
    let banned = ["canar", "known_answer", "known answer", "expected_output", "expected output", "reference_output", "golden"];
    for f in &files {
        let s = source_without_tests(f).to_lowercase();
        for b in banned {
            assert!(!s.contains(b), "{b:?} in {}", f.display());
        }
    }
}

/// The abandon reason for a non-conforming output stays `ERROR`, and no other abandon reason was added.
#[test]
fn abandon_reasons_are_unchanged() {
    use pool_proto::pb::AbandonReason;
    let all: Vec<i32> = (0..16).filter(|i| AbandonReason::try_from(*i).is_ok()).collect();
    assert_eq!(all, [0, 1, 2, 3, 4, 5], "no new abandon reason code");
    let session = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/session.rs")).unwrap();
    let i = session.find("check_runner_output(&shape").expect("pre-PUT check in run_job");
    let after = &session[i..i + 400];
    assert!(after.contains("abandon(pb::AbandonReason::Error)"), "{after}");
}
