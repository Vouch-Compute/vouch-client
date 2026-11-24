//! bge-m3's bundle layout end to end, on the CPU, with a tiny stand-in model: the real runner binary, inside the OS
//! sandbox, runs an XLM-R `tokenizer.json` pipeline and an ONNX graph whose weights are external data
//! (`onnx/model.onnx` + `onnx/model.onnx_data`), and must reproduce the engine reference worker's embeddings
//! (`tests/fixtures/xlmr-tiny/expected.json`, written by `make_fixture.py` with the reference worker's own code).
//!
//! Needs this OS's pinned ONNX Runtime pack (`pool-app/src-tauri/backends/<dir>` from `packs.json`: `ort-directml` on
//! Windows, `ort-cpu` on macOS arm64 and Linux x64; fetched by `node pool-app/scripts/runtime-packs.mjs`, or
//! `POOL_ORT_PACK=<dir>`). The GPU provider is switched off: CPU only.
//!   cargo test -p pool-runner --features onnx --test onnx_xlmr -- --nocapture
//! Without a pack the tests print why and pass without running (no ONNX Runtime library to load), unless
//! `POOL_REQUIRE_ORT_PACK=1` (CI), which makes a missing or mismatching pack a failure.
#![cfg(feature = "onnx")]

use std::io::Write;
use std::path::{Path, PathBuf};

use pool_runner::ipc::{read_frame, write_frame, RunRequest, RunResponse};
use pool_runner::testutil;
use pool_sandbox::{spawn_sandboxed, SandboxConfig};

const FILES: [&str; 4] = ["onnx/model.onnx", "onnx/model.onnx_data", "onnx/tokenizer.json", "onnx/tokenizer_config.json"];

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xlmr-tiny")
}

fn pack() -> Option<PathBuf> {
    let dir = pool_runner::accel::ort_pack().map(|p| p.dir.as_str()).unwrap_or("none");
    let p = std::env::var_os("POOL_ORT_PACK")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pool-app/src-tauri/backends").join(dir));
    match pool_runner::accel::verify_pack(&p) {
        Ok(_) => Some(p),
        Err(e) if std::env::var("POOL_REQUIRE_ORT_PACK").as_deref() == Ok("1") => {
            panic!("POOL_REQUIRE_ORT_PACK=1: no usable pinned ONNX Runtime pack at {} ({e})", p.display())
        }
        Err(e) => {
            eprintln!("skipped: no pinned ONNX Runtime pack at {} ({e})", p.display());
            None
        }
    }
}

fn bundle(files: &[&str]) -> testutil::BundleFixture {
    let files: Vec<(&str, Vec<u8>)> = files.iter().map(|f| (*f, std::fs::read(fixture().join(f)).unwrap())).collect();
    testutil::bundle_fixture_with(&files, "onnxruntime", "onnx", pool_proto::EMBED_BATCH_FORMAT, "bge-m3")
}

fn run(fx: &testutil::BundleFixture, inputs: &[String], pack: &Path) -> (RunResponse, Vec<u8>) {
    let input = serde_json::to_vec(&serde_json::json!({ "inputs": inputs })).unwrap();
    let req = RunRequest {
        keyset_b64: pool_proto::keys::b64(&fx.keyset),
        manifest_b64: pool_proto::keys::b64(&fx.manifest_cose),
        expected_model_hash_hex: hex::encode(fx.model_hash),
        model_dir: fx.dir.path().to_string_lossy().into(),
        input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
        max_output_bytes: 16 << 20,
        language: None,
    };
    let env = vec![
        (pool_runner::accel::PACK_ENV.to_string(), pack.to_string_lossy().into_owned()),
        (pool_runner::accel::FORCE_CPU_ENV.to_string(), "1".to_string()),
    ];
    // as pool-core does for onnxruntime jobs: the pack is readable, and the job runs in a regular AppContainer on
    // Windows (LPAC refuses to load ONNX Runtime), still without network or user files
    let cfg = SandboxConfig {
        readable_dirs: vec![fx.dir.path().to_path_buf(), pack.to_path_buf()],
        env,
        lpac: false,
        ..Default::default()
    };
    let runner = PathBuf::from(env!("CARGO_BIN_EXE_pool-runner"));
    let mut s = spawn_sandboxed(&runner, &["run".to_string()], &cfg).expect("spawn");
    let mut stderr = std::mem::replace(&mut s.stderr, Box::new(std::io::empty()));
    let drain = std::thread::spawn(move || {
        let mut e = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut e);
        e
    });
    write_frame(&mut s.stdin, &serde_json::to_vec(&req).unwrap()).unwrap();
    write_frame(&mut s.stdin, &input).unwrap();
    s.stdin.flush().unwrap();
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let resp: RunResponse = serde_json::from_slice(&read_frame(&mut s.stdout, 1 << 20).unwrap()).unwrap();
    let out = read_frame(&mut s.stdout, 16 << 20).unwrap_or_default();
    let code = s.process.wait().expect("wait");
    let err = drain.join().unwrap_or_default();
    if !err.trim().is_empty() {
        eprintln!("runner stderr: {}", err.trim());
    }
    // a job ends with a clean exit, not an abort after the answer (ONNX Runtime's static destructors on macOS)
    assert_eq!(code, if resp.ok { 0 } else { 3 }, "runner exit code; stderr: {}", err.trim());
    (resp, out)
}

fn expected() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture().join("expected.json")).unwrap()).unwrap()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

fn vectors(v: &serde_json::Value) -> Vec<Vec<f64>> {
    v.as_array().unwrap().iter().map(|e| e.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect()).collect()
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let d: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    d / (a.iter().map(|x| x * x).sum::<f64>().sqrt() * b.iter().map(|x| x * x).sum::<f64>().sqrt())
}

#[test]
fn matches_the_reference_worker_on_cpu() {
    let Some(pack) = pack() else { return };
    let exp = expected();
    let inputs = strings(&exp["inputs"]);
    let want = vectors(&exp["embeddings"]);
    let fx = bundle(&FILES);

    let (resp, out) = run(&fx, &inputs, &pack);
    assert!(resp.ok, "{resp:?}");
    assert_eq!(resp.backend.as_deref(), Some("onnxruntime-cpu"));
    assert_eq!(resp.units_device_milli, Some(exp["tokens"].as_u64().unwrap() * 1000), "token count as the reference");
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["model_id"], "bge-m3");
    assert_eq!(doc["dim"], 16);
    let got = vectors(&doc["embeddings"]);
    assert_eq!(got.len(), want.len());
    for ((g, w), text) in got.iter().zip(&want).zip(&inputs) {
        let c = cosine(g, w);
        let max_abs = g.iter().zip(w).map(|(a, b)| (a - b).abs()).fold(0f64, f64::max);
        // the embed-v1 canary bar is cosine >= 0.995; same graph, same precision: expect float noise only
        assert!(c >= 0.99999 && max_abs <= 1e-4, "{text:?}: cosine {c}, max |diff| {max_abs}");
        let norm = g.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4, "unit length");
    }

    // batching does not change a vector: each input alone (no padding) gives the batched result
    for (i, text) in inputs.iter().enumerate().step_by(3) {
        let (resp, out) = run(&fx, std::slice::from_ref(text), &pack);
        assert!(resp.ok, "{resp:?}");
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let one = &vectors(&doc["embeddings"])[0];
        assert!(cosine(one, &got[i]) >= 0.99999, "{text:?} alone differs from its batched vector");
    }
}

/// The graph's weights come only from the signed bundle: a bundle whose manifest does not list `model.onnx_data`
/// fails, even with the file sitting in the model directory (ONNX Runtime must not read it from disk).
#[test]
fn external_weights_outside_the_manifest_are_not_read() {
    let Some(pack) = pack() else { return };
    let fx = bundle(&["onnx/model.onnx", "onnx/tokenizer.json", "onnx/tokenizer_config.json"]);
    let data = std::fs::read(fixture().join("onnx/model.onnx_data")).unwrap();
    std::fs::write(fx.dir.path().join("onnx/model.onnx_data"), data).unwrap();
    let (resp, _) = run(&fx, &["Hello world".to_string()], &pack);
    assert!(!resp.ok, "the job ran with weights the manifest does not list: {resp:?}");
    assert_eq!(resp.error_code.as_deref(), Some("runtime_error"), "{resp:?}");
}

/// The real bge-m3 bundle against the reference worker. **Needs the owner's approval**: it uses the 2.3 GB
/// fp32 weights (already on disk, pinned commit 5617a9f6) and several GB of RAM; CPU only.
///   1. `PYTHONPATH=engine/src python client/crates/pool-runner/tests/fixtures/xlmr-tiny/bge_m3_reference.py <dir> ref.json`
///   2. `POOL_BGE_M3_DIR=<dir> POOL_BGE_M3_EXPECTED=ref.json cargo test -p pool-runner --features onnx --test onnx_xlmr -- --ignored --nocapture`
#[test]
#[ignore = "real bge-m3 weights (2.3 GB): run only with the owner's approval"]
fn real_bge_m3_matches_the_reference() {
    let Some(pack) = pack() else { panic!("needs the pinned ONNX Runtime pack") };
    let dir = PathBuf::from(std::env::var_os("POOL_BGE_M3_DIR").expect("set POOL_BGE_M3_DIR"));
    let exp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var_os("POOL_BGE_M3_EXPECTED").expect("set POOL_BGE_M3_EXPECTED")).unwrap())
            .unwrap();
    let names = [
        "onnx/config.json",
        "onnx/model.onnx",
        "onnx/model.onnx_data",
        "onnx/special_tokens_map.json",
        "onnx/tokenizer.json",
        "onnx/tokenizer_config.json",
    ];
    let files: Vec<(&str, Vec<u8>)> = names.iter().map(|f| (*f, std::fs::read(dir.join(f)).unwrap())).collect();
    let fx = testutil::bundle_fixture_with(&files, "onnxruntime", "onnx", pool_proto::EMBED_BATCH_FORMAT, "bge-m3");
    drop(files);
    let inputs = strings(&exp["inputs"]);
    let t = std::time::Instant::now();
    let (resp, out) = run(&fx, &inputs, &pack);
    eprintln!("bge-m3, {} inputs: {:.1} s (one job: load + run)", inputs.len(), t.elapsed().as_secs_f64());
    assert!(resp.ok, "{resp:?}");
    assert_eq!(resp.units_device_milli, Some(exp["tokens"].as_u64().unwrap() * 1000));
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["dim"], 1024);
    let (got, want) = (vectors(&doc["embeddings"]), vectors(&exp["embeddings"]));
    let sims: Vec<f64> = got.iter().zip(&want).map(|(g, w)| cosine(g, w)).collect();
    let min = sims.iter().copied().fold(1f64, f64::min);
    eprintln!("cosine vs reference: min {min:.6}");
    // embed-v1 canary bar (vault verify/metrics.py COSINE_SAME_PRECISION)
    assert!(min >= 0.995, "{sims:?}");
}
