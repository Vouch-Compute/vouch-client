//! GPU acceleration: the same signed embedding model run by the real runner binary, inside the OS
//! sandbox, on the CPU (candle; ONNX Runtime CPU provider) and on the GPU (ONNX Runtime DirectML provider from the
//! pinned backend pack). Needs a GPU, the pack and a downloaded model, so it is ignored by default:
//!
//!   POOL_GPU_PACK=<dir with DirectML.dll + onnxruntime.dll> POOL_BENCH_MODEL=<dir with model.onnx, vocab.txt,
//!   config.json, model.safetensors> cargo test -p pool-runner --features onnx --test gpu -- --ignored --nocapture
//!
//! Throughput is the marginal rate between a small and a large batch of the same texts, so process start and model
//! load (paid once per job) are reported separately and do not inflate the figure.
#![cfg(feature = "onnx")]

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use pool_runner::ipc::{read_frame, write_frame, RunRequest, RunResponse};
use pool_runner::testutil;
use pool_sandbox::{spawn_sandboxed, SandboxConfig};

fn runner() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pool-runner"))
}

fn env_dir(k: &str) -> Option<PathBuf> {
    std::env::var_os(k).map(PathBuf::from).filter(|p| p.is_dir())
}

/// Varied English sentences, about 40-60 tokens each.
fn texts(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            format!(
                "Request {i}: the contributor's computer runs this embedding job only after the signed bundle verified, \
                 and the server meters tokens itself; sentence {} talks about batch inference, verified work and payouts number {}.",
                i * 7 % 13,
                i % 97
            )
        })
        .collect()
}

struct Run {
    resp: RunResponse,
    out: Vec<u8>,
    secs: f64,
}

fn run(fx: &testutil::BundleFixture, inputs: &[String], pack: Option<&PathBuf>, force_cpu: bool) -> Run {
    let input = serde_json::to_vec(&serde_json::json!({ "inputs": inputs })).unwrap();
    let req = RunRequest {
        keyset_b64: pool_proto::keys::b64(&fx.keyset),
        manifest_b64: pool_proto::keys::b64(&fx.manifest_cose),
        expected_model_hash_hex: hex::encode(fx.model_hash),
        model_dir: fx.dir.path().to_string_lossy().into(),
        input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
        max_output_bytes: 256 << 20,
        language: None,
    };
    let mut readable = vec![fx.dir.path().to_path_buf()];
    let mut env = vec![];
    if let Some(p) = pack {
        readable.push(p.clone());
        env.push((pool_runner::accel::PACK_ENV.to_string(), p.to_string_lossy().into_owned()));
    }
    if force_cpu {
        env.push((pool_runner::accel::FORCE_CPU_ENV.to_string(), "1".into()));
    }
    // LPAC refuses to load DirectML/ONNX Runtime (even the system's DirectML.dll); a job that uses the pack runs in a
    // regular AppContainer, which still has no network and no user files (sandbox_isolation tests)
    let cfg = SandboxConfig { readable_dirs: readable, env, lpac: pack.is_none(), ..Default::default() };
    let t = Instant::now();
    let mut s = spawn_sandboxed(&runner(), &["run".to_string()], &cfg).expect("spawn");
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
    let out = read_frame(&mut s.stdout, 256 << 20).unwrap_or_default();
    let _ = s.process.wait();
    let err = drain.join().unwrap_or_default();
    if !err.trim().is_empty() {
        eprintln!("runner stderr: {}", err.trim());
    }
    Run { resp, out, secs: t.elapsed().as_secs_f64() }
}

fn vectors(out: &[u8]) -> Vec<Vec<f64>> {
    let v: serde_json::Value = serde_json::from_slice(out).unwrap();
    v["embeddings"].as_array().unwrap().iter().map(|e| e.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect()).collect()
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let d: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    d / (a.iter().map(|x| x * x).sum::<f64>().sqrt() * b.iter().map(|x| x * x).sum::<f64>().sqrt())
}

fn bundle(dir: &std::path::Path, files: &[&str], runtime: &str, format: &str) -> testutil::BundleFixture {
    let files: Vec<(&str, Vec<u8>)> = files.iter().map(|f| (*f, std::fs::read(dir.join(f)).unwrap())).collect();
    testutil::bundle_fixture_with(&files, runtime, format, pool_proto::EMBED_BATCH_FORMAT, "bench-model")
}

#[test]
#[ignore = "needs a GPU, the pinned backend pack and a downloaded model (POOL_GPU_PACK, POOL_BENCH_MODEL)"]
fn embeddings_on_gpu_vs_cpu() {
    let (Some(pack), Some(model)) = (env_dir("POOL_GPU_PACK"), env_dir("POOL_BENCH_MODEL")) else {
        panic!("set POOL_GPU_PACK and POOL_BENCH_MODEL");
    };
    pool_runner::accel::verify_pack(&pack).expect("the pack must match the pinned hashes");
    let onnx = bundle(&model, &["model.onnx", "vocab.txt"], "onnxruntime", "onnx");
    let candle = bundle(&model, &["model.safetensors", "config.json", "vocab.txt"], "candle", "safetensors");
    let small = texts(16);
    let big_n: usize = std::env::var("POOL_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
    let big = texts(big_n);

    let mut rows = vec![];
    let mut reference: Option<Vec<Vec<f64>>> = None;
    for (label, fx, pack) in [
        ("candle (CPU)", &candle, None),
        ("ONNX Runtime CPU provider", &onnx, Some(&pack)),
        ("ONNX Runtime DirectML (GPU)", &onnx, Some(&pack)),
    ] {
        // the CPU-provider row runs the same pinned pack with DirectML switched off
        let cpu_only = label.contains("CPU provider");
        // one warm-up job (first start of a fresh binary pays antivirus scanning and cold caches), then medians of 3
        let w = run(fx, &small, pack, cpu_only);
        assert!(w.resp.ok, "{label}: {:?}", w.resp);
        let median = |mut v: Vec<f64>| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let smalls: Vec<Run> = (0..3).map(|_| run(fx, &small, pack, cpu_only)).collect();
        let bigs: Vec<Run> = (0..3).map(|_| run(fx, &big, pack, cpu_only)).collect();
        for r in smalls.iter().chain(&bigs) {
            assert!(r.resp.ok, "{label}: {:?}", r.resp);
        }
        let (ts, tb) = (median(smalls.iter().map(|r| r.secs).collect()), median(bigs.iter().map(|r| r.secs).collect()));
        let tokens_small = smalls[0].resp.units_device_milli.unwrap() / 1000;
        let tokens_big = bigs[0].resp.units_device_milli.unwrap() / 1000;
        let end_to_end = tokens_big as f64 / tb;
        let rate = if tb > ts { (tokens_big - tokens_small) as f64 / (tb - ts) } else { f64::NAN };
        let b = &bigs[0];
        let v = vectors(&b.out);
        let agree = reference.as_ref().map(|r| r.iter().zip(&v).map(|(x, y)| cosine(x, y)).fold(1.0f64, f64::min));
        if reference.is_none() {
            reference = Some(v);
        }
        eprintln!(
            "{label:<30} backend={:<22} median {}-text job {:.2} s, {big_n}-text job {:.2} s ({tokens_big} tokens): end-to-end {:.0} tokens/s, marginal {:.0} tokens/s, min cosine vs candle {}",
            b.resp.backend.clone().unwrap_or_default(),
            small.len(),
            ts,
            tb,
            end_to_end,
            rate,
            agree.map(|c| format!("{c:.6}")).unwrap_or_else(|| "-".into())
        );
        let rate = end_to_end;
        rows.push((label, b.resp.backend.clone().unwrap_or_default(), rate, agree));
    }
    let gpu = &rows[2];
    assert_eq!(gpu.1, "onnxruntime-directml", "the GPU row must really run on DirectML inside the sandbox");
    for r in &rows[1..] {
        assert!(r.3.unwrap() > 0.999, "{} disagrees with the CPU reference: {:?}", r.0, r.3);
    }
    eprintln!("end-to-end speedup per {big_n}-text job: DirectML vs candle CPU {:.1}x, vs ORT CPU provider {:.1}x", gpu.2 / rows[0].2, gpu.2 / rows[1].2);
}

/// A tampered pack is refused before anything is loaded, and without a pack an ONNX job is refused instead of
/// loading whatever `onnxruntime.dll` the DLL search path finds.
#[test]
#[ignore = "needs POOL_GPU_PACK and POOL_BENCH_MODEL"]
fn tampered_or_missing_pack_is_refused() {
    let (Some(pack), Some(model)) = (env_dir("POOL_GPU_PACK"), env_dir("POOL_BENCH_MODEL")) else {
        panic!("set POOL_GPU_PACK and POOL_BENCH_MODEL");
    };
    let onnx = bundle(&model, &["model.onnx", "vocab.txt"], "onnxruntime", "onnx");
    let r = run(&onnx, &texts(2), None, false);
    assert!(!r.resp.ok && r.resp.message.unwrap_or_default().contains("backend pack"), "no pack: refused");
    let bad = tempfile::tempdir().unwrap();
    for f in pool_runner::accel::pinned() {
        let mut b = std::fs::read(pack.join(&f.name)).unwrap();
        let n = b.len();
        b[n / 2] ^= 1;
        std::fs::write(bad.path().join(&f.name), b).unwrap();
    }
    let r = run(&onnx, &texts(2), Some(&bad.path().to_path_buf()), false);
    assert!(!r.resp.ok && r.resp.message.unwrap_or_default().contains("pinned"), "tampered pack: refused");
}
