//! GPU acceleration on macOS: candle on Metal vs candle on the CPU, for embeddings and Whisper, with the real runner
//! binary inside the macOS sandbox. The CPU job runs like the agent runs a job without the GPU (no Metal
//! allowances, GPU forced off); the Metal job gets `SandboxConfig::gpu`. Needs Apple silicon, a `metal` build and
//! downloaded models, so it is ignored by default:
//!
//!   (POOL_BENCH_SKIP_WHISPER=1 measures the embeddings only)
//!   POOL_BENCH_MODEL=<bge dir: model.safetensors, config.json, vocab.txt> POOL_WHISPER_MODEL=<whisper dir:
//!   model.safetensors, config.json, tokenizer.json> POOL_SPEECH_WAV=<16 kHz mono 16-bit wav>
//!   cargo test --release -p pool-runner --features metal --test gpu_metal -- --ignored --nocapture
#![cfg(all(feature = "metal", target_os = "macos"))]

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use pool_runner::ipc::{read_frame, write_frame, RunRequest, RunResponse};
use pool_runner::testutil;
use pool_sandbox::{spawn_sandboxed, SandboxConfig};

fn env_dir(k: &str) -> PathBuf {
    std::env::var_os(k).map(PathBuf::from).unwrap_or_else(|| panic!("set {k}"))
}

fn run(fx: &testutil::BundleFixture, format: &str, input: &[u8], force_cpu: bool) -> (RunResponse, Vec<u8>, f64) {
    let req = RunRequest {
        keyset_b64: pool_proto::keys::b64(&fx.keyset),
        manifest_b64: pool_proto::keys::b64(&fx.manifest_cose),
        expected_model_hash_hex: hex::encode(fx.model_hash),
        model_dir: fx.dir.path().to_string_lossy().into(),
        input_format: format.into(),
        max_output_bytes: 256 << 20,
        language: Some("en".into()),
    };
    let mut env = vec![];
    if force_cpu {
        env.push((pool_runner::accel::FORCE_CPU_ENV.to_string(), "1".into()));
    } else if format == pool_proto::CANONICAL_AUDIO_FORMAT {
        // jobs keep Whisper on the CPU (accel::candle_transcription_device); measure Metal anyway
        env.push((pool_runner::accel::METAL_WHISPER_ENV.to_string(), "1".into()));
    }
    // diagnostics: POOL_TEST_MEM_GB overrides the sandbox memory cap (the footprint watchdog on macOS);
    // POOL_TEST_UNSANDBOXED=1 starts the runner without the sandbox
    let mut cfg = SandboxConfig { readable_dirs: vec![fx.dir.path().to_path_buf()], env, gpu: !force_cpu, ..Default::default() };
    if let Some(gb) = std::env::var("POOL_TEST_MEM_GB").ok().and_then(|v| v.parse::<u64>().ok()) {
        cfg.memory_limit_bytes = gb << 30;
    }
    let t = Instant::now();
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_pool-runner"));
    let mut s = if std::env::var("POOL_TEST_UNSANDBOXED").as_deref() == Ok("1") {
        pool_sandbox::spawn_unsandboxed(&exe, &["run".to_string()], &cfg)
    } else {
        spawn_sandboxed(&exe, &["run".to_string()], &cfg)
    }
    .expect("spawn");
    let mut stderr = std::mem::replace(&mut s.stderr, Box::new(std::io::empty()));
    let drain = std::thread::spawn(move || {
        let mut e = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut e);
        e
    });
    write_frame(&mut s.stdin, &serde_json::to_vec(&req).unwrap()).unwrap();
    write_frame(&mut s.stdin, input).unwrap();
    s.stdin.flush().unwrap();
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let resp: RunResponse = serde_json::from_slice(&read_frame(&mut s.stdout, 1 << 20).unwrap()).unwrap();
    let out = read_frame(&mut s.stdout, 256 << 20).unwrap_or_default();
    let _ = s.process.wait();
    let err = drain.join().unwrap_or_default();
    if !err.trim().is_empty() {
        eprintln!("runner stderr: {}", err.trim());
    }
    (resp, out, t.elapsed().as_secs_f64())
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Warm-up, then the median of 3 jobs; returns (median seconds, last response, last output).
fn timed(fx: &testutil::BundleFixture, format: &str, input: &[u8], force_cpu: bool) -> (f64, RunResponse, Vec<u8>) {
    let (r, _, _) = run(fx, format, input, force_cpu);
    assert!(r.ok, "{r:?}");
    let mut times = vec![];
    let mut last = None;
    for _ in 0..3 {
        let (r, o, t) = run(fx, format, input, force_cpu);
        assert!(r.ok, "{r:?}");
        times.push(t);
        last = Some((r, o));
    }
    let (r, o) = last.unwrap();
    (median(times), r, o)
}

fn bundle(dir: &std::path::Path, files: &[&str], format: &str, model_id: &str) -> testutil::BundleFixture {
    let files: Vec<(&str, Vec<u8>)> = files.iter().map(|f| (*f, std::fs::read(dir.join(f)).unwrap())).collect();
    testutil::bundle_fixture_with(&files, "candle", "safetensors", format, model_id)
}

#[test]
#[ignore = "needs Apple silicon, a metal build and downloaded models"]
fn candle_metal_vs_cpu() {
    // embeddings
    let emb = bundle(&env_dir("POOL_BENCH_MODEL"), &["model.safetensors", "config.json", "vocab.txt"], pool_proto::EMBED_BATCH_FORMAT, "bench-model");
    let texts: Vec<String> = (0..2048)
        .map(|i| format!("Request {i}: the contributor's computer runs this embedding job only after the signed bundle verified, and the server meters tokens itself; sentence {} about batch inference and payouts {}.", i * 7 % 13, i % 97))
        .collect();
    let input = serde_json::to_vec(&serde_json::json!({ "inputs": texts })).unwrap();
    let (tc, rc, oc) = timed(&emb, pool_proto::EMBED_BATCH_FORMAT, &input, true);
    let (tg, rg, og) = timed(&emb, pool_proto::EMBED_BATCH_FORMAT, &input, false);
    assert_eq!(rc.backend.as_deref(), Some("candle-cpu"), "the CPU job must not touch the GPU");
    assert_eq!(rg.backend.as_deref(), Some("candle-metal"), "the GPU job must really run on Metal inside the sandbox");
    let tokens = rc.units_device_milli.unwrap() / 1000;
    let vc: serde_json::Value = serde_json::from_slice(&oc).unwrap();
    let vg: serde_json::Value = serde_json::from_slice(&og).unwrap();
    let mut min_cos = 1.0f64;
    for (a, b) in vc["embeddings"].as_array().unwrap().iter().zip(vg["embeddings"].as_array().unwrap()) {
        let (a, b): (Vec<f64>, Vec<f64>) = (a.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect(), b.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect());
        let d: f64 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        min_cos = min_cos.min(d / (a.iter().map(|x| x * x).sum::<f64>().sqrt() * b.iter().map(|x| x * x).sum::<f64>().sqrt()));
    }
    eprintln!(
        "embeddings 2048 texts ({tokens} tokens): candle CPU {tc:.2} s ({:.0} tokens/s), candle Metal {tg:.2} s ({:.0} tokens/s), speedup {:.1}x, min cosine {min_cos:.6}",
        tokens as f64 / tc,
        tokens as f64 / tg,
        tc / tg
    );
    assert!(min_cos > 0.999);

    if std::env::var("POOL_BENCH_SKIP_WHISPER").as_deref() == Ok("1") {
        return;
    }
    // whisper: the speech sample repeated to 60 s
    let wav = std::fs::read(std::env::var_os("POOL_SPEECH_WAV").expect("set POOL_SPEECH_WAV")).unwrap();
    let data = wav.windows(4).position(|w| w == b"data").expect("wav data chunk") + 8;
    let pcm: Vec<i16> = wav[data..].as_chunks::<2>().0.iter().map(|b| i16::from_le_bytes(*b)).collect();
    let mut sixty = Vec::with_capacity(16_000 * 60);
    while sixty.len() < 16_000 * 60 {
        sixty.extend_from_slice(&pcm);
    }
    sixty.truncate(16_000 * 60);
    let flac = testutil::flac_encode(&sixty);
    let wh = bundle(&env_dir("POOL_WHISPER_MODEL"), &["model.safetensors", "config.json", "tokenizer.json"], pool_proto::CANONICAL_AUDIO_FORMAT, "whisper-base");
    let (tc, _, oc) = timed(&wh, pool_proto::CANONICAL_AUDIO_FORMAT, &flac, true);
    let (tg, rg, og) = timed(&wh, pool_proto::CANONICAL_AUDIO_FORMAT, &flac, false);
    assert_eq!(rg.backend.as_deref(), Some("candle-metal"));
    let text = |o: &[u8]| serde_json::from_slice::<serde_json::Value>(o).unwrap()["text"].as_str().unwrap_or_default().to_string();
    eprintln!(
        "whisper-base, 60 s of speech: candle CPU {tc:.2} s ({:.1}x real time), candle Metal {tg:.2} s ({:.1}x real time), speedup {:.1}x",
        60.0 / tc,
        60.0 / tg,
        tc / tg
    );
    eprintln!("transcripts identical: {}", text(&oc) == text(&og));
    eprintln!("CPU text:  {}", text(&oc).chars().take(160).collect::<String>());
    eprintln!("Metal text: {}", text(&og).chars().take(160).collect::<String>());
}
