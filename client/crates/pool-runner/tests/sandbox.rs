//! Sandbox verification: start the real `pool-runner` binary, once without and once with the OS sandbox,
//! and have it try to (1) connect to a TCP listener on loopback, (2) read a "user" file, (3) write a file
//! in the user's area, (4) start a child process. Outside the sandbox (control) these succeed; inside,
//! every one must fail. Then run real jobs through the sandbox.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use pool_runner::ipc::{read_frame, write_frame, RunRequest, RunResponse};
use pool_runner::probe::ProbeReport;
use pool_sandbox::{spawn_sandboxed, spawn_unsandboxed, SandboxConfig, SandboxLevel, Spawned};
use pool_proto::outputs::{check_output, EmbedResult, OutputContext, Transcript};
use pool_runner::testutil;

fn runner() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pool-runner"))
}

/// A directory in the user's own area (not a temp dir the sandbox might be allowed to see).
fn user_area() -> tempfile::TempDir {
    let base = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap();
    let base = base.join(".cache");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new().prefix("pool-sandbox-probe").tempdir_in(base).unwrap()
}

fn collect(mut s: Spawned) -> (i32, String, String) {
    drop(s.stdin);
    let mut out = String::new();
    let mut err = String::new();
    s.stdout.read_to_string(&mut out).unwrap();
    s.stderr.read_to_string(&mut err).unwrap();
    let code = s.process.wait().unwrap();
    (code, out, err)
}

fn probe(sandboxed: bool) -> (ProbeReport, SandboxLevel) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            drop(s);
        }
    });
    let area = user_area();
    let secret = area.path().join("secret.txt");
    std::fs::write(&secret, b"user data").unwrap();
    let model_dir = tempfile::tempdir().unwrap();
    let mut args: Vec<String> = vec![
        "probe".into(),
        "--connect".into(),
        addr.to_string(),
        "--read".into(),
        secret.to_string_lossy().into(),
        "--write-dir".into(),
        area.path().to_string_lossy().into(),
        "--spawn".into(),
        "--model-dir".into(),
        model_dir.path().to_string_lossy().into(),
    ];
    if !sandboxed {
        args.push("--no-harden".into()); // control run: show the probes themselves work
    } else {
        // also try the public internet and DNS from inside the sandbox
        args.extend(["--connect".into(), "1.1.1.1:443".into(), "--dns".into(), "example.com".into()]);
    }
    let cfg = SandboxConfig { readable_dirs: vec![model_dir.path().to_path_buf()], ..Default::default() };
    let s = if sandboxed { spawn_sandboxed(&runner(), &args, &cfg) } else { spawn_unsandboxed(&runner(), &args, &cfg) }
        .expect("spawn runner");
    let level = s.level;
    let (code, out, err) = collect(s);
    assert_eq!(code, 0, "probe exited {code}: stdout={out} stderr={err}");
    (serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("bad probe output {out:?}: {e}")), level)
}

#[test]
fn control_run_without_sandbox_can_escape() {
    let (rep, level) = probe(false);
    assert_eq!(level, SandboxLevel::None);
    assert!(rep.net_connect[0].ok, "control connect failed: {rep:?}");
    assert!(rep.file_read[0].ok, "control read failed: {rep:?}");
    assert!(rep.file_write[0].ok, "control write failed: {rep:?}");
    assert!(rep.spawn.as_ref().unwrap().ok, "control spawn failed: {rep:?}");
}

#[test]
fn sandboxed_runner_has_no_network_no_user_files_no_children() {
    let (rep, level) = probe(true);
    eprintln!("sandbox level: {level:?}\nreport: {rep:#?}");
    assert_ne!(level, SandboxLevel::None);
    assert!(!rep.net_connect[0].ok, "network connect must fail in the sandbox: {rep:?}");
    assert!(!rep.spawn.as_ref().unwrap().ok, "child process must fail in the sandbox: {rep:?}");
    #[cfg(target_os = "linux")]
    {
        // File isolation on Linux comes from Landlock; kernels without it are reported, not silently passed.
        let ll = rep.harden.landlock.clone().unwrap_or_default();
        if ll.contains("NotEnforced") || ll.starts_with("error") {
            eprintln!("WARNING: Landlock not enforced on this kernel ({ll}); file isolation relies on AppArmor/bwrap");
            return;
        }
    }
    assert!(!rep.file_read[0].ok, "reading a user file must fail in the sandbox: {rep:?}");
    assert!(!rep.file_write[0].ok, "writing in the user's area must fail in the sandbox: {rep:?}");
    assert!(rep.all_blocked());
}

fn run_job(fx: &testutil::BundleFixture, input_format: &str, input: &[u8], sandboxed: bool) -> (RunResponse, Vec<u8>, SandboxLevel) {
    run_job_lang(fx, input_format, input, sandboxed, None)
}

fn run_job_lang(
    fx: &testutil::BundleFixture,
    input_format: &str,
    input: &[u8],
    sandboxed: bool,
    language: Option<&str>,
) -> (RunResponse, Vec<u8>, SandboxLevel) {
    let req = RunRequest {
        keyset_b64: pool_proto::keys::b64(&fx.keyset),
        manifest_b64: pool_proto::keys::b64(&fx.manifest_cose),
        expected_model_hash_hex: hex::encode(fx.model_hash),
        model_dir: fx.dir.path().to_string_lossy().into(),
        input_format: input_format.into(),
        max_output_bytes: 16 << 20,
        language: language.map(str::to_string),
    };
    let cfg = SandboxConfig { readable_dirs: vec![fx.dir.path().to_path_buf()], ..Default::default() };
    let args = vec!["run".to_string()];
    let mut s = if sandboxed { spawn_sandboxed(&runner(), &args, &cfg) } else { spawn_unsandboxed(&runner(), &args, &cfg) }
        .expect("spawn");
    write_frame(&mut s.stdin, &serde_json::to_vec(&req).unwrap()).unwrap();
    write_frame(&mut s.stdin, input).unwrap();
    s.stdin.flush().unwrap();
    let level = s.level;
    let resp: RunResponse = serde_json::from_slice(&read_frame(&mut s.stdout, 1 << 20).unwrap()).unwrap();
    let out = read_frame(&mut s.stdout, 64 << 20).unwrap();
    let _ = s.process.wait();
    (resp, out, level)
}

#[test]
fn embeddings_job_runs_inside_the_sandbox() {
    let fx = testutil::bundle_fixture(&testutil::tiny_bert_files());
    let input = br#"{"inputs":["hello world","we pay for verified work only"]}"#;
    let (resp, out, level) = run_job(&fx, pool_proto::EMBED_BATCH_FORMAT, input, true);
    assert!(resp.ok, "{resp:?}");
    assert_ne!(level, SandboxLevel::None);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["dim"], 16);
    // closed EmbedResult (cddl 1.1.0): exactly model_id, dim, embeddings
    assert_eq!(v.as_object().unwrap().len(), 3);
    assert_eq!(v["model_id"], "test-model");
    let ctx = OutputContext { model_id: "test-model", duration_s: None, n_inputs: Some(2) };
    check_output(pool_proto::EMBED_RESULT_FORMAT, &out, ctx).unwrap();
    let e = v["embeddings"].as_array().unwrap();
    assert_eq!(e.len(), 2);
    let norm: f64 = e[0].as_array().unwrap().iter().map(|x| x.as_f64().unwrap().powi(2)).sum::<f64>().sqrt();
    assert!((norm - 1.0).abs() < 1e-3, "embeddings are L2-normalized: {norm}");
}

#[test]
fn transcription_job_runs_inside_the_sandbox() {
    let fx = testutil::bundle_fixture_with(
        &testutil::tiny_whisper_files(),
        "candle",
        "safetensors",
        pool_proto::CANONICAL_AUDIO_FORMAT,
        "whisper-tiny-test",
    );
    let audio = testutil::flac_tone(1500);
    let (resp, out, _) = run_job(&fx, pool_proto::CANONICAL_AUDIO_FORMAT, &audio, true);
    assert!(resp.ok, "{resp:?}");
    assert_eq!(resp.units_device_milli, Some(1500));
    // closed Transcript (cddl 1.1.0): the server's schema checks pass for a 1.5 s chunk
    let ctx = OutputContext { model_id: "whisper-tiny-test", duration_s: Some(1.5), n_inputs: None };
    check_output(pool_proto::TRANSCRIPT_FORMAT, &out, ctx).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    for k in v.as_object().unwrap().keys() {
        assert!(["model_id", "language", "text", "segments"].contains(&k.as_str()), "extra key {k}");
    }
    assert!(v["segments"].as_array().unwrap().len() <= 1);

    // the lease's language hint is forced: the tiny model knows <|tr|>, so no auto-detect
    let (resp, out, _) = run_job_lang(&fx, pool_proto::CANONICAL_AUDIO_FORMAT, &audio, true, Some("tr-TR"));
    assert!(resp.ok, "{resp:?}");
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["language"], "tr");
    check_output(pool_proto::TRANSCRIPT_FORMAT, &out, ctx).unwrap();
}

/// Dev builds: the shared dev catalog's placeholder bundles (ct2 `model.bin` + `config.json` with
/// `"dev_reference": true`) run the server's deterministic reference model, byte-compatible with the server's dev reference outputs.
#[test]
fn dev_reference_bundles_run_inside_the_sandbox() {
    let mut model_bin = 6u32.to_le_bytes().to_vec();
    model_bin.extend_from_slice(&[0x5a; 1020]);
    let fx = testutil::bundle_fixture_with(
        &[
            ("model.bin", model_bin),
            ("config.json", br#"{"dev_reference": true, "model_id": "whisper-tiny", "sample_rate": 16000}"#.to_vec()),
            ("vocabulary.txt", b"alpha bravo".to_vec()),
        ],
        "ctranslate2",
        "ct2",
        pool_proto::CANONICAL_AUDIO_FORMAT,
        "whisper-tiny",
    );
    let audio = testutil::flac_tone(1500);
    let (resp, out, _) = run_job_lang(&fx, pool_proto::CANONICAL_AUDIO_FORMAT, &audio, true, Some("de"));
    assert!(resp.ok, "{resp:?}");
    assert_eq!(resp.backend.as_deref(), Some("dev-reference"));
    let t: Transcript = serde_json::from_slice(&out).unwrap();
    assert_eq!(t.language.as_deref(), Some("de"));
    assert_eq!(t.segments.len(), 1);
    assert_eq!((t.segments[0].start_s, t.segments[0].end_s), (0.0, 1.5));
    assert_eq!(t.text.split(' ').count(), 16);
    let ctx = OutputContext { model_id: "whisper-tiny", duration_s: Some(1.5), n_inputs: None };
    check_output(pool_proto::TRANSCRIPT_FORMAT, &out, ctx).unwrap();

    let fx = testutil::bundle_fixture_with(
        &[("model.onnx", vec![8, 8]), ("config.json", br#"{"dev_reference": true, "dim": 384}"#.to_vec())],
        "onnxruntime",
        "onnx",
        pool_proto::EMBED_BATCH_FORMAT,
        "bge-small-en-v1.5",
    );
    let (resp, out, _) = run_job(&fx, pool_proto::EMBED_BATCH_FORMAT, br#"{"inputs":["hello world","x"]}"#, true);
    assert!(resp.ok, "{resp:?}");
    let ctx = OutputContext { model_id: "bge-small-en-v1.5", duration_s: None, n_inputs: Some(2) };
    check_output(pool_proto::EMBED_RESULT_FORMAT, &out, ctx).unwrap();
    let r: EmbedResult = serde_json::from_slice(&out).unwrap();
    assert_eq!(r.dim, 384);
    // serde_json's default float parser may be off by one ulp; the emitted text itself is shortest-roundtrip
    let want = pool_runner::backends::dev_reference::ref_embed("hello world", 384);
    assert!(r.embeddings[0].iter().zip(&want).all(|(a, b)| (a - b).abs() < 1e-15));
    let text = String::from_utf8(out.clone()).unwrap();
    assert!(text.contains(&serde_json::to_string(&want[..3]).unwrap()[1..40]), "exact digits are emitted");

    // a ct2 bundle whose signed, hash-correct model.bin is a pickle stream is refused
    let fx = testutil::bundle_fixture_with(
        &[("model.bin", vec![0x80, 0x04, 0x95, 0, 0, 0, 0, 0]), ("config.json", br#"{"dev_reference": true}"#.to_vec())],
        "ctranslate2",
        "ct2",
        pool_proto::CANONICAL_AUDIO_FORMAT,
        "whisper-tiny",
    );
    let (resp, _, _) = run_job(&fx, pool_proto::CANONICAL_AUDIO_FORMAT, &audio, true);
    assert_eq!(resp.error_code.as_deref(), Some("bundle_invalid"), "{resp:?}");
}

#[test]
fn sandboxed_runner_rejects_tampered_bundle_and_non_canonical_input() {
    let fx = testutil::bundle_fixture(&testutil::tiny_bert_files());
    // non-canonical input (a WAV header declared as FLAC) is rejected before decode
    let (resp, _, _) = run_job(&fx, pool_proto::CANONICAL_AUDIO_FORMAT, b"RIFF\0\0\0\0WAVEfmt ", true);
    assert_eq!(resp.error_code.as_deref(), Some("input_rejected"));
    let (resp, _, _) = run_job(&fx, "audio/mpeg", b"ID3", true);
    assert_eq!(resp.error_code.as_deref(), Some("input_rejected"));
    // tamper with the weights after signing
    let p = fx.dir.path().join("model.safetensors");
    let mut w = std::fs::read(&p).unwrap();
    let n = w.len();
    w[n - 1] ^= 0xff;
    std::fs::write(&p, w).unwrap();
    let (resp, _, _) = run_job(&fx, pool_proto::EMBED_BATCH_FORMAT, br#"{"inputs":["a"]}"#, true);
    assert_eq!(resp.error_code.as_deref(), Some("bundle_invalid"), "{resp:?}");
}
