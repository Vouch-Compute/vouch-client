//! Pre-emption SLA: a running sandboxed job is killed and reported as pre-empted well within 5 s of the
//! user returning (the protocol's rule: "node frees the GPU <= 5 s p95").

use std::time::{Duration, Instant};

use pool_core::registry::CachedModel;
use pool_core::runner_client::{Preempt, RunError, RunnerClient};

fn runner_exe() -> std::path::PathBuf {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "pool-runner", "--bin", "pool-runner"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(status.success());
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(if cfg!(windows) { "pool-runner.exe" } else { "pool-runner" })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn running_job_is_killed_within_five_seconds() {
    let fx = pool_runner::testutil::bundle_fixture_with(
        &pool_runner::testutil::tiny_whisper_files(),
        "candle",
        "safetensors",
        pool_proto::CANONICAL_AUDIO_FORMAT,
        "whisper-tiny-test",
    );
    let model = CachedModel {
        manifest: fx.manifest.clone(),
        manifest_cose: fx.manifest_cose.clone(),
        model_hash: fx.model_hash,
        dir: fx.dir.path().to_path_buf(),
    };
    let runner = RunnerClient { exe: runner_exe(), memory_limit_bytes: 4 << 30, ort_pack_dir: None };
    // 10 minutes of audio: far longer than the time until pre-emption
    let audio = pool_runner::testutil::flac_tone(10 * 60 * 1000);
    let p = Preempt::default();
    let p2 = p.clone();
    let fired_at = std::sync::Arc::new(std::sync::Mutex::new(None));
    let f2 = fired_at.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(4)).await;
        *f2.lock().unwrap() = Some(Instant::now());
        p2.fire();
    });
    let started = Instant::now();
    let r = runner.run(&fx.keyset, &model, pool_proto::CANONICAL_AUDIO_FORMAT, audio, Some("en"), p).await;
    let fired = fired_at.lock().unwrap().expect("job finished before pre-emption fired; make it longer");
    let release = fired.elapsed();
    eprintln!("job ran {:?}, released {:?} after pre-emption", started.elapsed(), release);
    assert_eq!(r.unwrap_err(), RunError::Preempted);
    assert!(release < Duration::from_secs(5), "pre-emption took {release:?}");
}
