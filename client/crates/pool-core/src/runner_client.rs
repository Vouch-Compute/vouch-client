//! Runs one job in a fresh sandboxed `pool-runner` process (pool-sandbox) over the memory-only pipe
//! protocol (`pool_runner::ipc`). The returned [`Preempt`] handle kills the whole sandbox at once; the
//! pre-emption SLA (GPU released within 5 s p95) is met because the kill is immediate.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pool_runner::ipc::{read_frame, write_frame, RunRequest, RunResponse};
use pool_sandbox::{spawn_sandboxed, KillHandle, SandboxConfig, SandboxLevel};

use crate::registry::CachedModel;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RunError {
    #[error("input rejected: {0}")]
    InputRejected(String),
    #[error("bundle invalid: {0}")]
    BundleInvalid(String),
    #[error("runner failed: {0}")]
    Failed(String),
    #[error("pre-empted")]
    Preempted,
}

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub output: Vec<u8>,
    pub format: String,
    pub units_device_milli: Option<u64>,
    pub backend: Option<String>,
    pub sandbox: SandboxLevel,
}

/// Kill switch for the running job (shared with the governor loop).
#[derive(Clone, Default)]
pub struct Preempt {
    slot: Arc<Mutex<Option<KillHandle>>>,
    fired: Arc<AtomicBool>,
}

impl Preempt {
    pub fn fire(&self) {
        self.fired.store(true, Ordering::SeqCst);
        if let Some(k) = self.slot.lock().unwrap().as_ref() {
            k.kill();
        }
    }
    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

/// Hard ceiling on the runner's share of the machine's CPU (Windows Job Object; `nice` elsewhere). The same
/// for the benchmark and for jobs, so delivered throughput stays comparable with the benchmark.
pub const RUNNER_CPU_CAP_PCT: u8 = 90;

pub struct RunnerClient {
    pub exe: PathBuf,
    pub memory_limit_bytes: u64,
    /// The GPU backend pack directory ([`pool_runner::accel`]); `None` = no GPU path.
    pub ort_pack_dir: Option<PathBuf>,
    /// macOS: candle embedding jobs may use the GPU through Metal: the user's "Use the GPU" setting is on and the
    /// runner reports a Metal build ([`runner_supports_metal`]). Their sandbox then gets the Metal allowances
    /// ([`SandboxConfig::gpu`]); every other job runs with the GPU forced off.
    pub metal_gpu: bool,
}

/// What the sandbox needs for one job's runtime. ONNX Runtime jobs get the pinned backend pack, after it verified
/// here (the runner verifies it again before loading): read access to its directory and a regular AppContainer,
/// because the Less-Privileged AppContainer refuses to load DirectML/ONNX Runtime. Every
/// other job keeps the LPAC. A missing or mismatching pack adds nothing: the runner then refuses the ONNX job.
pub fn runtime_sandbox(runtime: &str, pack: Option<&std::path::Path>) -> (Vec<PathBuf>, Vec<(String, String)>, bool) {
    if runtime != "onnxruntime" {
        return (vec![], vec![], true);
    }
    match pack.map(|p| (p, pool_runner::accel::verify_pack(p))) {
        Some((p, Ok(_))) => (
            vec![p.to_path_buf()],
            vec![(pool_runner::accel::PACK_ENV.to_string(), p.to_string_lossy().into_owned())],
            false,
        ),
        Some((p, Err(e))) => {
            tracing::warn!("GPU backend pack at {} not used: {e}", p.display());
            (vec![], vec![], true)
        }
        None => (vec![], vec![], true),
    }
}

/// macOS: does the runner at `exe` say it is a Metal build (`pool-runner capabilities`)? This ties the GPU sandbox
/// rules to the one switch, pool-runner's `metal` feature: an agent never opens the GPU driver to a runner that cannot
/// use it. The runner is asked inside the sandbox (no GPU rules) with a 5 s limit; any failure means no.
pub fn runner_supports_metal(exe: &std::path::Path) -> bool {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return false;
    }
    let Ok(mut s) = pool_sandbox::spawn_sandboxed(exe, &["capabilities".to_string()], &SandboxConfig::default()) else {
        return false;
    };
    drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
    let kill = s.process.kill_handle();
    let mut stdout = std::mem::replace(&mut s.stdout, Box::new(std::io::empty()));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout, &mut out);
        let _ = tx.send(out);
    });
    let out = match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(out) => out,
        Err(_) => {
            kill.kill();
            String::new()
        }
    };
    let _ = s.process.wait();
    reports_metal(&out)
}

/// `{"metal": true}` and nothing else counts as yes.
fn reports_metal(capabilities_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(capabilities_json.trim())
        .ok()
        .and_then(|v| v.get("metal")?.as_bool())
        .unwrap_or(false)
}

/// macOS: does this job get the Metal GPU allowances? Only candle embedding jobs (candle is the runtime with a Metal
/// backend; transcription runs faster on the CPU, see `pool_runner::accel::candle_transcription_device`), and only
/// when the user lets the app use the GPU.
pub fn metal_gpu_job(runtime: &str, input_format: &str, metal_gpu: bool) -> bool {
    cfg!(target_os = "macos") && metal_gpu && runtime == "candle" && input_format == pool_proto::EMBED_BATCH_FORMAT
}

impl RunnerClient {
    /// `language`: the optional BCP 47 hint from the signed `LeaseEnvelope`, passed to Whisper.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        keyset_cose: &[u8],
        model: &CachedModel,
        input_format: &str,
        input: Vec<u8>,
        language: Option<&str>,
        preempt: Preempt,
    ) -> Result<RunOutput, RunError> {
        let req = RunRequest {
            language: language.map(str::to_string),
            keyset_b64: pool_proto::keys::b64(keyset_cose),
            manifest_b64: pool_proto::keys::b64(&model.manifest_cose),
            expected_model_hash_hex: hex::encode(model.model_hash),
            model_dir: model.dir.to_string_lossy().into(),
            input_format: input_format.into(),
            max_output_bytes: 64 << 20,
        };
        let (extra_dirs, mut env, lpac) = runtime_sandbox(&model.manifest.runtime, self.ort_pack_dir.as_deref());
        let mut readable_dirs = vec![model.dir.clone()];
        readable_dirs.extend(extra_dirs);
        let gpu = metal_gpu_job(&model.manifest.runtime, &model.manifest.input_format, self.metal_gpu);
        if cfg!(target_os = "macos") && !gpu {
            env.push((pool_runner::accel::FORCE_CPU_ENV.to_string(), "1".to_string()));
        }
        // No more POOL_ORT_DYLIB passthrough: the ONNX Runtime library comes only from the verified pack
        let cfg = SandboxConfig {
            readable_dirs,
            memory_limit_bytes: self.memory_limit_bytes,
            cpu_rate_pct: Some(RUNNER_CPU_CAP_PCT),
            lpac,
            env,
            gpu,
        };
        let exe = self.exe.clone();
        tokio::task::spawn_blocking(move || run_blocking(&exe, &cfg, &req, &input, &preempt))
            .await
            .map_err(|e| RunError::Failed(format!("join: {e}")))?
    }
}

fn run_blocking(
    exe: &std::path::Path,
    cfg: &SandboxConfig,
    req: &RunRequest,
    input: &[u8],
    preempt: &Preempt,
) -> Result<RunOutput, RunError> {
    if preempt.fired() {
        return Err(RunError::Preempted);
    }
    let t0 = std::time::Instant::now();
    let mut s = spawn_sandboxed(exe, &["run".to_string()], cfg).map_err(|e| RunError::Failed(format!("spawn: {e}")))?;
    tracing::debug!("runner spawned in {:?} ({:?})", t0.elapsed(), s.level);
    *preempt.slot.lock().unwrap() = Some(s.process.kill_handle());
    if preempt.fired() {
        s.process.kill_handle().kill();
    }
    let mut stderr = std::mem::replace(&mut s.stderr, Box::new(std::io::empty()));
    let drain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.by_ref().take(64 * 1024).read_to_end(&mut buf);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        String::from_utf8_lossy(&buf).into_owned()
    });
    let level = s.level;
    let io = (|| -> std::io::Result<(RunResponse, Vec<u8>)> {
        write_frame(&mut s.stdin, &serde_json::to_vec(req).map_err(std::io::Error::other)?)?;
        write_frame(&mut s.stdin, input)?;
        s.stdin.flush()?;
        drop(std::mem::replace(&mut s.stdin, Box::new(std::io::sink())));
        let resp: RunResponse = serde_json::from_slice(&read_frame(&mut s.stdout, 1 << 20)?).map_err(std::io::Error::other)?;
        let out = read_frame(&mut s.stdout, req.max_output_bytes)?;
        Ok((resp, out))
    })();
    let code = s.process.wait();
    tracing::debug!("runner finished in {:?}", t0.elapsed());
    *preempt.slot.lock().unwrap() = None;
    let stderr_text = drain.join().unwrap_or_default();
    if preempt.fired() {
        return Err(RunError::Preempted);
    }
    let (resp, out) = io.map_err(|e| RunError::Failed(format!("pipe: {e}; exit {code:?}; {}", stderr_text.trim())))?;
    if !resp.ok {
        let msg = resp.message.unwrap_or_default();
        return Err(match resp.error_code.as_deref() {
            Some("input_rejected") => RunError::InputRejected(msg),
            Some("bundle_invalid") => RunError::BundleInvalid(msg),
            _ => RunError::Failed(msg),
        });
    }
    Ok(RunOutput {
        output: out,
        format: resp.output_format.unwrap_or_default(),
        units_device_milli: resp.units_device_milli,
        backend: resp.backend,
        sandbox: level,
    })
}

#[cfg(test)]
mod tests {
    use super::{metal_gpu_job, reports_metal, runner_supports_metal};

    #[test]
    fn only_an_explicit_metal_capability_counts() {
        assert!(reports_metal("{\"metal\":true}\n"));
        for no in ["{\"metal\":false}", "{\"metal\":\"true\"}", "{}", "", "pool-runner 0.1.0", "{\"metal\":1}"] {
            assert!(!reports_metal(no), "{no:?}");
        }
        assert!(!runner_supports_metal(std::path::Path::new("/nonexistent/pool-runner")), "a missing runner: no grant");
    }

    #[test]
    fn only_candle_embedding_jobs_with_the_gpu_on_get_metal() {
        let (emb, audio) = (pool_proto::EMBED_BATCH_FORMAT, pool_proto::CANONICAL_AUDIO_FORMAT);
        assert!(!metal_gpu_job("candle", emb, false), "the user's GPU setting off: no GPU allowances");
        assert!(!metal_gpu_job("onnxruntime", emb, true), "only candle has a Metal backend");
        assert!(!metal_gpu_job("candle", audio, true), "transcription runs on the CPU");
        assert_eq!(metal_gpu_job("candle", emb, true), cfg!(target_os = "macos"), "Metal is a macOS-only grant");
    }
}
