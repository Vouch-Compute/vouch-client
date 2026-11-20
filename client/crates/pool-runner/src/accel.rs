//! GPU acceleration through a pinned ONNX Runtime **backend pack**.
//!
//! On Windows, GPUs are used through DirectML: a DX12 API in Microsoft's prebuilt `onnxruntime.dll` (DirectML build)
//! plus `DirectML.dll`, loaded at runtime (`ort` `load-dynamic`). It runs on any DX12 GPU (NVIDIA, AMD, Intel) and
//! needs neither a CUDA toolkit nor an MSVC build.
//!
//! Rules:
//! * The pack is a fixed set of files whose SHA-256 is **pinned in this binary** ([`PINNED`]): Microsoft's releases,
//!   all Authenticode-signed by Microsoft. Any other file or version is refused.
//! * The pins are checked on **every job start**, by the agent (before it lets the sandbox read the pack) and again by
//!   the runner (right before loading). A pin changes only with a signed app update.
//! * Every pinned DLL is loaded by **full path** after its hash matched, in [`PINNED`] order: the Visual C++ runtime
//!   first, then `DirectML.dll`, then `onnxruntime.dll`, so each import resolves to an already-loaded, checked module,
//!   never to whatever copy the machine has installed or a DLL placed next to the runner.
//! * The pack directory is only *readable* inside the sandbox (the agent grants read access like a model dir); the
//!   runner gets no network or other file access for it. Models still come only from signed bundles.
//! * A missing or mismatching pack refuses `onnxruntime` jobs: ONNX Runtime is never searched for on the default DLL
//!   path, and there is no fallback through another library. With the pinned pack, a GPU failure (no DX12 GPU, a
//!   driver error) falls back to the pack's own CPU provider; the backend actually used is reported
//!   (`onnxruntime-directml` / `onnxruntime-cpu`), never assumed.

use std::path::{Path, PathBuf};

/// Environment variable through which pool-core passes the verified pack directory to the sandboxed runner.
pub const PACK_ENV: &str = "POOL_ORT_PACK_DIR";

/// The pinned pack: file name and SHA-256 (hex), in load order. Windows x64:
/// * the Visual C++ 2015-2022 runtime 14.51.36247.0 that `onnxruntime.dll` links against (`vcruntime140.dll`,
///   `vcruntime140_1.dll`, `msvcp140.dll`; Microsoft's redistributable files, shipped app-local from
///   `pool-app/vendor/vcruntime/`), so the GPU path never depends on what the machine has installed;
/// * Microsoft.AI.DirectML 1.15.4 (`bin/x64-win/DirectML.dll`);
/// * Microsoft.ML.OnnxRuntime.DirectML 1.22.0 (`runtimes/win-x64/native/onnxruntime.dll`).
#[cfg(windows)]
pub const PINNED: &[(&str, &str)] = &[
    ("vcruntime140.dll", "d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7"),
    ("vcruntime140_1.dll", "a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e"),
    ("msvcp140.dll", "7c26614e1d733892c2deac7e245ce115504b1d80592dd0a01b08e3e5a55f89ca"),
    ("DirectML.dll", "9c9e6d822561c6c41b90e6994b3e8857cf1d66dbfb1e0c4c799c7c89b4e92da1"),
    ("onnxruntime.dll", "95366724919f4e95ecc60010912ed538ad9804b6683fbd0aad389749102834b9"),
];
/// No pinned GPU pack on this OS: Linux GPUs use the `cuda` feature (candle), and Apple silicon Macs use the `metal`
/// feature (candle on the system Metal framework, nothing to pin). Intel Macs have no GPU path and use the CPU.
#[cfg(not(windows))]
pub const PINNED: &[(&str, &str)] = &[];

/// `1` = use the pack's CPU provider only (the user's "Use the GPU" setting off, or a test's CPU baseline).
pub const FORCE_CPU_ENV: &str = "POOL_ORT_FORCE_CPU";

/// The device for candle backends: CUDA (`cuda` builds) or Metal (`metal` builds, macOS) when a GPU is usable and
/// [`FORCE_CPU_ENV`] is not set; the CPU otherwise. Returns the device and the backend label reported for the job.
#[cfg(feature = "candle")]
pub fn candle_device() -> (candle_core::Device, &'static str) {
    #[cfg(feature = "cuda")]
    if std::env::var(FORCE_CPU_ENV).as_deref() != Ok("1") {
        match candle_core::Device::new_cuda(0) {
            Ok(d) => return (d, "candle-cuda"),
            Err(e) => eprintln!("CUDA unavailable, using the CPU: {e}"),
        }
    }
    #[cfg(all(feature = "metal", target_os = "macos"))]
    if std::env::var(FORCE_CPU_ENV).as_deref() != Ok("1") {
        match metal_device() {
            Ok(d) => return (d, "candle-metal"),
            Err(e) => eprintln!("Metal unavailable, using the CPU: {e}"),
        }
    }
    (candle_core::Device::Cpu, "candle-cpu")
}

/// The device for candle Whisper. Same as [`candle_device`] except on Metal: measured on an M3 Pro (whisper-base,
/// 60 s of speech, one job per runner process), Metal took 18.9 s and the CPU 8.2 s with identical transcripts:
/// decoding is many small sequential kernels, and each job pays Metal's start-up again. So transcription stays on
/// the CPU in `metal` builds (and the agent does not grant those jobs the GPU). `POOL_METAL_WHISPER=1` (benchmarks
/// only; the agent never sets it) still selects Metal when the sandbox allows it.
#[cfg(feature = "candle")]
pub fn candle_transcription_device() -> (candle_core::Device, &'static str) {
    #[cfg(all(feature = "metal", not(feature = "cuda")))]
    if std::env::var(METAL_WHISPER_ENV).as_deref() != Ok("1") {
        return (candle_core::Device::Cpu, "candle-cpu");
    }
    candle_device()
}

/// See [`candle_transcription_device`].
pub const METAL_WHISPER_ENV: &str = "POOL_METAL_WHISPER";

/// A Metal device that has actually run a kernel: creating the device can succeed inside a sandbox that later
/// refuses the shader compiler or the GPU user client, so a small matmul is checked before any job uses it.
#[cfg(all(feature = "candle", feature = "metal", target_os = "macos"))]
pub fn metal_device() -> candle_core::Result<candle_core::Device> {
    // candle's Device::new_metal panics (and release builds abort) when no Metal device is visible, e.g. in a
    // sandbox without the GPU allowances; ask Metal itself first.
    if !metal_device_visible() {
        candle_core::bail!("no Metal device visible");
    }
    let d = candle_core::Device::new_metal(0)?;
    let a = candle_core::Tensor::arange(0f32, 6., &d)?.reshape((2, 3))?;
    let p = a.matmul(&a.t()?)?.to_vec2::<f32>()?;
    if p != [[5.0, 14.0], [14.0, 50.0]] {
        candle_core::bail!("Metal self-test returned {p:?}");
    }
    Ok(d)
}

/// Apple silicon only: on Intel Macs (x86_64) Metal jobs are not supported and the job runs on the CPU.
#[cfg(all(feature = "candle", feature = "metal", target_os = "macos"))]
fn metal_device_visible() -> bool {
    if !cfg!(target_arch = "aarch64") {
        return false;
    }
    #[link(name = "Metal", kind = "framework")]
    extern "C" {
        fn MTLCreateSystemDefaultDevice() -> *mut std::ffi::c_void;
    }
    #[link(name = "objc")]
    extern "C" {
        fn objc_release(obj: *mut std::ffi::c_void);
    }
    // SAFETY: a plain C entry point of Metal.framework; it returns a +1 retained id<MTLDevice> or nil.
    let d = unsafe { MTLCreateSystemDefaultDevice() };
    if d.is_null() {
        return false;
    }
    // SAFETY: `d` is the retained object returned above, released exactly once.
    unsafe { objc_release(d) };
    true
}

/// The ONNX Runtime library inside the pack.
pub const ORT_LIB: &str = if cfg!(windows) { "onnxruntime.dll" } else { "libonnxruntime.so" };

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    NoPack,
    Missing(String),
    HashMismatch(String),
    Load(String),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackError::NoPack => write!(f, "no GPU backend pack for this OS"),
            PackError::Missing(n) => write!(f, "backend pack lacks {n}"),
            PackError::HashMismatch(n) => write!(f, "backend pack file {n} does not match its pinned SHA-256"),
            PackError::Load(e) => write!(f, "backend pack failed to load: {e}"),
        }
    }
}

/// Check every pinned file of the pack in `dir`. Used by pool-core before it grants the sandbox read access, and by
/// the runner again right before loading.
pub fn verify_pack(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    if PINNED.is_empty() {
        return Err(PackError::NoPack);
    }
    let mut out = Vec::with_capacity(PINNED.len());
    for (name, want) in PINNED {
        let p = dir.join(name);
        let bytes = std::fs::read(&p).map_err(|_| PackError::Missing((*name).into()))?;
        if hex::encode(pool_proto::sha256(&bytes)) != *want {
            return Err(PackError::HashMismatch((*name).into()));
        }
        out.push(p);
    }
    Ok(out)
}

#[cfg(all(windows, feature = "onnx"))]
fn load_by_full_path(p: &Path) -> Result<(), PackError> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    }
    // LOAD_WITH_ALTERED_SEARCH_PATH: the DLL's own dependencies are searched next to it first
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: a valid NUL-terminated wide path; the module stays loaded for the process lifetime (one job).
    let h = unsafe { LoadLibraryExW(w.as_ptr(), 0, LOAD_WITH_ALTERED_SEARCH_PATH) };
    if h == 0 {
        return Err(PackError::Load(format!("{}: {}", p.display(), std::io::Error::last_os_error())));
    }
    Ok(())
}

/// Verify and load the pack named by [`PACK_ENV`] and initialise `ort` from it. `Ok(true)` = the GPU pack is ready.
#[cfg(feature = "onnx")]
pub fn init_from_env() -> Result<bool, PackError> {
    let Some(dir) = std::env::var_os(PACK_ENV).map(PathBuf::from) else {
        return Ok(false);
    };
    let files = verify_pack(&dir)?;
    #[cfg(windows)]
    for f in &files {
        load_by_full_path(f)?;
    }
    let _ = files;
    ort::init_from(dir.join(ORT_LIB).to_string_lossy()).commit().map_err(|e| PackError::Load(e.to_string()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_files_must_match_their_pins() {
        let d = tempfile::tempdir().unwrap();
        if PINNED.is_empty() {
            assert_eq!(verify_pack(d.path()), Err(PackError::NoPack));
            return;
        }
        assert_eq!(verify_pack(d.path()), Err(PackError::Missing(PINNED[0].0.into())));
        for (name, _) in PINNED {
            std::fs::write(d.path().join(name), b"not the pinned file").unwrap();
        }
        assert_eq!(verify_pack(d.path()), Err(PackError::HashMismatch(PINNED[0].0.into())));
        // pins are lower-case hex SHA-256
        for (_, h) in PINNED {
            assert_eq!(h.len(), 64);
            assert!(h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }
}
