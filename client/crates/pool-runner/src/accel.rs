//! Native runtime **packs** (ONNX Runtime today) and the GPU device choice for candle.
//!
//! A pack is a fixed set of prebuilt library files for one runtime and one target. Which packs exist, their files,
//! load order and SHA-256 are **data** (`packs.json` next to this crate's `Cargo.toml`, compiled into the binary), so
//! another runtime or target is added by adding an entry, not code:
//! * Windows x64 (`ort-directml`): Microsoft's ONNX Runtime DirectML build with `DirectML.dll` and the Visual C++
//!   runtime. GPUs through DirectML (any DX12 GPU), with the pack's own CPU provider as fallback.
//! * macOS arm64 and Linux x64 (`ort-cpu`): Microsoft's ONNX Runtime CPU library from the official
//!   `Microsoft.ML.OnnxRuntime` nuget.org package (owner decision T-218). CPU provider only.
//!
//! Rules:
//! * Every file is checked against its pin on **every job start**, by the agent (before it lets the sandbox read the
//!   pack) and again by the runner (right before loading). Any other file or version is refused. A pin changes only
//!   with a signed app update.
//! * Every pinned file is loaded by **full path** after its hash matched, in the listed order, so each import resolves
//!   to an already-loaded, checked module, never to a copy the machine has installed or a library placed next to the
//!   runner. The runtime is then initialised from the pack's `library` by full path (`ort` `load-dynamic`). On Linux
//!   the runner hashes each file from one open descriptor and loads `/proc/self/fd/<n>` of that descriptor, so the
//!   file that was checked is the file that is mapped ([`open_verified`]).
//! * The pack directory is only *readable* inside the sandbox (the agent grants read access like a model dir; on
//!   Linux the runner adds it to its Landlock read set); the runner gets no network or other file access for it.
//!   Models still come only from signed bundles.
//! * A missing or mismatching pack refuses `onnxruntime` jobs: ONNX Runtime is never searched for on the default
//!   library path, and there is no fallback through another library. The backend actually used is reported
//!   (`onnxruntime-directml` / `onnxruntime-cpu`), never assumed.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Environment variable through which pool-core passes the verified pack directory to the sandboxed runner.
pub const PACK_ENV: &str = "POOL_ORT_PACK_DIR";

/// The pack table (`packs.json`).
pub const PACKS_JSON: &str = include_str!("../packs.json");

/// One pinned runtime pack.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Pack {
    pub runtime: String,
    /// `<os>-<arch>` as [`std::env::consts`] spells them, e.g. `macos-aarch64`.
    pub target: String,
    /// Directory name under `backends/` in the installed app.
    pub dir: String,
    /// The file the runtime is initialised from (one of `files`).
    pub library: String,
    /// In load order.
    pub files: Vec<PackFile>,
}

/// One pinned file: its name in the pack directory and its SHA-256 (lower-case hex). Where it comes from is read
/// only by the build scripts.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PackFile {
    pub name: String,
    pub sha256: String,
}

#[derive(serde::Deserialize)]
struct PackTable {
    packs: Vec<Pack>,
}

/// Every pack in `packs.json`. A malformed table is a build defect caught by the tests; at run time it yields no
/// packs, so every ONNX job is refused (fail closed).
pub fn packs() -> &'static [Pack] {
    static PACKS: OnceLock<Vec<Pack>> = OnceLock::new();
    PACKS.get_or_init(|| serde_json::from_str::<PackTable>(PACKS_JSON).map(|t| t.packs).unwrap_or_default())
}

/// This binary's target key, e.g. `windows-x86_64`.
pub fn this_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The pack of `runtime` for `target`, if one is pinned.
pub fn pack_for(runtime: &str, target: &str) -> Option<&'static Pack> {
    packs().iter().find(|p| p.runtime == runtime && p.target == target)
}

/// The ONNX Runtime pack for this binary's target (`None`: ONNX jobs cannot run here).
pub fn ort_pack() -> Option<&'static Pack> {
    pack_for("onnxruntime", &this_target())
}

/// The pinned files of this target's ONNX Runtime pack, in load order (empty when there is none).
pub fn pinned() -> &'static [PackFile] {
    ort_pack().map(|p| p.files.as_slice()).unwrap_or(&[])
}

/// This build can run candle jobs on an Apple silicon GPU through Metal (`metal` feature, macOS, aarch64). Reported by
/// `pool-runner capabilities`; the agent grants the GPU sandbox rules only when it is true.
pub const METAL_BUILD: bool = cfg!(all(feature = "metal", target_os = "macos", target_arch = "aarch64"));

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
            PackError::NoPack => write!(f, "no ONNX Runtime pack for this OS"),
            PackError::Missing(n) => write!(f, "runtime pack lacks {n}"),
            PackError::HashMismatch(n) => write!(f, "runtime pack file {n} does not match its pinned SHA-256"),
            PackError::Load(e) => write!(f, "runtime pack failed to load: {e}"),
        }
    }
}

/// Check every pinned file of this target's ONNX Runtime pack in `dir`. Used by pool-core before it grants the
/// sandbox read access, and by the runner again right before loading. Returns the files' full paths in load order.
pub fn verify_pack(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    let Some(pack) = ort_pack() else { return Err(PackError::NoPack) };
    verify_files(dir, &pack.files)
}

/// Check `files` in `dir` against their pins.
pub fn verify_files(dir: &Path, files: &[PackFile]) -> Result<Vec<PathBuf>, PackError> {
    if files.is_empty() {
        return Err(PackError::NoPack);
    }
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let p = dir.join(&f.name);
        let bytes = std::fs::read(&p).map_err(|_| PackError::Missing(f.name.clone()))?;
        if hex::encode(pool_proto::sha256(&bytes)) != f.sha256 {
            return Err(PackError::HashMismatch(f.name.clone()));
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

#[cfg(all(unix, feature = "onnx"))]
fn load_by_full_path(p: &Path) -> Result<(), PackError> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|e| PackError::Load(e.to_string()))?;
    // SAFETY: a valid NUL-terminated path; the handle stays open for the process lifetime (one job).
    let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if h.is_null() {
        // SAFETY: dlerror returns a thread-local C string or NULL, read right after the failing call
        let e = unsafe { libc::dlerror() };
        let msg = if e.is_null() {
            "dlopen failed".to_string()
        } else {
            // SAFETY: non-null, NUL-terminated, valid until the next dl* call on this thread
            unsafe { std::ffi::CStr::from_ptr(e) }.to_string_lossy().into_owned()
        };
        return Err(PackError::Load(format!("{}: {msg}", p.display())));
    }
    Ok(())
}

/// Linux: open every pinned file once, hash it **from that open descriptor**, and return the descriptors' paths
/// (`/proc/self/fd/<n>`) in load order. Loading through those paths maps exactly the file that was hashed, even if
/// the pack directory is changed between the check and the load (a rename or a swapped entry cannot redirect the
/// load). The descriptors stay open for the rest of the process (one job), so the paths stay valid for `ort` too.
/// A pinned name that is a symlink or not a regular file is refused.
#[cfg(target_os = "linux")]
pub fn open_verified(dir: &Path, files: &[PackFile]) -> Result<Vec<PathBuf>, PackError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::IntoRawFd;
    if files.is_empty() {
        return Err(PackError::NoPack);
    }
    let mut opened = Vec::with_capacity(files.len());
    for f in files {
        let p = dir.join(&f.name);
        // O_NOFOLLOW: the pinned name itself must not be a symlink; O_CLOEXEC: never inherited
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&p)
            .map_err(|_| PackError::Missing(f.name.clone()))?;
        if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err(PackError::Missing(f.name.clone()));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| PackError::Missing(f.name.clone()))?;
        if hex::encode(pool_proto::sha256(&bytes)) != f.sha256 {
            return Err(PackError::HashMismatch(f.name.clone()));
        }
        opened.push(file);
    }
    // only once every file matched: keep the descriptors open for the process lifetime
    Ok(opened.into_iter().map(|f| PathBuf::from(format!("/proc/self/fd/{}", f.into_raw_fd()))).collect())
}

/// Verify and load the pack named by [`PACK_ENV`] and initialise `ort` from it. `Ok(true)` = the pack is ready.
#[cfg(feature = "onnx")]
pub fn init_from_env() -> Result<bool, PackError> {
    let Some(dir) = std::env::var_os(PACK_ENV).map(PathBuf::from) else {
        return Ok(false);
    };
    let pack = ort_pack().ok_or(PackError::NoPack)?;
    let lib_index = pack.files.iter().position(|f| f.name == pack.library).ok_or_else(|| PackError::Missing(pack.library.clone()))?;
    // Linux: hash and load the same open file (vault follow-up to CR-T215-01). Elsewhere: hash by path, then load by
    // the same full path (macOS moves to a same-file load with the Developer ID work).
    #[cfg(target_os = "linux")]
    let files = open_verified(&dir, &pack.files)?;
    #[cfg(not(target_os = "linux"))]
    let files = verify_files(&dir, &pack.files)?;
    for f in &files {
        load_by_full_path(f)?;
    }
    // `ort` opens the library by this exact path. On Linux it is the descriptor path loaded above, so the dynamic
    // loader returns that module instead of opening the directory entry again.
    let lib = &files[lib_index];
    ort::init_from(lib.to_string_lossy()).commit().map_err(|e| PackError::Load(e.to_string()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_files_must_match_their_pins() {
        let d = tempfile::tempdir().unwrap();
        let pinned = pinned();
        if pinned.is_empty() {
            assert_eq!(verify_pack(d.path()), Err(PackError::NoPack));
            return;
        }
        assert_eq!(verify_pack(d.path()), Err(PackError::Missing(pinned[0].name.clone())));
        for f in pinned {
            std::fs::write(d.path().join(&f.name), b"not the pinned file").unwrap();
        }
        assert_eq!(verify_pack(d.path()), Err(PackError::HashMismatch(pinned[0].name.clone())));
    }

    /// Linux: the bytes that are hashed are the bytes behind the returned path. Replacing the directory entry after
    /// the check (what an attacker racing the load would do) does not change what the path opens; a symlink in
    /// place of a pinned file, a mismatch or a missing file is refused before any descriptor is handed out.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_load_paths_name_the_hashed_file() {
        let d = tempfile::tempdir().unwrap();
        let good = b"the pinned library bytes".to_vec();
        let other = b"a second pinned file".to_vec();
        let files = vec![
            PackFile { name: "libdep.so".into(), sha256: hex::encode(pool_proto::sha256(&other)) },
            PackFile { name: "libpinned.so".into(), sha256: hex::encode(pool_proto::sha256(&good)) },
        ];
        std::fs::write(d.path().join("libdep.so"), &other).unwrap();
        std::fs::write(d.path().join("libpinned.so"), &good).unwrap();
        let paths = open_verified(d.path(), &files).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.starts_with("/proc/self/fd/")), "{paths:?}");
        // swap the directory entry for different bytes: the descriptor path still reads the checked file
        std::fs::remove_file(d.path().join("libpinned.so")).unwrap();
        std::fs::write(d.path().join("libpinned.so"), b"planted after the check").unwrap();
        assert_eq!(std::fs::read(&paths[1]).unwrap(), good);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), other);

        // refused: a mismatch, a missing file, a symlink in place of a pinned file
        std::fs::write(d.path().join("libpinned.so"), b"tampered").unwrap();
        assert_eq!(open_verified(d.path(), &files), Err(PackError::HashMismatch("libpinned.so".into())));
        std::fs::remove_file(d.path().join("libpinned.so")).unwrap();
        assert_eq!(open_verified(d.path(), &files), Err(PackError::Missing("libpinned.so".into())));
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("real.so"), &good).unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("real.so"), d.path().join("libpinned.so")).unwrap();
        assert_eq!(open_verified(d.path(), &files), Err(PackError::Missing("libpinned.so".into())));
        assert_eq!(open_verified(d.path(), &[]), Err(PackError::NoPack));
    }

    /// The table parses, and every entry is well formed: one pack per runtime and target, plain file names,
    /// lower-case hex SHA-256 pins, the library among the files.
    #[test]
    fn pack_table_is_well_formed() {
        let t: PackTable = serde_json::from_str(PACKS_JSON).expect("packs.json parses");
        assert_eq!(t.packs.len(), packs().len());
        let plain = |n: &str| !n.is_empty() && !n.starts_with('.') && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        let mut seen = std::collections::HashSet::new();
        for p in packs() {
            assert!(seen.insert((p.runtime.clone(), p.target.clone())), "duplicate pack {} {}", p.runtime, p.target);
            assert!(!p.files.is_empty(), "{}", p.target);
            assert!(p.files.iter().any(|f| f.name == p.library), "{}: library not among the files", p.target);
            assert!(plain(&p.dir), "{}", p.dir);
            for f in &p.files {
                assert!(plain(&f.name), "{}", f.name);
                assert_eq!(f.sha256.len(), 64, "{}", f.name);
                assert!(f.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{}", f.name);
            }
        }
        // the three desktop targets have an ONNX Runtime pack
        for target in ["windows-x86_64", "macos-aarch64", "linux-x86_64"] {
            assert!(pack_for("onnxruntime", target).is_some(), "{target}");
        }
    }
}
