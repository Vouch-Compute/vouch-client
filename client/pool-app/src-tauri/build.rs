//! Tauri build script. On Windows with the GNU toolchain, `windres` cannot open files under a non-ASCII
//! path (this repo lives under "AIİnference"), so the window icon is copied to OUT_DIR (an ASCII path
//! because CARGO_TARGET_DIR is ASCII) and passed explicitly.
use std::{env, fs, path::PathBuf};

/// `externalBin` sidecars must exist for tauri-build to succeed. `tauri build`/`tauri dev` build the real
/// ones first (scripts/sidecars.mjs); plain `cargo build/clippy -p pool-app` gets empty placeholders so it
/// can compile. A placeholder is never shipped: the bundler's beforeBuildCommand overwrites it.
fn ensure_sidecar_placeholders() {
    let triple = env::var("TARGET").unwrap();
    let exe = if triple.contains("windows") { ".exe" } else { "" };
    fs::create_dir_all("binaries").unwrap();
    for name in ["pool-core", "pool-runner"] {
        let p = PathBuf::from("binaries").join(format!("{name}-{triple}{exe}"));
        if !p.exists() {
            println!("cargo:warning=sidecar {} missing; writing a placeholder (run `npm run sidecars`)", p.display());
            fs::write(&p, b"").unwrap();
        }
    }
}

/// The Windows GPU backend pack (`backends/ort-directml/`, bundled by `tauri.windows.conf.json`). The real files come
/// from `node scripts/gpu-pack.mjs`, which checks each against its pin in `crates/pool-runner/src/accel.rs` and replaces
/// any file that does not match.
/// * Non-release builds: a missing file gets an empty placeholder so a fresh checkout can `cargo build/test/clippy`.
///   A placeholder never matches its pin, so the agent and the runner refuse the pack at job start (ONNX jobs
///   do not run) and gpu-pack.mjs replaces it.
/// * Release builds (`POOL_RELEASE=1`): every pinned file must be present with its pinned SHA-256; a missing file, a
///   placeholder or any other mismatch fails the build, so no release bundle ships without the exact pinned pack.
fn gpu_pack() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    use sha2::{Digest, Sha256};
    let accel = "../../crates/pool-runner/src/accel.rs";
    println!("cargo:rerun-if-changed={accel}");
    let src = fs::read_to_string(accel).expect("read accel.rs pins").replace("\r\n", "\n");
    let start = src.find("#[cfg(windows)]\npub const PINNED").expect("windows PINNED in accel.rs");
    let block = &src[start..start + src[start..].find("];").expect("end of PINNED")];
    let pins: Vec<(&str, &str)> = block
        .lines()
        .filter_map(|l| {
            let mut q = l.split('"');
            let (_, name, _, hash) = (q.next()?, q.next()?, q.next()?, q.next()?);
            (hash.len() == 64).then_some((name, hash))
        })
        .collect();
    assert!(!pins.is_empty(), "no GPU pack pins found in accel.rs");
    let release = env::var("POOL_RELEASE").as_deref() == Ok("1");
    let dir = PathBuf::from("backends").join("ort-directml");
    fs::create_dir_all(&dir).unwrap();
    for (name, pin) in pins {
        let p = dir.join(name);
        println!("cargo:rerun-if-changed={}", p.display());
        if release {
            let got = fs::read(&p).map(|b| hex(&Sha256::digest(&b))).unwrap_or_default();
            assert!(
                got == pin,
                "release build: GPU pack file {} is missing, a placeholder or does not match its pin (run `node scripts/gpu-pack.mjs`)",
                p.display()
            );
        } else if !p.exists() {
            println!("cargo:warning=GPU pack file {} missing; writing a placeholder (run `node scripts/gpu-pack.mjs`)", p.display());
            fs::write(&p, b"").unwrap();
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Release-signing configuration (`POOL_RELEASE=1`): the app uses the release updater
/// channel, which needs the release keys and endpoint at build time, and never a dev key.
fn release_channel() {
    println!("cargo::rustc-check-cfg=cfg(app_release)");
    println!("cargo:rerun-if-env-changed=POOL_RELEASE");
    println!("cargo:rerun-if-env-changed=VOUCH_RELEASE_UPDATER_PUBKEYS");
    println!("cargo:rerun-if-env-changed=VOUCH_RELEASE_UPDATE_URL");
    if env::var("POOL_RELEASE").as_deref() != Ok("1") {
        return;
    }
    let keys = env::var("VOUCH_RELEASE_UPDATER_PUBKEYS").unwrap_or_default();
    let url = env::var("VOUCH_RELEASE_UPDATE_URL").unwrap_or_default();
    assert!(!keys.trim().is_empty(), "POOL_RELEASE=1 needs VOUCH_RELEASE_UPDATER_PUBKEYS (the release updater public keys)");
    assert!(url.starts_with("https://"), "POOL_RELEASE=1 needs an https VOUCH_RELEASE_UPDATE_URL");
    let src = fs::read_to_string("src/updater.rs").unwrap_or_default();
    for k in keys.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        assert!(!src.contains(k), "a dev updater key is listed as a release key");
    }
    println!("cargo:rustc-cfg=app_release");
    println!("cargo:rustc-env=VOUCH_RELEASE_UPDATER_PUBKEYS={keys}");
    println!("cargo:rustc-env=VOUCH_RELEASE_UPDATE_URL={url}");
}

/// This binary's build time for the update policy (`update_policy.rs`): an update signed before it is an old
/// release. `SOURCE_DATE_EPOCH` (reproducible builds) wins over the clock.
fn build_time() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let t = env::var("SOURCE_DATE_EPOCH").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    });
    println!("cargo:rustc-env=APP_BUILD_UNIX_S={t}");
}

fn main() {
    build_time();
    release_channel();
    ensure_sidecar_placeholders();
    gpu_pack();
    let mut attrs = tauri_build::Attributes::new();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let ico = out.join("app-icon.ico");
        fs::copy("icons/icon.ico", &ico).expect("copy icon.ico");
        println!("cargo:rerun-if-changed=icons/icon.ico");
        attrs = attrs.windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path(ico));
    }
    tauri_build::try_build(attrs).expect("tauri build script");
}
