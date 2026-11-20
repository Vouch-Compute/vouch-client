//! Generates Rust types from `proto/node.proto` (node protocol 1.2.0) with prost and a vendored `protoc`.
//! The .proto is copied into OUT_DIR first: the repo path contains a non-ASCII character and
//! `protoc` on Windows is not reliable with such paths.
//!
//! Also generates the 1.1.0 types from `tests/data/node-1.1.0.proto` into `OUT_DIR/v110/` for the cross-version
//! tests only (a 1.1.0 peer against a 1.2.0 peer).
//!
//! Release guard: a build made with the release-signing configuration
//! (`POOL_RELEASE=1`, set by the release CI jobs and by `pool-app/scripts/sidecars.mjs` in release mode)
//! sets `cfg(pool_release)`; `lib.rs` then refuses to compile when the `dev-trust` feature is on too.
use std::{env, fs, path::{Path, PathBuf}};

fn compile(src: &Path, out: &Path, sub: &str) {
    let inc = out.join(format!("proto-src-{sub}"));
    fs::create_dir_all(&inc).unwrap();
    let dst = inc.join("node.proto");
    fs::copy(src, &dst).expect("copy node.proto");
    let gen = out.join(sub);
    fs::create_dir_all(&gen).unwrap();
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut cfg = prost_build::Config::new();
    cfg.protoc_executable(protoc);
    cfg.out_dir(&gen);
    cfg.compile_protos(&[dst], &[inc]).expect("compile node.proto");
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    let src = manifest_dir.join("../../../proto/node.proto");
    println!("cargo:rerun-if-changed={}", src.display());
    compile(&src, &out, "v120");

    let old = manifest_dir.join("tests/data/node-1.1.0.proto");
    println!("cargo:rerun-if-changed={}", old.display());
    compile(&old, &out, "v110");

    println!("cargo::rustc-check-cfg=cfg(pool_release)");
    println!("cargo:rerun-if-env-changed=POOL_RELEASE");
    if env::var("POOL_RELEASE").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=pool_release");
    }
}
