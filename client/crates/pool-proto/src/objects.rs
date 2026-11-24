//! Typed claim maps from `proto/signed-objects.cddl`. Every `from_value` enforces the closed key set,
//! the `type` string and field shapes. Encoding goes through `cbor::MapBuilder` (deterministic).

use ciborium::value::{Integer, Value};

use crate::cbor::{as_text, as_uint, MapBuilder, MapReader};
use crate::{object_types as t, Error};

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

fn uuid(r: &MapReader, k: &str) -> Result<String, Error> {
    let v = r.text(k)?;
    if is_uuid(&v) {
        Ok(v)
    } else {
        Err(Error::Malformed("bad uuid"))
    }
}

fn dkid(r: &MapReader, k: &str) -> Result<String, Error> {
    let v = r.text(k)?;
    let ok = v.len() == 46
        && v.starts_with("dk_")
        && v[3..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(v)
    } else {
        Err(Error::Malformed("bad device_key_id"))
    }
}

pub const INPUT_FORMATS: [&str; 2] = [crate::CANONICAL_AUDIO_FORMAT, crate::EMBED_BATCH_FORMAT];
pub const UNIT_TYPES: [&str; 3] = ["audio_sec", "token", "image"];
pub const MODEL_FORMATS: [&str; 4] = ["safetensors", "gguf", "onnx", "ct2"];

fn one_of(v: String, allowed: &[&str], what: &'static str) -> Result<String, Error> {
    if allowed.contains(&v.as_str()) {
        Ok(v)
    } else {
        Err(Error::Malformed(what))
    }
}

// ------------------------------------------------------------------ device-signed

#[derive(Debug, Clone, PartialEq)]
pub struct HelloClaims {
    pub device_id: String,
    pub device_key_id: String,
    pub nonce: [u8; 32],
    pub tls_exporter: [u8; 32],
    pub ts: u64,
}

impl HelloClaims {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::HELLO)
            .text("device_id", &self.device_id)
            .text("device_key_id", &self.device_key_id)
            .bytes("nonce", &self.nonce)
            .bytes("tls_exporter", &self.tls_exporter)
            .uint("ts", self.ts)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "device_id", "device_key_id", "nonce", "tls_exporter", "ts"], &[])?;
        r.expect_type(t::HELLO)?;
        Ok(Self {
            device_id: uuid(&r, "device_id")?,
            device_key_id: dkid(&r, "device_key_id")?,
            nonce: r.bytes_n("nonce")?,
            tls_exporter: r.bytes_n("tls_exporter")?,
            ts: r.uint("ts")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResultClaims {
    pub job_id: String,
    pub lease_id: String,
    pub model_hash: [u8; 32],
    pub input_sha256: [u8; 32],
    pub output_sha256: [u8; 32],
    pub t_start: u64,
    pub t_end: u64,
    pub units_device: Option<u64>,
}

impl ResultClaims {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::RESULT_CLAIMS)
            .text("job_id", &self.job_id)
            .text("lease_id", &self.lease_id)
            .bytes("model_hash", &self.model_hash)
            .bytes("input_sha256", &self.input_sha256)
            .bytes("output_sha256", &self.output_sha256)
            .uint("t_start", self.t_start)
            .uint("t_end", self.t_end)
            .opt_uint("units_device", self.units_device)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &["type", "job_id", "lease_id", "model_hash", "input_sha256", "output_sha256", "t_start", "t_end"],
            &["units_device"],
        )?;
        r.expect_type(t::RESULT_CLAIMS)?;
        Ok(Self {
            job_id: uuid(&r, "job_id")?,
            lease_id: uuid(&r, "lease_id")?,
            model_hash: r.bytes_n("model_hash")?,
            input_sha256: r.bytes_n("input_sha256")?,
            output_sha256: r.bytes_n("output_sha256")?,
            t_start: r.uint("t_start")?,
            t_end: r.uint("t_end")?,
            units_device: r.opt_uint("units_device")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LeaseProof {
    pub lease_id: String,
    pub method: String,
    pub path: String,
    pub body_sha256: Option<[u8; 32]>,
    pub ts: u64,
    pub nonce: [u8; 16],
}

impl LeaseProof {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::LEASE_PROOF)
            .text("lease_id", &self.lease_id)
            .text("method", &self.method)
            .text("path", &self.path)
            .opt_bytes("body_sha256", self.body_sha256.as_ref().map(|b| &b[..]))
            .uint("ts", self.ts)
            .bytes("nonce", &self.nonce)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "lease_id", "method", "path", "ts", "nonce"], &["body_sha256"])?;
        r.expect_type(t::LEASE_PROOF)?;
        let method = one_of(r.text("method")?, &["GET", "PUT"], "bad method")?;
        let body_sha256 = r.opt_bytes_n("body_sha256")?;
        if method == "PUT" && body_sha256.is_none() {
            return Err(Error::Malformed("PUT proof needs body_sha256"));
        }
        Ok(Self {
            lease_id: uuid(&r, "lease_id")?,
            method,
            path: r.text("path")?,
            body_sha256,
            ts: r.uint("ts")?,
            nonce: r.bytes_n("nonce")?,
        })
    }
}

/// Enrollment proof (cddl 1.1.0): `nonce_sig` for `POST /v1/devices` is a COSE_Sign1 over this map,
/// signed by the new device key (`kid` = its `device_key_id`). Replaces the deprecated raw-nonce payload.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrollClaims {
    pub challenge_id: String,
    pub nonce: [u8; 32],
}

impl EnrollClaims {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::ENROLL).text("challenge_id", &self.challenge_id).bytes("nonce", &self.nonce).build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "challenge_id", "nonce"], &[])?;
        r.expect_type(t::ENROLL)?;
        Ok(Self { challenge_id: uuid(&r, "challenge_id")?, nonce: r.bytes_n("nonce")? })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HwClaims {
    pub os: String,
    pub arch: String,
    pub cpu: String,
    pub ram_mb: u64,
    pub gpu: Option<String>,
    pub vram_mb: Option<u64>,
    pub driver: Option<String>,
    pub backend: Option<String>,
}

impl HwClaims {
    pub fn to_value(&self) -> Value {
        MapBuilder::default()
            .text("os", &self.os)
            .text("arch", &self.arch)
            .text("cpu", &self.cpu)
            .uint("ram_mb", self.ram_mb)
            .opt_text("gpu", self.gpu.as_deref())
            .opt_uint("vram_mb", self.vram_mb)
            .opt_text("driver", self.driver.as_deref())
            .opt_text("backend", self.backend.as_deref())
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["os", "arch", "cpu", "ram_mb"], &["gpu", "vram_mb", "driver", "backend"])?;
        Ok(Self {
            os: r.text("os")?,
            arch: r.text("arch")?,
            cpu: r.text("cpu")?,
            ram_mb: r.uint("ram_mb")?,
            gpu: r.opt_text("gpu")?,
            vram_mb: r.opt_uint("vram_mb")?,
            driver: r.opt_text("driver")?,
            backend: r.opt_text("backend")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkSegment {
    pub seq: u64,
    pub t_start: u64,
    pub t_end: u64,
    pub output_sha256: [u8; 32],
    pub units_device: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkResult {
    pub benchmark_id: String,
    pub device_key_id: String,
    pub nonce: [u8; 32],
    pub workload_sha256: [u8; 32],
    pub t_start: u64,
    pub t_end: u64,
    pub segments: Vec<BenchmarkSegment>,
    pub hw_claims: HwClaims,
}

impl BenchmarkResult {
    pub fn to_value(&self) -> Value {
        let segs = self
            .segments
            .iter()
            .map(|s| {
                MapBuilder::default()
                    .uint("seq", s.seq)
                    .uint("t_start", s.t_start)
                    .uint("t_end", s.t_end)
                    .bytes("output_sha256", &s.output_sha256)
                    .opt_uint("units_device", s.units_device)
                    .build()
            })
            .collect();
        MapBuilder::new(t::BENCHMARK_RESULT)
            .text("benchmark_id", &self.benchmark_id)
            .text("device_key_id", &self.device_key_id)
            .bytes("nonce", &self.nonce)
            .bytes("workload_sha256", &self.workload_sha256)
            .uint("t_start", self.t_start)
            .uint("t_end", self.t_end)
            .value("segments", Value::Array(segs))
            .value("hw_claims", self.hw_claims.to_value())
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &["type", "benchmark_id", "device_key_id", "nonce", "workload_sha256", "t_start", "t_end", "segments", "hw_claims"],
            &[],
        )?;
        r.expect_type(t::BENCHMARK_RESULT)?;
        let mut segments = Vec::new();
        for s in r.array("segments")? {
            let sr = MapReader::new(s, &["seq", "t_start", "t_end", "output_sha256"], &["units_device"])?;
            segments.push(BenchmarkSegment {
                seq: sr.uint("seq")?,
                t_start: sr.uint("t_start")?,
                t_end: sr.uint("t_end")?,
                output_sha256: sr.bytes_n("output_sha256")?,
                units_device: sr.opt_uint("units_device")?,
            });
        }
        if segments.is_empty() {
            return Err(Error::Malformed("segments must be non-empty"));
        }
        Ok(Self {
            benchmark_id: uuid(&r, "benchmark_id")?,
            device_key_id: dkid(&r, "device_key_id")?,
            nonce: r.bytes_n("nonce")?,
            workload_sha256: r.bytes_n("workload_sha256")?,
            t_start: r.uint("t_start")?,
            t_end: r.uint("t_end")?,
            segments,
            hw_claims: HwClaims::from_value(r.map("hw_claims")?)?,
        })
    }
}

// ------------------------------------------------------------------ server-signed

#[derive(Debug, Clone, PartialEq)]
pub struct LeaseEnvelope {
    pub job_id: String,
    pub lease_id: String,
    pub device_id: String,
    pub device_key_id: String,
    pub model_id: String,
    pub model_hash: [u8; 32],
    pub input_sha256: [u8; 32],
    pub input_format: String,
    pub input_bytes: u64,
    pub unit_type: String,
    pub issued_at: u64,
    pub deadline: u64,
    /// 1.1.0: optional BCP 47 transcription hint. Nodes must accept it; it is only a hint.
    pub language: Option<String>,
}

impl LeaseEnvelope {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::LEASE_ENVELOPE)
            .text("job_id", &self.job_id)
            .text("lease_id", &self.lease_id)
            .text("device_id", &self.device_id)
            .text("device_key_id", &self.device_key_id)
            .text("model_id", &self.model_id)
            .bytes("model_hash", &self.model_hash)
            .bytes("input_sha256", &self.input_sha256)
            .text("input_format", &self.input_format)
            .uint("input_bytes", self.input_bytes)
            .text("unit_type", &self.unit_type)
            .uint("issued_at", self.issued_at)
            .uint("deadline", self.deadline)
            .opt_text("language", self.language.as_deref())
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &[
                "type", "job_id", "lease_id", "device_id", "device_key_id", "model_id", "model_hash",
                "input_sha256", "input_format", "input_bytes", "unit_type", "issued_at", "deadline",
            ],
            &["language"],
        )?;
        r.expect_type(t::LEASE_ENVELOPE)?;
        Ok(Self {
            job_id: uuid(&r, "job_id")?,
            lease_id: uuid(&r, "lease_id")?,
            device_id: uuid(&r, "device_id")?,
            device_key_id: dkid(&r, "device_key_id")?,
            model_id: r.text("model_id")?,
            model_hash: r.bytes_n("model_hash")?,
            input_sha256: r.bytes_n("input_sha256")?,
            input_format: one_of(r.text("input_format")?, &INPUT_FORMATS, "non-canonical input_format")?,
            input_bytes: r.uint("input_bytes")?,
            unit_type: one_of(r.text("unit_type")?, &UNIT_TYPES, "bad unit_type")?,
            issued_at: r.uint("issued_at")?,
            deadline: r.uint("deadline")?,
            language: r.opt_text("language")?,
        })
    }
}

/// Sustained benchmark floor (cddl `min_duration_s: uint .ge 1200`).
pub const MIN_BENCHMARK_DURATION_S: u64 = 1200;
/// What the decoder enforces. Release builds: 1200 s. Dev builds (`dev-trust`) also accept the shorter
/// workloads a dev server signs with `VAULT_DEV_BENCHMARK_MIN_DURATION_S`; pool-core
/// additionally refuses them unless the agent runs in dev mode.
#[cfg(not(feature = "dev-trust"))]
pub const MIN_BENCHMARK_DURATION_FLOOR_S: u64 = MIN_BENCHMARK_DURATION_S;
#[cfg(feature = "dev-trust")]
pub const MIN_BENCHMARK_DURATION_FLOOR_S: u64 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkWorkload {
    pub benchmark_id: String,
    pub device_id: String,
    pub device_key_id: String,
    pub model_id: String,
    pub model_hash: [u8; 32],
    pub bundle_sha256: [u8; 32],
    pub nonce: [u8; 32],
    pub min_duration_s: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl BenchmarkWorkload {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::BENCHMARK_WORKLOAD)
            .text("benchmark_id", &self.benchmark_id)
            .text("device_id", &self.device_id)
            .text("device_key_id", &self.device_key_id)
            .text("model_id", &self.model_id)
            .bytes("model_hash", &self.model_hash)
            .bytes("bundle_sha256", &self.bundle_sha256)
            .bytes("nonce", &self.nonce)
            .uint("min_duration_s", self.min_duration_s)
            .uint("issued_at", self.issued_at)
            .uint("expires_at", self.expires_at)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &[
                "type", "benchmark_id", "device_id", "device_key_id", "model_id", "model_hash", "bundle_sha256",
                "nonce", "min_duration_s", "issued_at", "expires_at",
            ],
            &[],
        )?;
        r.expect_type(t::BENCHMARK_WORKLOAD)?;
        let min_duration_s = r.uint("min_duration_s")?;
        if min_duration_s < MIN_BENCHMARK_DURATION_FLOOR_S {
            return Err(Error::Malformed("min_duration_s must be >= 1200"));
        }
        Ok(Self {
            benchmark_id: uuid(&r, "benchmark_id")?,
            device_id: uuid(&r, "device_id")?,
            device_key_id: dkid(&r, "device_key_id")?,
            model_id: r.text("model_id")?,
            model_hash: r.bytes_n("model_hash")?,
            bundle_sha256: r.bytes_n("bundle_sha256")?,
            nonce: r.bytes_n("nonce")?,
            min_duration_s,
            issued_at: r.uint("issued_at")?,
            expires_at: r.uint("expires_at")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelManifest {
    pub model_id: String,
    pub version: String,
    pub source_repo: String,
    pub source_commit: String,
    pub license: String,
    pub format: String,
    pub runtime: String,
    pub quantization: String,
    pub files: Vec<ManifestFile>,
    pub min_vram_mb: u64,
    pub min_ram_mb: u64,
    pub tolerance_class: String,
    pub tiers: Vec<String>,
    pub input_format: String,
    pub issued_at: u64,
    pub approvals: Vec<String>,
    /// Optional signed claim (CR-T190-01, CLIENT-IMPACT 3.4.0): `Some("single_owner")` on a manifest the owner
    /// approved alone under vault's single-owner mode, which then carries exactly one approver. Two-person
    /// manifests never carry it (`None`), so their bytes are unchanged.
    pub approval_mode: Option<String>,
}

/// The only allowed value of the `approval_mode` manifest claim.
pub const APPROVAL_MODE_SINGLE_OWNER: &str = "single_owner";

/// Approval rule (CR-T190-01): without the claim, at least two distinct approvers; with
/// `approval_mode: "single_owner"`, exactly one. Any other claim value, the claim with two or more approvers, an
/// empty list or a repeated approver is malformed.
fn check_approvals(approvals: &[String], approval_mode: Option<&str>) -> Result<(), Error> {
    let mut distinct = approvals.to_vec();
    distinct.sort();
    distinct.dedup();
    if distinct.len() != approvals.len() {
        return Err(Error::Malformed("manifest approvals must be distinct"));
    }
    if approvals.iter().any(String::is_empty) {
        return Err(Error::Malformed("empty manifest approval"));
    }
    match approval_mode {
        None if approvals.len() >= 2 => Ok(()),
        None => Err(Error::Malformed("manifest needs >= 2 distinct approvals")),
        Some(APPROVAL_MODE_SINGLE_OWNER) if approvals.len() == 1 => Ok(()),
        Some(APPROVAL_MODE_SINGLE_OWNER) => Err(Error::Malformed("single_owner manifest needs exactly 1 approval")),
        Some(_) => Err(Error::Malformed("unknown approval_mode")),
    }
}

/// Most files one signed bundle may list (bounds the download and verification work).
pub const MAX_MANIFEST_FILES: usize = 1024;
/// Largest total bundle size a manifest may declare (64 GiB; also keeps every size sum far from overflow).
pub const MAX_BUNDLE_BYTES: u64 = 64 << 30;

/// Windows maps these names to devices in every directory (`model/nul.json` opens `\\.\NUL`), whatever the extension.
fn is_windows_device_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit())
}

/// A bundle file path must be a plain relative path: no traversal, no absolute paths, no drive letters, and
///  no segment that Windows would alias to another file or a device: a trailing `.` (Windows strips it, so
/// `x.pkl.` is written as `x.pkl`) or a reserved device name (`nul`, `com1.json`, ...).
pub fn is_safe_relative_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && !p.starts_with('/')
        && !p.starts_with('\\')
        && !p.contains(':')
        && !p.contains('\\')
        && p.split('/').all(|seg| {
            !seg.is_empty() && seg != "." && seg != ".." && !seg.ends_with('.') && !is_windows_device_name(seg)
        })
        && p.chars().all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
}

/// The file list must name distinct files on every OS. Two entries that differ only in case are one file on
/// Windows and macOS, and a file that is also used as a directory of another entry cannot exist; either would
/// let one verified entry be replaced by another on disk.
fn check_file_set(files: &[ManifestFile]) -> Result<(), Error> {
    if files.len() > MAX_MANIFEST_FILES {
        return Err(Error::Malformed("too many bundle files"));
    }
    let mut total: u64 = 0;
    for f in files {
        total = total.checked_add(f.size).ok_or(Error::Malformed("bundle too large"))?;
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(Error::Malformed("bundle too large"));
    }
    let mut seen = std::collections::HashSet::with_capacity(files.len());
    for f in files {
        if !seen.insert(f.path.to_ascii_lowercase()) {
            return Err(Error::Malformed("duplicate bundle file path"));
        }
    }
    for p in &seen {
        // every directory prefix ("a" and "a/b" of "a/b/c") must not also be listed as a file
        if p.match_indices('/').any(|(i, _)| seen.contains(&p[..i])) {
            return Err(Error::Malformed("bundle file path is also a directory"));
        }
    }
    Ok(())
}

/// File types that never reach a model parser (the protocol's file-type policy, the server's
/// registry): pickle, torch checkpoints, numpy/joblib, code and native libraries. `.bin` is in the list; the only
/// exception is `model.bin` in a `ct2` bundle that passes [`ct2_header_ok`].
pub const FORBIDDEN_FILE_SUFFIXES: [&str; 19] = [
    ".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib", ".npy", ".npz", ".py", ".pyc", ".so", ".dll",
    ".dylib", ".exe", ".sh", ".bat", ".ps1", ".js",
];

/// The single `.bin` exception: basename exactly `model.bin` in a manifest with `format: "ct2"`.
pub fn is_ct2_model_bin(format: &str, path: &str) -> bool {
    format == "ct2" && path.rsplit('/').next() == Some("model.bin")
}

/// Name-level policy for one bundle file of a manifest with `format`.
pub fn bundle_file_allowed(format: &str, path: &str) -> bool {
    if is_ct2_model_bin(format, path) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    !FORBIDDEN_FILE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Header check for a CTranslate2 `model.bin`: not pickle (first byte not the `0x80` PROTO opcode),
/// not a ZIP/torch archive (`PK\x03\x04`), and the first four bytes, as a little-endian uint32 binary
/// version, in `1..=16`.
pub fn ct2_header_ok(data: &[u8]) -> bool {
    if data.len() < 4 || data[0] == 0x80 || data[..4] == *b"PK\x03\x04" {
        return false;
    }
    (1..=16).contains(&u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// Content-level policy, applied after a file's SHA-256 matched the manifest and before any parser sees it.
pub fn check_bundle_file_content(format: &str, path: &str, data: &[u8]) -> Result<(), Error> {
    if !bundle_file_allowed(format, path) {
        return Err(Error::Malformed("forbidden bundle file type"));
    }
    if is_ct2_model_bin(format, path) && !ct2_header_ok(data) {
        return Err(Error::Malformed("model.bin is not a CTranslate2 binary"));
    }
    Ok(())
}

impl ModelManifest {
    pub fn to_value(&self) -> Value {
        let files = self
            .files
            .iter()
            .map(|f| {
                MapBuilder::default()
                    .text("path", &f.path)
                    .bytes("sha256", &f.sha256)
                    .uint("size", f.size)
                    .build()
            })
            .collect();
        MapBuilder::new(t::MODEL_MANIFEST)
            .text("model_id", &self.model_id)
            .text("version", &self.version)
            .value(
                "source",
                MapBuilder::default()
                    .text("repo", &self.source_repo)
                    .text("commit", &self.source_commit)
                    .build(),
            )
            .text("license", &self.license)
            .text("format", &self.format)
            .text("runtime", &self.runtime)
            .text("quantization", &self.quantization)
            .value("files", Value::Array(files))
            .uint("min_vram_mb", self.min_vram_mb)
            .uint("min_ram_mb", self.min_ram_mb)
            .text("tolerance_class", &self.tolerance_class)
            .value("tiers", Value::Array(self.tiers.iter().map(|s| Value::Text(s.clone())).collect()))
            .text("input_format", &self.input_format)
            .uint("issued_at", self.issued_at)
            .value("approvals", Value::Array(self.approvals.iter().map(|s| Value::Text(s.clone())).collect()))
            .opt_text("approval_mode", self.approval_mode.as_deref())
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &[
                "type", "model_id", "version", "source", "license", "format", "runtime", "quantization", "files",
                "min_vram_mb", "min_ram_mb", "tolerance_class", "tiers", "input_format", "issued_at", "approvals",
            ],
            &["approval_mode"],
        )?;
        r.expect_type(t::MODEL_MANIFEST)?;
        let src = MapReader::new(r.map("source")?, &["repo", "commit"], &[])?;
        let mut files = Vec::new();
        for f in r.array("files")? {
            let fr = MapReader::new(f, &["path", "sha256", "size"], &[])?;
            let path = fr.text("path")?;
            if !is_safe_relative_path(&path) {
                return Err(Error::Malformed("unsafe bundle file path"));
            }
            files.push(ManifestFile { path, sha256: fr.bytes_n("sha256")?, size: fr.uint("size")? });
        }
        if files.is_empty() {
            return Err(Error::Malformed("files must be non-empty"));
        }
        check_file_set(&files)?;
        let format = one_of(r.text("format")?, &MODEL_FORMATS, "model format not allowed")?;
        if files.iter().any(|f| !bundle_file_allowed(&format, &f.path)) {
            return Err(Error::Malformed("forbidden bundle file type"));
        }
        let tiers = r.array("tiers")?.iter().map(as_text).collect::<Result<Vec<_>, _>>()?;
        if tiers.is_empty() {
            return Err(Error::Malformed("tiers must be non-empty"));
        }
        let approvals = r.array("approvals")?.iter().map(as_text).collect::<Result<Vec<_>, _>>()?;
        let approval_mode = r.opt_text("approval_mode")?;
        check_approvals(&approvals, approval_mode.as_deref())?;
        Ok(Self {
            model_id: r.text("model_id")?,
            version: r.text("version")?,
            source_repo: src.text("repo")?,
            source_commit: src.text("commit")?,
            license: r.text("license")?,
            format,
            runtime: r.text("runtime")?,
            quantization: r.text("quantization")?,
            files,
            min_vram_mb: r.uint("min_vram_mb")?,
            min_ram_mb: r.uint("min_ram_mb")?,
            tolerance_class: r.text("tolerance_class")?,
            tiers,
            input_format: one_of(r.text("input_format")?, &INPUT_FORMATS, "non-canonical input_format")?,
            issued_at: r.uint("issued_at")?,
            approvals,
            approval_mode,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeySetEntry {
    pub kid: String,
    pub alg: i64,
    pub purpose: String,
    pub public_key: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
}

pub const KEY_PURPOSES: [&str; 5] = ["dispatch", "meter", "registry", "benchmark", "updater"];

#[derive(Debug, Clone, PartialEq)]
pub struct KeySet {
    pub version: u64,
    pub issued_at: u64,
    pub keys: Vec<KeySetEntry>,
}

impl KeySet {
    pub fn to_value(&self) -> Value {
        let keys = self
            .keys
            .iter()
            .map(|k| {
                MapBuilder::default()
                    .text("kid", &k.kid)
                    .int("alg", k.alg)
                    .text("purpose", &k.purpose)
                    .bytes("public_key", &k.public_key)
                    .uint("not_before", k.not_before)
                    .uint("not_after", k.not_after)
                    .build()
            })
            .collect();
        MapBuilder::new(t::KEY_SET)
            .uint("version", self.version)
            .uint("issued_at", self.issued_at)
            .value("keys", Value::Array(keys))
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "version", "issued_at", "keys"], &[])?;
        r.expect_type(t::KEY_SET)?;
        let mut keys = Vec::new();
        for k in r.array("keys")? {
            let kr = MapReader::new(k, &["kid", "alg", "purpose", "public_key", "not_before", "not_after"], &[])?;
            let alg = kr.int("alg")?;
            if alg != -7 && alg != -8 {
                return Err(Error::Malformed("bad alg"));
            }
            keys.push(KeySetEntry {
                kid: kr.text("kid")?,
                alg,
                purpose: one_of(kr.text("purpose")?, &KEY_PURPOSES, "bad key purpose")?,
                public_key: kr.bytes("public_key")?,
                not_before: kr.uint("not_before")?,
                not_after: kr.uint("not_after")?,
            });
        }
        if keys.is_empty() {
            return Err(Error::Malformed("keys must be non-empty"));
        }
        Ok(Self { version: r.uint("version")?, issued_at: r.uint("issued_at")?, keys })
    }
}


// ------------------------------------------------------------------ 1.2.0 device-signed objects (sent to the server only)

/// One physical NIC in [`HwIdentifiers`] (globally administered MACs only; the agent filters the rest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwNic {
    pub mac: [u8; 6],
    /// `"ethernet" | "wifi" | "other"`.
    pub kind: String,
    /// `true` when the address is the adapter's burned-in (permanent) address.
    pub permanent: bool,
    /// `**:**:**:**:xx:yy` (the last two octets, lower-case hex), computed by the agent; the server checks it.
    pub mac_display: String,
}

pub const NIC_KINDS: [&str; 3] = ["ethernet", "wifi", "other"];

/// The masked form the server expects next to every MAC: only the last two octets are shown.
pub fn mac_display(mac: &[u8; 6]) -> String {
    format!("**:**:**:**:{:02x}:{:02x}", mac[4], mac[5])
}

/// Bit 1 of the first octet: a locally administered (randomized or software-assigned) address.
pub fn mac_is_locally_administered(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// `HwIdentifiers` (cddl 1.2.0, `pool/hw-ids/v1`): signed by the device key, sent **only to the server**
/// (`POST /v1/devices` `hw_ids`, `POST /v1/devices/{id}/hw-ids`), only after the in-app `hw_identifiers` consent.
/// Raw values live in memory for the request and are never written to disk or logs (`Debug` is redacted).
#[derive(Clone, PartialEq, Eq)]
pub struct HwIdentifiers {
    pub device_id: String,
    pub ts: u64,
    pub ek_pub_sha256: Option<[u8; 32]>,
    pub gpu_uuids: Vec<String>,
    pub smbios_uuid: Option<String>,
    pub board_serial: Option<String>,
    pub disk_serial: Option<String>,
    pub os_install_id: Option<String>,
    pub nics: Vec<HwNic>,
    pub vm_indicators: Vec<String>,
}

impl std::fmt::Debug for HwIdentifiers {
    /// Never prints a raw identifier (logs and panics included): counts and the masked MACs only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HwIdentifiers")
            .field("device_id", &self.device_id)
            .field("ek", &self.ek_pub_sha256.is_some())
            .field("gpu_uuids", &self.gpu_uuids.len())
            .field("smbios_uuid", &self.smbios_uuid.is_some())
            .field("board_serial", &self.board_serial.is_some())
            .field("disk_serial", &self.disk_serial.is_some())
            .field("os_install_id", &self.os_install_id.is_some())
            .field("nics", &self.nics.iter().map(|n| n.mac_display.as_str()).collect::<Vec<_>>())
            .field("vm_indicators", &self.vm_indicators)
            .finish()
    }
}

impl HwIdentifiers {
    pub fn to_value(&self) -> Value {
        let nics = self
            .nics
            .iter()
            .map(|n| {
                MapBuilder::default()
                    .bytes("mac", &n.mac)
                    .text("kind", &n.kind)
                    .value("permanent", Value::Bool(n.permanent))
                    .text("mac_display", &n.mac_display)
                    .build()
            })
            .collect();
        MapBuilder::new(t::HW_IDS)
            .text("device_id", &self.device_id)
            .uint("ts", self.ts)
            .opt_bytes("ek_pub_sha256", self.ek_pub_sha256.as_ref().map(|b| &b[..]))
            .value("gpu_uuids", Value::Array(self.gpu_uuids.iter().map(|g| Value::Text(g.clone())).collect()))
            .opt_text("smbios_uuid", self.smbios_uuid.as_deref())
            .opt_text("board_serial", self.board_serial.as_deref())
            .opt_text("disk_serial", self.disk_serial.as_deref())
            .opt_text("os_install_id", self.os_install_id.as_deref())
            .value("nics", Value::Array(nics))
            .value("vm_indicators", Value::Array(self.vm_indicators.iter().map(|g| Value::Text(g.clone())).collect()))
            .build()
    }

    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(
            v,
            &["type", "device_id", "ts", "gpu_uuids", "nics", "vm_indicators"],
            &["ek_pub_sha256", "smbios_uuid", "board_serial", "disk_serial", "os_install_id"],
        )?;
        r.expect_type(t::HW_IDS)?;
        let texts = |k: &str| -> Result<Vec<String>, Error> { r.array(k)?.iter().map(as_text).collect() };
        let mut nics = Vec::new();
        for n in r.array("nics")? {
            let nr = MapReader::new(n, &["mac", "kind", "permanent", "mac_display"], &[])?;
            let mac: [u8; 6] = nr.bytes_n("mac")?;
            let permanent = match nr.get("permanent") {
                Some(Value::Bool(b)) => *b,
                _ => return Err(Error::Malformed("expected bool")),
            };
            let display = nr.text("mac_display")?;
            if display != mac_display(&mac) {
                return Err(Error::Malformed("mac_display does not match the MAC"));
            }
            nics.push(HwNic { mac, kind: one_of(nr.text("kind")?, &NIC_KINDS, "bad nic kind")?, permanent, mac_display: display });
        }
        Ok(Self {
            device_id: uuid(&r, "device_id")?,
            ts: r.uint("ts")?,
            ek_pub_sha256: r.opt_bytes_n("ek_pub_sha256")?,
            gpu_uuids: texts("gpu_uuids")?,
            smbios_uuid: r.opt_text("smbios_uuid")?,
            board_serial: r.opt_text("board_serial")?,
            disk_serial: r.opt_text("disk_serial")?,
            os_install_id: r.opt_text("os_install_id")?,
            nics,
            vm_indicators: texts("vm_indicators")?,
        })
    }
}

pub const DEVICE_CONTROL_ACTIONS: [&str; 3] = ["pause", "resume", "self_revoke"];

/// `DeviceControl` (cddl 1.2.0, `pool/device-control/v1`): the app's pause / resume / "Remove this device",
/// signed by the device's current key and sent to `POST /v1/devices/{id}/control`. `ts` within ±60 s at the server,
/// `nonce` single use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceControl {
    pub device_id: String,
    pub action: String,
    pub ts: u64,
    pub nonce: [u8; 16],
}

impl DeviceControl {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::DEVICE_CONTROL)
            .text("device_id", &self.device_id)
            .text("action", &self.action)
            .uint("ts", self.ts)
            .bytes("nonce", &self.nonce)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "device_id", "action", "ts", "nonce"], &[])?;
        r.expect_type(t::DEVICE_CONTROL)?;
        Ok(Self {
            device_id: uuid(&r, "device_id")?,
            action: one_of(r.text("action")?, &DEVICE_CONTROL_ACTIONS, "bad action")?,
            ts: r.uint("ts")?,
            nonce: r.bytes_n("nonce")?,
        })
    }
}

/// `RecoveryProof` (cddl 1.2.0, `pool/recovery/v1`): the desktop app's signature for an account recovery case
/// (`POST /v1/auth/recovery-cases/{case_id}/device-proof`). Made only when the user starts "Recover my account".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProof {
    pub case_id: String,
    pub account_id: String,
    pub challenge: [u8; 32],
    pub ts: u64,
}

impl RecoveryProof {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::RECOVERY)
            .text("case_id", &self.case_id)
            .text("account_id", &self.account_id)
            .bytes("challenge", &self.challenge)
            .uint("ts", self.ts)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "case_id", "account_id", "challenge", "ts"], &[])?;
        r.expect_type(t::RECOVERY)?;
        Ok(Self { case_id: uuid(&r, "case_id")?, account_id: uuid(&r, "account_id")?, challenge: r.bytes_n("challenge")?, ts: r.uint("ts")? })
    }
}

/// `old_key_sig` / `new_key_sig` payload of `POST /v1/devices/{id}/key-rotations`:
/// both keys sign the same map, so the old key vouches for the new one and the tier is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationClaims {
    pub device_id: String,
    pub old_device_key_id: String,
    pub new_device_key_id: String,
}

impl KeyRotationClaims {
    pub fn to_value(&self) -> Value {
        MapBuilder::new(t::KEY_ROTATION)
            .text("device_id", &self.device_id)
            .text("old_device_key_id", &self.old_device_key_id)
            .text("new_device_key_id", &self.new_device_key_id)
            .build()
    }
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let r = MapReader::new(v, &["type", "device_id", "old_device_key_id", "new_device_key_id"], &[])?;
        r.expect_type(t::KEY_ROTATION)?;
        Ok(Self {
            device_id: uuid(&r, "device_id")?,
            old_device_key_id: dkid(&r, "old_device_key_id")?,
            new_device_key_id: dkid(&r, "new_device_key_id")?,
        })
    }
}

// silence "unused" for helpers only used in some cfgs
#[allow(dead_code)]
fn _int(v: i64) -> Value {
    Value::Integer(Integer::from(v))
}
#[allow(dead_code)]
fn _uint(v: &Value) -> Result<u64, Error> {
    as_uint(v)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn uuid4() -> String {
        let mut b = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }

    pub fn manifest() -> ModelManifest {
        ModelManifest {
            model_id: "minilm-l6".into(),
            version: "1".into(),
            source_repo: "sentence-transformers/all-MiniLM-L6-v2".into(),
            source_commit: "c9745ed1d9f207416be6d2e6f8de32d1f16199bf".into(),
            license: "Apache-2.0".into(),
            format: "safetensors".into(),
            runtime: "candle".into(),
            quantization: "f32".into(),
            files: vec![ManifestFile { path: "model.safetensors".into(), sha256: [1; 32], size: 10 }],
            min_vram_mb: 0,
            min_ram_mb: 512,
            tolerance_class: "cosine-0.999".into(),
            tiers: vec!["cpu".into()],
            input_format: crate::EMBED_BATCH_FORMAT.into(),
            issued_at: 1,
            approvals: vec!["alice".into(), "bob".into()],
            approval_mode: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::cbor;

    #[test]
    fn manifest_roundtrip_and_rules() {
        let m = manifest();
        let v = cbor::decode_deterministic(&cbor::encode(&m.to_value())).unwrap();
        assert_eq!(ModelManifest::from_value(&v).unwrap(), m);

        let mut bad = manifest();
        bad.format = "pickle".into();
        assert!(ModelManifest::from_value(&bad.to_value()).is_err());
        let mut bad = manifest();
        bad.approvals = vec!["alice".into(), "alice".into()];
        assert!(ModelManifest::from_value(&bad.to_value()).is_err());
        let mut bad = manifest();
        bad.files[0].path = "../../etc/passwd".into();
        assert!(ModelManifest::from_value(&bad.to_value()).is_err());
        let mut bad = manifest();
        bad.input_format = "audio/mpeg".into();
        assert!(ModelManifest::from_value(&bad.to_value()).is_err());
    }

    /// CLIENT-IMPACT 3.4.0 / CR-T190-01: one approver only with the signed claim `approval_mode: "single_owner"`.
    #[test]
    fn single_owner_manifests() {
        let enc = |m: &ModelManifest| cbor::decode_deterministic(&cbor::encode(&m.to_value())).unwrap();
        // two-person manifests carry no claim: same bytes as before the claim existed
        let two = manifest();
        assert!(!cbor::encode(&two.to_value()).windows(13).any(|w| w == b"approval_mode"));
        assert_eq!(ModelManifest::from_value(&enc(&two)).unwrap().approval_mode, None);

        let mut one = manifest();
        one.approvals = vec!["owner".into()];
        one.approval_mode = Some(APPROVAL_MODE_SINGLE_OWNER.into());
        assert_eq!(ModelManifest::from_value(&enc(&one)).unwrap(), one);

        let cases: [(&[&str], Option<&str>); 10] = [
            (&[""], Some("single_owner")),                       // empty approver name
            (&["alice", ""], None),
            (&["owner"], None),                                  // one approver without the claim
            (&[], Some("single_owner")),                         // claim without an approver
            (&["alice", "bob"], Some("single_owner")),           // claim with two approvers
            (&["owner", "owner"], Some("single_owner")),         // claim with a repeated approver
            (&["owner"], Some("Single_Owner")),                  // any other value
            (&["owner"], Some("")),
            (&["alice", "bob"], Some("two_person")),
            (&["alice", "alice"], None),                         // repeated approver, no claim
        ];
        for (approvals, mode) in cases {
            let mut bad = manifest();
            bad.approvals = approvals.iter().map(|s| s.to_string()).collect();
            bad.approval_mode = mode.map(str::to_string);
            assert!(ModelManifest::from_value(&enc(&bad)).is_err(), "{approvals:?} {mode:?}");
        }
        // the claim must be text
        let Value::Map(mut entries) = one.to_value() else { unreachable!() };
        for (k, v) in entries.iter_mut() {
            if *k == Value::Text("approval_mode".into()) {
                *v = Value::Integer(1.into());
            }
        }
        assert!(ModelManifest::from_value(&Value::Map(entries)).is_err());
    }

    #[test]
    fn safe_paths() {
        assert!(is_safe_relative_path("model.safetensors"));
        assert!(is_safe_relative_path("tok/vocab.txt"));
        for p in ["", "/abs", "a/../b", "./a", "C:/x", "a\\b", "a//b", "x?y"] {
            assert!(!is_safe_relative_path(p), "{p}");
        }
        // Names Windows aliases to another file or to a device
        for p in ["x.pkl.", "model.", "nul", "NUL.json", "tok/con", "com1.txt", "LPT9", "aux.safetensors", "a/prn/b"] {
            assert!(!is_safe_relative_path(p), "{p}");
        }
        for p in ["console.json", "com10.txt", "nullable.json", "auxiliary/x.onnx", "a.b.c"] {
            assert!(is_safe_relative_path(p), "{p}");
        }
    }

    /// A manifest's files must be distinct on every OS and bounded in number and size.
    #[test]
    fn manifest_file_set_rules() {
        let with = |files: Vec<(&str, u64)>| {
            let mut m = manifest();
            m.files = files.into_iter().map(|(p, size)| ManifestFile { path: p.into(), sha256: [1; 32], size }).collect();
            ModelManifest::from_value(&m.to_value())
        };
        assert!(with(vec![("a.safetensors", 1), ("tok/vocab.txt", 2)]).is_ok());
        // one file on Windows/macOS, two entries with different hashes in the manifest
        assert!(with(vec![("model.safetensors", 1), ("Model.safetensors", 1)]).is_err());
        assert!(with(vec![("a.json", 1), ("a.json", 1)]).is_err());
        // a file that is also a directory of another entry, whatever sorts between them
        assert!(with(vec![("a", 1), ("a-b", 1), ("a/b", 1)]).is_err());
        assert!(with(vec![("x/y/z.json", 1), ("X/y", 1)]).is_err());
        // size overflow and the total cap
        assert!(with(vec![("a.json", u64::MAX), ("b.json", 2)]).is_err());
        assert!(with(vec![("a.json", MAX_BUNDLE_BYTES + 1)]).is_err());
        assert!(with(vec![("a.json", MAX_BUNDLE_BYTES)]).is_ok());
        let many: Vec<(String, u64)> = (0..=MAX_MANIFEST_FILES).map(|i| (format!("f{i}.json"), 1)).collect();
        assert!(with(many.iter().map(|(p, s)| (p.as_str(), *s)).collect()).is_err());
    }

    #[test]
    fn workload_min_duration_enforced() {
        let w = BenchmarkWorkload {
            benchmark_id: uuid4(),
            device_id: uuid4(),
            device_key_id: format!("dk_{}", "A".repeat(43)),
            model_id: "m".into(),
            model_hash: [0; 32],
            bundle_sha256: [0; 32],
            nonce: [0; 32],
            min_duration_s: 1199,
            issued_at: 0,
            expires_at: 1,
        };
        // release builds refuse anything under 1200 s; dev-trust builds accept a dev the server's short workloads
        assert_eq!(BenchmarkWorkload::from_value(&w.to_value()).is_err(), !cfg!(feature = "dev-trust"));
        let zero = BenchmarkWorkload { min_duration_s: 0, ..w.clone() };
        assert!(BenchmarkWorkload::from_value(&zero.to_value()).is_err());
        let ok = BenchmarkWorkload { min_duration_s: 1200, ..w };
        assert_eq!(BenchmarkWorkload::from_value(&ok.to_value()).unwrap(), ok);
    }

    #[test]
    fn lease_proof_put_requires_body_hash() {
        let p = LeaseProof {
            lease_id: uuid4(),
            method: "PUT".into(),
            path: "/x".into(),
            body_sha256: None,
            ts: 1,
            nonce: [0; 16],
        };
        assert!(LeaseProof::from_value(&p.to_value()).is_err());
        let p = LeaseProof { body_sha256: Some([2; 32]), ..p };
        assert_eq!(LeaseProof::from_value(&p.to_value()).unwrap(), p);
    }

    #[test]
    fn envelope_rejects_non_canonical_format() {
        let e = LeaseEnvelope {
            job_id: uuid4(),
            lease_id: uuid4(),
            device_id: uuid4(),
            device_key_id: format!("dk_{}", "B".repeat(43)),
            model_id: "m".into(),
            model_hash: [0; 32],
            input_sha256: [0; 32],
            input_format: "audio/wav".into(),
            input_bytes: 1,
            unit_type: "audio_sec".into(),
            issued_at: 0,
            deadline: 1,
            language: None,
        };
        assert!(LeaseEnvelope::from_value(&e.to_value()).is_err());
        let e = LeaseEnvelope { input_format: crate::CANONICAL_AUDIO_FORMAT.into(), ..e };
        assert_eq!(LeaseEnvelope::from_value(&e.to_value()).unwrap(), e);
    }

    fn envelope() -> LeaseEnvelope {
        LeaseEnvelope {
            job_id: uuid4(),
            lease_id: uuid4(),
            device_id: uuid4(),
            device_key_id: format!("dk_{}", "C".repeat(43)),
            model_id: "whisper-tiny".into(),
            model_hash: [1; 32],
            input_sha256: [2; 32],
            input_format: crate::CANONICAL_AUDIO_FORMAT.into(),
            input_bytes: 10,
            unit_type: "audio_sec".into(),
            issued_at: 0,
            deadline: 1,
            language: None,
        }
    }

    #[test]
    fn envelope_accepts_optional_language_1_1_0() {
        // `language` is an optional key; a 1.0.0 envelope without it still parses
        let plain = envelope();
        let v = cbor::decode_deterministic(&cbor::encode(&plain.to_value())).unwrap();
        assert_eq!(LeaseEnvelope::from_value(&v).unwrap().language, None);
        let tr = LeaseEnvelope { language: Some("tr".into()), ..envelope() };
        let v = cbor::decode_deterministic(&cbor::encode(&tr.to_value())).unwrap();
        assert_eq!(LeaseEnvelope::from_value(&v).unwrap(), tr);
        // still a closed map: any other extra key is refused
        let Value::Map(mut entries) = tr.to_value() else { panic!() };
        entries.push((Value::Text("dialect".into()), Value::Text("x".into())));
        assert!(LeaseEnvelope::from_value(&Value::Map(entries)).is_err());
        // language must be text
        let Value::Map(mut entries) = envelope().to_value() else { panic!() };
        entries.push((Value::Text("language".into()), Value::Integer(7.into())));
        assert!(LeaseEnvelope::from_value(&Value::Map(entries)).is_err());
    }

    #[test]
    fn enroll_claims_roundtrip_and_closed() {
        let c = EnrollClaims { challenge_id: uuid4(), nonce: [9; 32] };
        let bytes = cbor::encode(&c.to_value());
        let v = cbor::decode_deterministic(&bytes).unwrap();
        assert_eq!(EnrollClaims::from_value(&v).unwrap(), c);
        // exactly {type, challenge_id, nonce}, deterministic key order
        let Value::Map(entries) = &v else { panic!() };
        let keys: Vec<_> = entries.iter().map(|(k, _)| k.as_text().unwrap().to_string()).collect();
        assert_eq!(keys, ["type", "nonce", "challenge_id"]);
        let bad = MapBuilder::new(t::ENROLL).text("challenge_id", "not-a-uuid").bytes("nonce", &[0; 32]).build();
        assert!(EnrollClaims::from_value(&bad).is_err());
        let short = MapBuilder::new(t::ENROLL).text("challenge_id", &uuid4()).bytes("nonce", &[0; 16]).build();
        assert!(EnrollClaims::from_value(&short).is_err());
        let wrong_type = MapBuilder::new(t::HELLO).text("challenge_id", &uuid4()).bytes("nonce", &[0; 32]).build();
        assert!(EnrollClaims::from_value(&wrong_type).is_err());
    }

    #[test]
    fn bundle_file_policy_and_ct2_model_bin() {
        // names
        assert!(bundle_file_allowed("safetensors", "model.safetensors"));
        assert!(bundle_file_allowed("ct2", "model.bin"));
        assert!(bundle_file_allowed("ct2", "sub/model.bin"));
        for (fmt, p) in [
            ("safetensors", "model.bin"),
            ("ct2", "other.bin"),
            ("ct2", "model.BIN"),
            ("ct2", "xmodel.bin"),
            ("gguf", "weights.pt"),
            ("onnx", "pytorch_model.PTH"),
            ("ct2", "data.pkl"),
            ("ct2", "hook.py"),
            ("onnx", "custom_op.dll"),
        ] {
            assert!(!bundle_file_allowed(fmt, p), "{fmt} {p}");
        }
        // a manifest listing a forbidden file is refused outright
        let mut m = manifest();
        m.files[0].path = "pytorch_model.bin".into();
        assert!(ModelManifest::from_value(&m.to_value()).is_err());
        let mut m = manifest();
        m.format = "ct2".into();
        m.files[0].path = "model.bin".into();
        assert_eq!(ModelManifest::from_value(&m.to_value()).unwrap(), m);

        // CTranslate2 header
        let mut good = 6u32.to_le_bytes().to_vec();
        good.extend_from_slice(&[0xAB; 32]);
        assert!(ct2_header_ok(&good));
        assert!(ct2_header_ok(&1u32.to_le_bytes()));
        assert!(ct2_header_ok(&16u32.to_le_bytes()));
        assert!(!ct2_header_ok(&0u32.to_le_bytes()));
        assert!(!ct2_header_ok(&17u32.to_le_bytes()));
        assert!(!ct2_header_ok(&[6, 0, 0]));
        assert!(!ct2_header_ok(b"\x80\x02}q\x00(X")); // pickle protocol 2
        assert!(!ct2_header_ok(b"PK\x03\x04\x14\x00\x00\x00")); // torch.save zip
        assert!(check_bundle_file_content("ct2", "model.bin", &good).is_ok());
        assert!(check_bundle_file_content("ct2", "model.bin", b"\x80\x04\x95\x00").is_err());
        assert!(check_bundle_file_content("safetensors", "model.bin", &good).is_err());
        assert!(check_bundle_file_content("ct2", "config.json", b"{}").is_ok());
    }

    #[test]
    fn m9_device_objects_are_exact_closed_maps() {
        let id = uuid4();
        // DeviceControl: exactly {type, device_id, action, ts, nonce}, deterministic, unknown action refused
        let dc = DeviceControl { device_id: id.clone(), action: "pause".into(), ts: 1_700_000_000_000, nonce: [9; 16] };
        let bytes = cbor::encode(&dc.to_value());
        let v = cbor::decode_deterministic(&bytes).unwrap();
        assert_eq!(DeviceControl::from_value(&v).unwrap(), dc);
        let Value::Map(m) = &v else { panic!() };
        let keys: Vec<_> = m.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["ts", "type", "nonce", "action", "device_id"]);
        let bad = MapBuilder::new(t::DEVICE_CONTROL).text("device_id", &id).text("action", "delete").uint("ts", 1).bytes("nonce", &[0; 16]).build();
        assert!(DeviceControl::from_value(&bad).is_err());
        let extra =
            MapBuilder::new(t::DEVICE_CONTROL).text("device_id", &id).text("action", "pause").uint("ts", 1).bytes("nonce", &[0; 16]).uint("x", 1).build();
        assert!(DeviceControl::from_value(&extra).is_err());
        // RecoveryProof
        let rp = RecoveryProof { case_id: uuid4(), account_id: uuid4(), challenge: [3; 32], ts: 5 };
        assert_eq!(RecoveryProof::from_value(&rp.to_value()).unwrap(), rp);
        // KeyRotationClaims
        let k1 = crate::keys::device_key_id(&crate::keys::SoftwareKey::generate().verifying_key());
        let k2 = crate::keys::device_key_id(&crate::keys::SoftwareKey::generate().verifying_key());
        let kr = KeyRotationClaims { device_id: id.clone(), old_device_key_id: k1, new_device_key_id: k2 };
        assert_eq!(KeyRotationClaims::from_value(&kr.to_value()).unwrap(), kr);
    }

    #[test]
    fn hw_identifiers_roundtrip_mask_and_redacted_debug() {
        let mac = [0x00, 0x1b, 0x21, 0xaa, 0x3f, 0x9a];
        let h = HwIdentifiers {
            device_id: uuid4(),
            ts: 7,
            ek_pub_sha256: Some([1; 32]),
            gpu_uuids: vec!["GPU-SENTINEL".into()],
            smbios_uuid: Some("SMBIOS-SENTINEL".into()),
            board_serial: None,
            disk_serial: Some("DISK-SENTINEL".into()),
            os_install_id: None,
            nics: vec![HwNic { mac, kind: "ethernet".into(), permanent: true, mac_display: mac_display(&mac) }],
            vm_indicators: vec![],
        };
        assert_eq!(h.nics[0].mac_display, "**:**:**:**:3f:9a");
        let v = cbor::decode_deterministic(&cbor::encode(&h.to_value())).unwrap();
        assert_eq!(HwIdentifiers::from_value(&v).unwrap(), h);
        // a display that does not match the MAC is refused (the server checks the same)
        let mut wrong = h.clone();
        wrong.nics[0].mac_display = "**:**:**:**:00:00".into();
        assert!(HwIdentifiers::from_value(&wrong.to_value()).is_err());
        // Debug never shows a raw value
        let dbg = format!("{h:?}");
        for raw in ["SENTINEL", "1b:21", "001b21"] {
            assert!(!dbg.contains(raw), "{dbg}");
        }
        assert!(mac_is_locally_administered(&[0x02, 0, 0, 0, 0, 1]) && !mac_is_locally_administered(&mac));
    }
}
