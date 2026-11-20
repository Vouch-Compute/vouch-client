//! Test fixtures shared by the runner's and pool-core's tests (feature `testkit`): one process-wide fake
//! the server (its roots are exported in `POOL_DEV_TRUST_ROOTS`), signed bundles, tiny random-weight models
//! and a minimal FLAC encoder.

use std::sync::OnceLock;

use pool_proto::objects::{ManifestFile, ModelManifest};
use pool_proto::testkit::FakeVault;
use pool_proto::{cbor, sha256};

/// The process-wide fake the server. Its two roots are installed as the dev trust roots.
pub fn vault() -> &'static FakeVault {
    static V: OnceLock<FakeVault> = OnceLock::new();
    V.get_or_init(|| {
        let v = FakeVault::new();
        // SAFETY (edition 2021: safe fn): set once, before any reader in this process.
        std::env::set_var(pool_proto::trust::DEV_ROOTS_ENV, v.roots_env());
        v
    })
}

/// Installs the dev roots (idempotent). Kept for readability at call sites.
pub fn set_dev_roots(_v: &FakeVault) {
    let _ = vault();
}

pub struct BundleFixture {
    pub vault: &'static FakeVault,
    pub dir: tempfile::TempDir,
    pub keyset: Vec<u8>,
    pub manifest: ModelManifest,
    pub manifest_cose: Vec<u8>,
    pub model_hash: [u8; 32],
}

pub fn bundle_fixture(files: &[(&str, Vec<u8>)]) -> BundleFixture {
    bundle_fixture_with(files, "candle", "safetensors", pool_proto::EMBED_BATCH_FORMAT, "test-model")
}

pub fn bundle_fixture_with(
    files: &[(&str, Vec<u8>)],
    runtime: &str,
    format: &str,
    input_format: &str,
    model_id: &str,
) -> BundleFixture {
    let v = vault();
    let dir = tempfile::tempdir().unwrap();
    let mut mf = Vec::new();
    for (path, data) in files {
        let p = dir.path().join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        mf.push(ManifestFile { path: path.to_string(), sha256: sha256(data), size: data.len() as u64 });
    }
    let manifest = ModelManifest {
        model_id: model_id.into(),
        version: "1".into(),
        source_repo: "test/tiny".into(),
        source_commit: "0000000000000000000000000000000000000000".into(),
        license: "Apache-2.0".into(),
        format: format.into(),
        runtime: runtime.into(),
        quantization: "f32".into(),
        files: mf,
        min_vram_mb: 0,
        min_ram_mb: 64,
        tolerance_class: "test".into(),
        tiers: vec!["cpu".into()],
        input_format: input_format.into(),
        issued_at: v.now(),
        approvals: vec!["approver-a".into(), "approver-b".into()],
    };
    let manifest_cose = v.sign_manifest(&manifest);
    let model_hash = sha256(&cbor::encode(&manifest.to_value()));
    BundleFixture { vault: v, dir, keyset: v.keyset_bytes(1), manifest, manifest_cose, model_hash }
}

/// Encode 16 kHz mono 16-bit PCM as a valid FLAC stream (VERBATIM subframes, 4096-sample blocks).
pub fn flac_encode(samples: &[i16]) -> Vec<u8> {
    fn crc8(data: &[u8]) -> u8 {
        let mut crc = 0u8;
        for b in data {
            crc ^= b;
            for _ in 0..8 {
                crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
            }
        }
        crc
    }
    fn crc16(data: &[u8]) -> u16 {
        let mut crc = 0u16;
        for b in data {
            crc ^= u16::from(*b) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x8005 } else { crc << 1 };
            }
        }
        crc
    }
    fn utf8_num(n: u64, out: &mut Vec<u8>) {
        if n < 0x80 {
            out.push(n as u8);
            return;
        }
        let mut bytes = Vec::new();
        let mut v = n;
        let mut count = 1;
        while v >= (1 << (6 - count)) {
            bytes.push(0x80 | (v & 0x3f) as u8);
            v >>= 6;
            count += 1;
        }
        let lead = (0xffu16 << (8 - count)) as u8 | v as u8;
        out.push(lead);
        out.extend(bytes.iter().rev());
    }
    let block = 4096usize;
    let mut out = b"fLaC".to_vec();
    out.push(0x80);
    out.extend_from_slice(&[0, 0, 34]);
    let mut si = [0u8; 34];
    si[0..2].copy_from_slice(&(block as u16).to_be_bytes());
    si[2..4].copy_from_slice(&(block as u16).to_be_bytes());
    let packed: u64 = (16_000u64 << 44) | (15u64 << 36) | samples.len() as u64;
    si[10..18].copy_from_slice(&packed.to_be_bytes());
    out.extend_from_slice(&si);
    for (i, chunk) in samples.chunks(block).enumerate() {
        let mut f = vec![0xFF, 0xF8, 0x70, 0x08]; // blocksize: 16-bit at end; rate from STREAMINFO; mono, 16-bit
        utf8_num(i as u64, &mut f);
        f.extend_from_slice(&((chunk.len() - 1) as u16).to_be_bytes());
        f.push(crc8(&f));
        f.push(0x02); // VERBATIM subframe
        for s in chunk {
            f.extend_from_slice(&s.to_be_bytes());
        }
        let c = crc16(&f);
        f.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&f);
    }
    out
}

/// A 440 Hz tone, `ms` milliseconds long, as canonical FLAC.
pub fn flac_tone(ms: usize) -> Vec<u8> {
    let n = ms * 16;
    let s: Vec<i16> =
        (0..n).map(|i| ((i as f32 * 440.0 * std::f32::consts::TAU / 16_000.0).sin() * 8000.0) as i16).collect();
    flac_encode(&s)
}

#[cfg(feature = "candle")]
fn save_varmap(vm: &candle_nn::VarMap) -> Vec<u8> {
    // a path in a fresh directory, not an open NamedTempFile: on Windows the save cannot replace a file
    // that is still held open
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("model.safetensors");
    vm.save(&p).unwrap();
    std::fs::read(&p).unwrap()
}

/// A random-weight 1-layer BERT (hidden 16) with a 30-token vocab: proves the embeddings pipeline.
#[cfg(feature = "candle")]
pub fn tiny_bert_files() -> Vec<(&'static str, Vec<u8>)> {
    use candle_core::{DType, Device};
    use candle_nn::{VarBuilder, VarMap};
    let words = [
        "[PAD]", "[UNK]", "[CLS]", "[SEP]", "the", "cat", "sat", "on", "mat", "dog", "ran", "a", "hello", "world", ",",
        ".", "!", "##s", "we", "pay", "for", "verified", "work", "only", "vouch", "embed", "this", "text", "is", "fine",
    ];
    let vocab = words.join("\n");
    let config = serde_json::json!({
        "vocab_size": words.len(), "hidden_size": 16, "num_hidden_layers": 1, "num_attention_heads": 2,
        "intermediate_size": 32, "hidden_act": "gelu", "hidden_dropout_prob": 0.0, "max_position_embeddings": 64,
        "type_vocab_size": 2, "initializer_range": 0.02, "layer_norm_eps": 1e-12, "pad_token_id": 0,
        "classifier_dropout": null, "model_type": "bert"
    });
    let cfg: candle_transformers::models::bert::Config = serde_json::from_value(config.clone()).unwrap();
    let vm = VarMap::new();
    let vb = VarBuilder::from_varmap(&vm, DType::F32, &Device::Cpu);
    candle_transformers::models::bert::BertModel::load(vb, &cfg).unwrap();
    vec![
        ("config.json", serde_json::to_vec(&config).unwrap()),
        ("vocab.txt", vocab.into_bytes()),
        ("model.safetensors", save_varmap(&vm)),
    ]
}

/// A random-weight 1-layer Whisper (d_model 16, vocab 64): proves the transcription pipeline.
#[cfg(feature = "candle")]
pub fn tiny_whisper_files() -> Vec<(&'static str, Vec<u8>)> {
    use candle_core::{DType, Device};
    use candle_nn::{VarBuilder, VarMap};
    let config = serde_json::json!({
        "num_mel_bins": 80, "max_source_positions": 1500, "d_model": 16, "encoder_attention_heads": 2,
        "encoder_layers": 1, "vocab_size": 64, "max_target_positions": 32, "decoder_attention_heads": 2,
        "decoder_layers": 1, "suppress_tokens": []
    });
    let cfg: candle_transformers::models::whisper::Config = serde_json::from_value(config.clone()).unwrap();
    let vm = VarMap::new();
    let vb = VarBuilder::from_varmap(&vm, DType::F32, &Device::Cpu);
    candle_transformers::models::whisper::model::Whisper::load(&vb, cfg).unwrap();
    let mut vocab = serde_json::Map::new();
    for i in 0..56u32 {
        let tok = if i < 26 { ((b'a' + i as u8) as char).to_string() } else { format!("Ġ{}", (b'a' + (i - 26) as u8 % 26) as char) };
        vocab.insert(tok, i.into());
    }
    let added = [
        (56, "<|endoftext|>"),
        (57, "<|startoftranscript|>"),
        (58, "<|en|>"),
        (59, "<|tr|>"),
        (60, "<|transcribe|>"),
        (61, "<|translate|>"),
        (62, "<|notimestamps|>"),
        (63, "<|nospeech|>"),
    ];
    let tokenizer = serde_json::json!({
        "model": { "type": "BPE", "vocab": vocab },
        "added_tokens": added.iter().map(|(id, c)| serde_json::json!({"id": id, "content": c, "special": true})).collect::<Vec<_>>()
    });
    vec![
        ("config.json", serde_json::to_vec(&config).unwrap()),
        ("tokenizer.json", serde_json::to_vec(&tokenizer).unwrap()),
        ("model.safetensors", save_varmap(&vm)),
    ]
}
