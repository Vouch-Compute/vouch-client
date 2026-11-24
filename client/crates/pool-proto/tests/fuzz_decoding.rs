//! Fuzzing of everything the node decodes from the network or from disk (property tests; the same inputs are
//! fed to the libFuzzer targets in `client/fuzz`).
//!
//! Properties:
//! 1. **No panic, no abort, bounded work** on arbitrary bytes for: protobuf frames (`Inbound::decode`),
//!    deterministic CBOR, the COSE_Sign1 envelope, every typed claims map, KeySet verification, manifest,
//!    lease envelope and benchmark workload verification, key and base64 parsing.
//! 2. **Tampering is always rejected:** any change to a validly signed KeySet, ModelManifest, LeaseEnvelope or
//!    BenchmarkWorkload (bit flips, truncation, insertion, deletion, appended bytes, combinations) fails
//!    verification.
//! 3. **Determinism:** encode/decode of random claim trees is the identity on canonical values, and every
//!    non-canonical re-encoding is refused.
//! 4. **Frame sequencing:** a frame is accepted iff its seq is exactly the next one.
//!
//! Case counts: `PROPTEST_CASES` overrides the defaults below (CI runs the defaults; a deep run uses 20000).

use pool_proto::cbor::{self, Value};
use pool_proto::cose::{self, Es256Signer};
use pool_proto::frame::Inbound;
use pool_proto::objects::*;
use pool_proto::pb;
use pool_proto::testkit::FakeVault;
use pool_proto::{keys, object_types as ot, trust};
use proptest::prelude::*;
use prost::Message as _;

fn cases(default: u32) -> ProptestConfig {
    let n = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default);
    ProptestConfig { cases: n, failure_persistence: None, ..ProptestConfig::default() }
}

const ALL_TYPES: [&str; 13] = [
    ot::HELLO,
    ot::LEASE_ENVELOPE,
    ot::RESULT_CLAIMS,
    ot::LEASE_PROOF,
    ot::BENCHMARK_WORKLOAD,
    ot::BENCHMARK_RESULT,
    ot::MODEL_MANIFEST,
    ot::KEY_SET,
    ot::ENROLL,
    ot::HW_IDS,
    ot::DEVICE_CONTROL,
    ot::RECOVERY,
    ot::KEY_ROTATION,
];

/// Every typed decoder, on one claims value. Results are ignored: only panics matter here.
fn decode_all_claims(v: &Value) {
    let _ = HelloClaims::from_value(v);
    let _ = ResultClaims::from_value(v);
    let _ = LeaseProof::from_value(v);
    let _ = EnrollClaims::from_value(v);
    let _ = HwClaims::from_value(v);
    let _ = BenchmarkResult::from_value(v);
    let _ = LeaseEnvelope::from_value(v);
    let _ = BenchmarkWorkload::from_value(v);
    let _ = ModelManifest::from_value(v);
    let _ = KeySet::from_value(v);
    let _ = HwIdentifiers::from_value(v);
    let _ = DeviceControl::from_value(v);
    let _ = RecoveryProof::from_value(v);
    let _ = KeyRotationClaims::from_value(v);
}

struct World {
    vault: FakeVault,
    keyset: Vec<u8>,
    manifest: Vec<u8>,
    envelope: Vec<u8>,
    workload: Vec<u8>,
}

fn world() -> &'static World {
    static W: std::sync::OnceLock<World> = std::sync::OnceLock::new();
    W.get_or_init(|| {
        let vault = FakeVault::new();
        let keyset = vault.keyset_bytes(4);
        let manifest = vault.sign_manifest(&fixture_manifest());
        let envelope = vault.sign_envelope(&fixture_envelope());
        let workload = vault.sign_workload(&BenchmarkWorkload {
            benchmark_id: "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
            device_id: "1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
            device_key_id: format!("dk_{}", "A".repeat(43)),
            model_id: "m".into(),
            model_hash: [3; 32],
            bundle_sha256: [4; 32],
            nonce: [5; 32],
            min_duration_s: 1200,
            issued_at: 1,
            expires_at: u64::MAX / 2,
        });
        World { vault, keyset, manifest, envelope, workload }
    })
}

fn fixture_manifest() -> ModelManifest {
    ModelManifest {
        model_id: "minilm-l6".into(),
        version: "1".into(),
        source_repo: "r".into(),
        source_commit: "c".into(),
        license: "Apache-2.0".into(),
        format: "safetensors".into(),
        runtime: "candle".into(),
        quantization: "f32".into(),
        files: vec![
            ManifestFile { path: "model.safetensors".into(), sha256: [1; 32], size: 10 },
            ManifestFile { path: "tok/vocab.txt".into(), sha256: [2; 32], size: 3 },
        ],
        min_vram_mb: 0,
        min_ram_mb: 512,
        tolerance_class: "cosine-0.999".into(),
        tiers: vec!["cpu".into()],
        input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
        issued_at: 1,
        approvals: vec!["alice".into(), "bob".into()],
        approval_mode: None,
    }
}

fn fixture_envelope() -> LeaseEnvelope {
    LeaseEnvelope {
        job_id: "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
        lease_id: "1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
        device_id: "2b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into(),
        device_key_id: format!("dk_{}", "B".repeat(43)),
        model_id: "minilm-l6".into(),
        model_hash: [7; 32],
        input_sha256: [8; 32],
        input_format: pool_proto::EMBED_BATCH_FORMAT.into(),
        input_bytes: 30,
        unit_type: "token".into(),
        issued_at: 1,
        deadline: u64::MAX / 2,
        language: Some("en".into()),
    }
}

/// Verify one signed object of each kind the way the node does; `Ok` only if the chain and the claims are valid.
fn verify_keyset(bytes: &[u8]) -> bool {
    trust::verify_keyset(bytes, &world().vault.roots(), 0).is_ok()
}
fn trusted() -> trust::TrustedKeySet {
    trust::verify_keyset(&world().keyset, &world().vault.roots(), 0).unwrap()
}
fn verify_manifest(bytes: &[u8]) -> bool {
    trusted().verify_manifest(bytes, 1000).is_ok()
}
fn verify_envelope(bytes: &[u8]) -> bool {
    trusted().verify_lease_envelope(bytes, 1000).is_ok()
}
fn verify_workload(bytes: &[u8]) -> bool {
    trusted().verify_benchmark_workload(bytes, 1000).is_ok()
}

type Verify = fn(&[u8]) -> bool;

#[derive(Debug, Clone)]
enum Mutation {
    Flip { at: usize, bit: u8 },
    Set { at: usize, byte: u8 },
    Truncate { len: usize },
    Insert { at: usize, byte: u8 },
    Delete { at: usize },
    Append(Vec<u8>),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => (any::<usize>(), 0u8..8).prop_map(|(at, bit)| Mutation::Flip { at, bit }),
        2 => (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Set { at, byte }),
        1 => any::<usize>().prop_map(|len| Mutation::Truncate { len }),
        1 => (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Insert { at, byte }),
        1 => any::<usize>().prop_map(|at| Mutation::Delete { at }),
        1 => proptest::collection::vec(any::<u8>(), 1..8).prop_map(Mutation::Append),
    ]
}

fn apply(orig: &[u8], muts: &[Mutation]) -> Vec<u8> {
    let mut b = orig.to_vec();
    for m in muts {
        let n = b.len().max(1);
        match m {
            Mutation::Flip { at, bit } if !b.is_empty() => b[at % n] ^= 1 << bit,
            Mutation::Set { at, byte } if !b.is_empty() => b[at % n] = *byte,
            Mutation::Truncate { len } => b.truncate(len % n),
            Mutation::Insert { at, byte } => b.insert(at % (b.len() + 1), *byte),
            Mutation::Delete { at } if !b.is_empty() => {
                b.remove(at % n);
            }
            Mutation::Append(extra) => b.extend_from_slice(extra),
            _ => {}
        }
    }
    b
}

proptest! {
    #![proptest_config(cases(4096))]

    /// Property 1 on raw bytes (frames, CBOR, COSE, every claims decoder, keys, base64).
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Inbound::new().decode(&bytes);
        let _ = pb::ServerMessage::decode(&bytes[..]);
        let _ = pb::NodeMessage::decode(&bytes[..]);
        let _ = cbor::decode_any(&bytes);
        if let Ok(v) = cbor::decode_deterministic(&bytes) {
            decode_all_claims(&v);
        }
        for ty in ALL_TYPES {
            if let Ok(s) = cose::parse_sign1(&bytes, ty) {
                decode_all_claims(&s.claims);
                prop_assert!(s.verify(&world().vault.registry.verifying_key()).is_err(), "random bytes verified");
            }
        }
        prop_assert!(!verify_keyset(&bytes));
        prop_assert!(!verify_manifest(&bytes));
        prop_assert!(!verify_envelope(&bytes));
        prop_assert!(!verify_workload(&bytes));
        let _ = keys::parse_spki(&bytes);
        let _ = keys::from_sec1(&bytes);
        let _ = keys::b64_decode(&String::from_utf8_lossy(&bytes));
        let _ = check_bundle_file_content("ct2", "model.bin", &bytes);
    }

    /// Property 1 on structurally valid COSE_Sign1 envelopes around arbitrary CBOR claims (reaches the typed
    /// decoders far more often than raw bytes do).
    #[test]
    fn arbitrary_claims_in_a_valid_envelope_never_panic(claims in claims_tree(), ty in 0usize..ALL_TYPES.len()) {
        let mut v = claims;
        if let Value::Map(m) = &mut v {
            m.retain(|(k, _)| k.as_text() != Some("type"));
            m.push((Value::Text("type".into()), Value::Text(ALL_TYPES[ty].into())));
        }
        decode_all_claims(&v);
        let signed = cose::sign1(&v, &world().vault.registry).unwrap();
        if let Ok(s) = cose::parse_sign1(&signed, ALL_TYPES[ty]) {
            decode_all_claims(&s.claims);
        }
        // a registry-signed object of the wrong type or with wrong claims never passes as a manifest
        let accepted = trusted().verify_manifest(&signed, 1000);
        if let Ok((m, _)) = accepted {
            prop_assert!(ModelManifest::from_value(&m.to_value()).is_ok());
        }
    }

    /// Property 2: any tampering with a signed object is rejected.
    #[test]
    fn tampered_signed_objects_are_rejected(which in 0usize..4, muts in proptest::collection::vec(mutation(), 1..4)) {
        let w = world();
        let (orig, verify): (&[u8], Verify) = match which {
            0 => (&w.keyset, verify_keyset),
            1 => (&w.manifest, verify_manifest),
            2 => (&w.envelope, verify_envelope),
            _ => (&w.workload, verify_workload),
        };
        prop_assert!(verify(orig), "fixture must verify");
        let t = apply(orig, &muts);
        if t != orig {
            prop_assert!(!verify(&t), "tampered object accepted: {:?}", muts);
        }
    }

    /// Property 3: canonical encoding round-trips; any re-encoding with an unsorted map is refused.
    #[test]
    fn deterministic_cbor_roundtrip(v in claims_tree()) {
        let enc = cbor::encode(&v);
        let dec = cbor::decode_deterministic(&enc);
        if has_dup_keys(&v) {
            prop_assert!(dec.is_err());
        } else {
            let dec = dec.unwrap();
            prop_assert_eq!(cbor::encode(&dec), enc.clone());
            prop_assert_eq!(dec, cbor::canonicalize(&v));
            // the raw (unsorted) encoding is accepted only if it already was canonical
            let mut raw = Vec::new();
            ciborium::into_writer(&v, &mut raw).unwrap();
            prop_assert_eq!(cbor::decode_deterministic(&raw).is_ok(), raw == enc);
        }
    }

    /// Property 4: a frame is accepted iff seq is exactly the next one.
    #[test]
    fn frame_sequencing(seqs in proptest::collection::vec(0u64..8, 1..24)) {
        let mut inb = Inbound::new();
        let mut expected = 1u64;
        for s in seqs {
            let f = pb::ServerMessage { seq: s, body: Some(pb::server_message::Body::AccountNotice(pb::AccountNotice { kind: 3 })) }.encode_to_vec();
            let r = inb.decode(&f);
            if s == expected {
                prop_assert!(r.is_ok());
                expected += 1;
            } else {
                prop_assert!(r.is_err());
                // a refused frame ends the session; the decoder state is irrelevant after that
                break;
            }
        }
    }

    /// Valid ServerMessages of every kind with random contents round-trip through the node's decoder.
    #[test]
    fn server_messages_roundtrip(nonce in proptest::collection::vec(any::<u8>(), 0..64), text in ".{0,40}", n in any::<i64>(), k in any::<i32>()) {
        let bodies = vec![
            pb::server_message::Body::Challenge(pb::Challenge { nonce: nonce.clone(), server_time_ms: n, protocol_version: text.clone() }),
            pb::server_message::Body::Offer(pb::Offer { job_id: text.clone(), model_id: text.clone(), model_hash: nonce.clone(), est_units: n as u64, deadline_ms: n }),
            pb::server_message::Body::LeaseGrant(pb::LeaseGrant { job_id: text.clone(), lease_id: text.clone(), lease_envelope: nonce.clone(), input_url: text.clone(), output_url: text.clone(), lease_deadline_ms: n }),
            pb::server_message::Body::AccountNotice(pb::AccountNotice { kind: k }),
            pb::server_message::Body::Goodbye(pb::Goodbye { reason: k, reconnect_after_s: k as u32 }),
        ];
        let mut inb = Inbound::new();
        for (i, b) in bodies.into_iter().enumerate() {
            let f = pb::ServerMessage { seq: i as u64 + 1, body: Some(b.clone()) }.encode_to_vec();
            prop_assert_eq!(inb.decode(&f).unwrap(), (i as u64 + 1, Some(b)));
        }
    }
}

fn has_dup_keys(v: &Value) -> bool {
    match v {
        Value::Map(m) => {
            let mut ks: Vec<Vec<u8>> = m.iter().map(|(k, _)| cbor::encode(k)).collect();
            let n = ks.len();
            ks.sort();
            ks.dedup();
            ks.len() != n || m.iter().any(|(k, v)| has_dup_keys(k) || has_dup_keys(v))
        }
        Value::Array(a) => a.iter().any(has_dup_keys),
        Value::Tag(_, i) => has_dup_keys(i),
        _ => false,
    }
}

/// Random claim-like CBOR: text-keyed maps (with the real field names often), arrays, ints, text, bytes, bools.
fn claims_tree() -> impl Strategy<Value = Value> {
    const NAMES: [&str; 16] = [
        "type", "files", "path", "sha256", "size", "keys", "kid", "alg", "purpose", "public_key", "version", "model_id",
        "deadline", "job_id", "approvals", "tiers",
    ];
    let leaf = prop_oneof![
        any::<u64>().prop_map(|n| Value::Integer(n.into())),
        any::<i64>().prop_map(|n| Value::Integer(n.into())),
        ".{0,12}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(5, 64, 8, move |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::vec(
                (prop_oneof![(0usize..NAMES.len()).prop_map(|i| NAMES[i].to_string()), ".{0,6}"], inner),
                0..8
            )
            .prop_map(|kv| Value::Map(kv.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())),
        ]
    })
}

// ---------------------------------------------------------------- adversarial shapes (fixed cases)

/// Deep nesting must be refused without exhausting the stack (ciborium's recursion limit), at every layer.
#[test]
fn deeply_nested_cbor_is_refused_without_stack_overflow() {
    for depth in [200usize, 1_000, 100_000] {
        let mut b = vec![0x81u8; depth]; // [[[[...0...]]]]
        b.push(0x00);
        let r = cbor::decode_deterministic(&b);
        if depth > 256 {
            assert!(r.is_err(), "depth {depth}");
        }
        let _ = cbor::decode_any(&b);
        let _ = cose::parse_sign1(&b, ot::MODEL_MANIFEST);
        // the same nesting inside a map value and inside a COSE payload
        let mut m = vec![0xa1, 0x61, b'x'];
        m.extend_from_slice(&b);
        let _ = cbor::decode_deterministic(&m);
    }
}

/// Length headers that announce huge items must fail fast, without allocating the announced size.
#[test]
fn huge_length_headers_fail_fast() {
    let t = std::time::Instant::now();
    let cases: Vec<Vec<u8>> = vec![
        vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],            // bstr of 2^64-1 bytes
        vec![0x7b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00],            // tstr of 64 GiB
        vec![0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],            // array of 2^32 items
        vec![0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],            // map of 2^32 pairs
        vec![0xd2, 0x84, 0x5a, 0xff, 0xff, 0xff, 0xff],                        // COSE with a 4 GiB protected header
        vec![0xd2, 0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],      // COSE "array" of 2^63 items
        vec![0x5f, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // indefinite bstr, huge chunk
    ];
    for c in &cases {
        assert!(cbor::decode_any(c).is_err());
        assert!(cbor::decode_deterministic(c).is_err());
        for ty in ALL_TYPES {
            assert!(cose::parse_sign1(c, ty).is_err());
        }
        assert!(!verify_keyset(c) && !verify_manifest(c));
    }
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "took {:?}", t.elapsed());
}

/// A protobuf frame that announces a huge length-delimited field, and the oversize limit.
#[test]
fn protobuf_length_bombs_fail_fast() {
    let mut f = pb::ServerMessage { seq: 1, body: None }.encode_to_vec();
    // field 3 (Offer), wire type 2, length 2^62
    prost::encoding::encode_key(3, prost::encoding::WireType::LengthDelimited, &mut f);
    prost::encoding::encode_varint(1 << 62, &mut f);
    assert!(Inbound::new().decode(&f).is_err());
    // nested messages 100 levels deep in an unknown field are skipped without recursion trouble
    let mut nested = vec![];
    for _ in 0..100_000 {
        let mut outer = vec![];
        prost::encoding::encode_key(99, prost::encoding::WireType::LengthDelimited, &mut outer);
        prost::encoding::encode_varint(nested.len() as u64, &mut outer);
        outer.extend_from_slice(&nested);
        nested = outer;
        if nested.len() > 900_000 {
            break;
        }
    }
    let mut frame = pb::ServerMessage { seq: 1, body: None }.encode_to_vec();
    frame.extend_from_slice(&nested);
    let _ = Inbound::new().decode(&frame);
    // groups (deprecated wire type 3) nested deeply: prost's recursion limit refuses them
    let mut g = pb::ServerMessage { seq: 1, body: None }.encode_to_vec();
    for _ in 0..10_000 {
        prost::encoding::encode_key(99, prost::encoding::WireType::StartGroup, &mut g);
    }
    assert!(Inbound::new().decode(&g).is_err());
}

/// A KeySet signed by a real root but with a key entry that is not a P-256 SPKI, or an Ed25519 entry, never yields
/// a verifying key; and an entry of the right purpose but the wrong kid is unknown.
#[test]
fn keyset_entries_are_checked_at_use() {
    let v = FakeVault::new();
    let mut ks = v.keyset(9);
    ks.keys[1].public_key = vec![0x30, 0x03, 0x02, 0x01, 0x00];
    ks.keys.push(KeySetEntry { kid: "ed".into(), alg: -8, purpose: "registry".into(), public_key: vec![0; 44], not_before: 0, not_after: u64::MAX });
    let bytes = cose::sign1(&ks.to_value(), &v.roots[0]).unwrap();
    let t = trust::verify_keyset(&bytes, &v.roots(), 0).unwrap();
    let m = v.sign_manifest(&fixture_manifest());
    assert!(t.verify_manifest(&m, v.now()).is_err(), "registry key is garbage now");
    assert!(t.key("ed", "registry", v.now()).is_err(), "EdDSA entries are never used for verification");
    assert!(t.key(&v.registry.kid(), "dispatch", v.now()).is_err());
}

/// Unsigned or wrongly signed manifests: a bare claims map, a COSE_Sign1 with an all-zero signature, and one
/// signed by the updater (app release) key are all refused.
#[test]
fn unsigned_and_wrongly_signed_manifests_are_refused() {
    let w = world();
    let claims = cbor::encode(&fixture_manifest().to_value());
    assert!(!verify_manifest(&claims), "bare claims map");
    let Value::Tag(18, inner) = cbor::decode_any(&w.manifest).unwrap() else { panic!() };
    let Value::Array(mut arr) = *inner else { panic!() };
    arr[3] = Value::Bytes(vec![0; 64]);
    assert!(!verify_manifest(&cbor::encode(&Value::Tag(18, Box::new(Value::Array(arr.clone()))))), "zero signature");
    arr[3] = Value::Bytes(vec![]);
    assert!(!verify_manifest(&cbor::encode(&Value::Tag(18, Box::new(Value::Array(arr))))), "empty signature");
    let by_updater = cose::sign1(&fixture_manifest().to_value(), &w.vault.updater).unwrap();
    assert!(!verify_manifest(&by_updater), "updater key");
    // the same valid manifest wrapped in a different tag is not a COSE_Sign1
    let mut wrong_tag = w.manifest.clone();
    wrong_tag[0] = 0xd1; // tag 17 (COSE_Mac0)
    assert!(!verify_manifest(&wrong_tag));
}
