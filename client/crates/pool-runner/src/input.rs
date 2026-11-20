//! Canonical input validation. Everything here runs BEFORE any decoder touches the bytes:
//! the runner accepts exactly `audio/flac;rate=16000;channels=1` and
//! `application/vnd.pool.embed-batch.v1+json`, and rejects anything else.

use pool_proto::{CANONICAL_AUDIO_FORMAT, EMBED_BATCH_FORMAT};

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("input rejected: {0}")]
pub struct Rejected(pub &'static str);

/// Longest canonical chunk accepted (chunks are 5-10 min of audio; allow headroom).
pub const MAX_AUDIO_SECONDS: u64 = 15 * 60;
pub const MAX_EMBED_INPUTS: usize = 2048;
pub const MAX_EMBED_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlacInfo {
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    pub total_samples: u64,
}

/// Validate the FLAC stream header without decoding any audio frame.
pub fn validate_flac_header(bytes: &[u8]) -> Result<FlacInfo, Rejected> {
    if bytes.len() < 4 + 4 + 34 || &bytes[..4] != b"fLaC" {
        return Err(Rejected("not a FLAC stream"));
    }
    let block_type = bytes[4] & 0x7f;
    let block_len = u32::from_be_bytes([0, bytes[5], bytes[6], bytes[7]]);
    if block_type != 0 || block_len != 34 {
        return Err(Rejected("first metadata block must be STREAMINFO"));
    }
    let si = &bytes[8..8 + 34];
    // bytes 10..18 of STREAMINFO: sample rate (20 bits), channels-1 (3), bps-1 (5), total samples (36)
    let packed = u64::from_be_bytes(si[10..18].try_into().unwrap());
    let sample_rate = (packed >> 44) as u32;
    let channels = (((packed >> 41) & 0x7) + 1) as u8;
    let bits_per_sample = (((packed >> 36) & 0x1f) + 1) as u8;
    let total_samples = packed & 0x0f_ffff_ffff;
    if sample_rate != 16_000 {
        return Err(Rejected("sample rate must be 16000"));
    }
    if channels != 1 {
        return Err(Rejected("audio must be mono"));
    }
    if !(bits_per_sample == 16 || bits_per_sample == 24) {
        return Err(Rejected("bits per sample must be 16 or 24"));
    }
    if total_samples == 0 || total_samples > MAX_AUDIO_SECONDS * 16_000 {
        return Err(Rejected("total samples out of range"));
    }
    Ok(FlacInfo { sample_rate, channels, bits_per_sample, total_samples })
}

/// Parse and validate an embed batch: strict UTF-8 JSON object `{"inputs": [string, ...]}`, NFC only.
pub fn parse_embed_batch(bytes: &[u8]) -> Result<Vec<String>, Rejected> {
    use unicode_normalization::{is_nfc_quick, IsNormalized};
    let text = std::str::from_utf8(bytes).map_err(|_| Rejected("not UTF-8"))?;
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| Rejected("not JSON"))?;
    let obj = v.as_object().ok_or(Rejected("not a JSON object"))?;
    if obj.len() != 1 {
        return Err(Rejected("unexpected keys"));
    }
    let arr = obj.get("inputs").and_then(|x| x.as_array()).ok_or(Rejected("missing inputs array"))?;
    if arr.is_empty() || arr.len() > MAX_EMBED_INPUTS {
        return Err(Rejected("inputs count out of range"));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str().ok_or(Rejected("inputs must be strings"))?;
        if s.len() > MAX_EMBED_INPUT_BYTES {
            return Err(Rejected("input too long"));
        }
        let nfc = match is_nfc_quick(s.chars()) {
            IsNormalized::Yes => true,
            IsNormalized::No => false,
            IsNormalized::Maybe => unicode_normalization::UnicodeNormalization::nfc(s).eq(s.chars()),
        };
        if !nfc {
            return Err(Rejected("input not NFC"));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// Gate: the declared format must be canonical and the bytes must match it.
pub fn validate(format: &str, bytes: &[u8]) -> Result<(), Rejected> {
    match format {
        f if f == CANONICAL_AUDIO_FORMAT => validate_flac_header(bytes).map(|_| ()),
        f if f == EMBED_BATCH_FORMAT => parse_embed_batch(bytes).map(|_| ()),
        _ => Err(Rejected("non-canonical input format")),
    }
}

/// Decode a validated FLAC stream to f32 PCM in [-1, 1].
#[cfg(any(feature = "candle", feature = "onnx", feature = "whisper"))]
pub fn decode_flac(bytes: &[u8]) -> Result<Vec<f32>, Rejected> {
    let info = validate_flac_header(bytes)?;
    let mut reader = claxon::FlacReader::new(std::io::Cursor::new(bytes)).map_err(|_| Rejected("bad FLAC"))?;
    let scale = (1u64 << (info.bits_per_sample - 1)) as f32;
    let mut pcm = Vec::with_capacity(info.total_samples as usize);
    for s in reader.samples() {
        let s = s.map_err(|_| Rejected("bad FLAC frame"))?;
        pcm.push(s as f32 / scale);
        if pcm.len() as u64 > info.total_samples {
            return Err(Rejected("more samples than declared"));
        }
    }
    Ok(pcm)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal valid FLAC: STREAMINFO + one VERBATIM subframe frame is complex to hand-build, so tests
    /// that need decodable audio use `encode_flac_verbatim` below.
    pub fn streaminfo(sample_rate: u32, channels: u8, bps: u8, total: u64) -> Vec<u8> {
        let mut v = b"fLaC".to_vec();
        v.push(0x80); // last-metadata-block flag + type 0
        v.extend_from_slice(&[0, 0, 34]);
        let mut si = [0u8; 34];
        si[0..2].copy_from_slice(&4096u16.to_be_bytes());
        si[2..4].copy_from_slice(&4096u16.to_be_bytes());
        let packed: u64 = (u64::from(sample_rate) << 44)
            | (u64::from(channels - 1) << 41)
            | (u64::from(bps - 1) << 36)
            | (total & 0x0f_ffff_ffff);
        si[10..18].copy_from_slice(&packed.to_be_bytes());
        v.extend_from_slice(&si);
        v
    }

    #[test]
    fn flac_header_rules() {
        assert_eq!(validate_flac_header(&streaminfo(16000, 1, 16, 16000)).unwrap().total_samples, 16000);
        assert!(validate_flac_header(&streaminfo(44100, 1, 16, 16000)).is_err());
        assert!(validate_flac_header(&streaminfo(16000, 2, 16, 16000)).is_err());
        assert!(validate_flac_header(&streaminfo(16000, 1, 8, 16000)).is_err());
        assert!(validate_flac_header(&streaminfo(16000, 1, 16, 0)).is_err());
        assert!(validate_flac_header(&streaminfo(16000, 1, 16, 16000 * 60 * 16)).is_err());
        assert!(validate_flac_header(b"RIFF....WAVEfmt ").is_err());
        assert!(validate_flac_header(b"ID3\x04").is_err());
    }

    #[test]
    fn embed_batch_rules() {
        assert_eq!(parse_embed_batch(br#"{"inputs":["a","b"]}"#).unwrap(), vec!["a", "b"]);
        for bad in [
            &br#"{"inputs":[]}"#[..],
            br#"{"inputs":["a"],"x":1}"#,
            br#"{"inputs":[1]}"#,
            br#"["a"]"#,
            b"\xff\xfe",
            br#"{"inputs":"a"}"#,
        ] {
            assert!(parse_embed_batch(bad).is_err());
        }
        // "e" + combining acute (NFD) is rejected; precomposed is fine
        assert!(parse_embed_batch("{\"inputs\":[\"e\u{301}\"]}".as_bytes()).is_err());
        assert!(parse_embed_batch("{\"inputs\":[\"\u{e9}\"]}".as_bytes()).is_ok());
    }

    /// Fuzz-style canonical-input test: random and mutated non-canonical inputs never pass validation for audio.
    #[test]
    fn random_bytes_never_pass_audio_gate() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..5000 {
            let len = (next() % 200) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            assert!(validate(CANONICAL_AUDIO_FORMAT, &bytes).is_err());
        }
        // mutate a valid header's format fields: anything not 16k/mono/16|24-bit is rejected
        let good = streaminfo(16000, 1, 16, 32000);
        for _ in 0..2000 {
            let mut m = good.clone();
            let i = 8 + 10 + (next() % 4) as usize;
            m[i] ^= 1 << (next() % 8);
            if let Ok(info) = validate_flac_header(&m) {
                assert_eq!((info.sample_rate, info.channels), (16000, 1));
            }
        }
        assert!(validate("audio/wav", &good).is_err());
        assert!(validate("audio/flac", &good).is_err());
    }
}
