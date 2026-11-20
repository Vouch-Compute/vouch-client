//! Update acceptance policy: downgrade and rollback protection on top of the updater's signature check.
//!
//! The update endpoint's JSON (`version`, `url`, `signature`) is **not** signed; only the downloaded artifact is.
//! Without more checks, whoever controls the endpoint (or the network, for a dev `http://` endpoint) could pair a
//! high version number with an *older*, validly signed release and roll a contributor back to a build with a known
//! bug. The rules, all of which must hold before anything is downloaded:
//!
//! 1. **Strictly newer** (semver): the announced version is greater than the running one. Equal or lower is never
//!    an update (no downgrade, no re-install of the same version).
//! 2. **Signed version binding:** the minisign trusted comment, written by the Tauri CLI as
//!    `timestamp:<unix>\tfile:<name>\tversion:<v>`, must carry a version equal to the announced one. The updater
//!    plugin enforces the same rule *after* verifying the global signature (`requireSignedVersion: true` in
//!    `tauri.conf.json`), which is what makes the comment authentic; this pre-check refuses early and keeps the
//!    rule even if that config flag is ever lost.
//! 3. **Signed after this build:** the signature timestamp must be later than this binary's build time
//!    (`APP_BUILD_UNIX_S`, from `SOURCE_DATE_EPOCH` when set). A release signed before the running build was
//!    made is an old release, whatever version the endpoint claims.
//!
//! Signature *validity* (Ed25519 over the artifact, the channel's keys only) stays with the updater plugin.

use base64::Engine as _;

/// What the trusted comment of a Tauri updater signature says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedInfo {
    pub timestamp: Option<u64>,
    pub file: Option<String>,
    pub version: Option<String>,
}

/// Parse the base64-wrapped minisign signature the updater endpoint serves. Never panics on any input.
pub fn parse_signature(sig_b64: &str) -> Result<SignedInfo, String> {
    let text = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| "signature is not base64".to_string())?;
    let text = String::from_utf8(text).map_err(|_| "signature is not UTF-8".to_string())?;
    let sig = minisign_verify::Signature::decode(&text).map_err(|e| format!("signature: {e}"))?;
    let mut info = SignedInfo::default();
    for field in sig.trusted_comment().split('\t') {
        if let Some(v) = field.strip_prefix("timestamp:") {
            info.timestamp = v.trim().parse().ok();
        } else if let Some(v) = field.strip_prefix("file:") {
            info.file = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("version:") {
            info.version = Some(v.to_string());
        }
    }
    Ok(info)
}

fn semver(v: &str) -> Option<semver::Version> {
    semver::Version::parse(v.trim().trim_start_matches('v')).ok()
}

/// Rule 1: `announced` is a valid semver strictly greater than `current`. Anything unparsable is not newer.
pub fn is_newer(current: &str, announced: &str) -> bool {
    match (semver(current), semver(announced)) {
        (Some(c), Some(a)) => a > c,
        _ => false,
    }
}

/// Rules 1 to 3. `build_unix_s` is this binary's build time.
pub fn precheck(sig_b64: &str, announced: &str, current: &str, build_unix_s: u64) -> Result<SignedInfo, String> {
    if !is_newer(current, announced) {
        return Err(format!("update {announced} is not newer than {current}: refused (no downgrades)"));
    }
    let info = parse_signature(sig_b64)?;
    let signed = info.version.as_deref().ok_or("the update's signature does not name its version: refused")?;
    if semver(signed) != semver(announced) {
        return Err(format!("the endpoint announces {announced} but the signature is for {signed}: refused (rollback)"));
    }
    let ts = info.timestamp.ok_or("the update's signature has no timestamp: refused")?;
    if ts <= build_unix_s {
        return Err(format!("the update was signed at {ts}, before this build ({build_unix_s}): refused (rollback)"));
    }
    Ok(info)
}

/// This binary's build time (seconds since the epoch), set by `build.rs`.
pub fn build_unix_s() -> u64 {
    env!("APP_BUILD_UNIX_S").parse().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A throwaway minisign key that signs like `tauri signer sign` (custom trusted comment), wrapped in base64 as
    /// the Tauri updater expects for both the public key and the signature.
    struct Signer {
        pk: minisign::PublicKey,
        sk: minisign::SecretKey,
    }

    impl Signer {
        fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Self { pk: kp.pk, sk: kp.sk }
        }
        fn pubkey_b64(&self) -> String {
            b64(&self.pk.to_box().unwrap().to_string())
        }
        fn sign(&self, data: &[u8], trusted_comment: &str) -> String {
            let sig = minisign::sign(Some(&self.pk), &self.sk, std::io::Cursor::new(data), Some(trusted_comment), Some("signature from tauri secret key")).unwrap();
            b64(&sig.to_string())
        }
    }

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    /// The updater plugin's own check (`verify_signature`): Ed25519 over the data and the global signature over the
    /// trusted comment.
    fn plugin_verifies(pubkey_b64: &str, sig_b64: &str, data: &[u8]) -> bool {
        let dec = |s: &str| String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap();
        let pk = minisign_verify::PublicKey::decode(&dec(pubkey_b64)).unwrap();
        let Ok(sig) = minisign_verify::Signature::decode(&dec(sig_b64)) else { return false };
        pk.verify(data, &sig, true).is_ok()
    }

    const BUILD: u64 = 1_795_000_000;

    #[test]
    fn newer_signed_update_passes() {
        let s = Signer::new();
        let data = b"Vouch Compute 0.2.0 installer";
        let sig = s.sign(data, &format!("timestamp:{}\tfile:VouchCompute_0.2.0_x64-setup.exe\tversion:0.2.0", BUILD + 3600));
        assert!(plugin_verifies(&s.pubkey_b64(), &sig, data));
        let info = precheck(&sig, "0.2.0", "0.1.0", BUILD).unwrap();
        assert_eq!(info.version.as_deref(), Some("0.2.0"));
        assert_eq!(info.file.as_deref(), Some("VouchCompute_0.2.0_x64-setup.exe"));
        // "v" prefixes are the same version
        assert!(precheck(&sig, "v0.2.0", "0.1.0", BUILD).is_ok());
    }

    #[test]
    fn downgrades_and_reinstalls_are_refused() {
        let s = Signer::new();
        let old = s.sign(b"0.0.9", &format!("timestamp:{}\tfile:x\tversion:0.0.9", BUILD + 10));
        assert!(precheck(&old, "0.0.9", "0.1.0", BUILD).unwrap_err().contains("not newer"));
        let same = s.sign(b"0.1.0", &format!("timestamp:{}\tfile:x\tversion:0.1.0", BUILD + 10));
        assert!(precheck(&same, "0.1.0", "0.1.0", BUILD).is_err());
        // pre-releases sort below the release
        assert!(!is_newer("0.2.0", "0.2.0-rc.1"));
        assert!(is_newer("0.2.0-rc.1", "0.2.0"));
        for junk in ["", "latest", "0.2", "999999999999999999999.0.0", "1.0.0.0", "-1.0.0"] {
            assert!(!is_newer("0.1.0", junk), "{junk:?}");
        }
    }

    /// The rollback attack: a tampered endpoint announces 0.3.0 but serves the (validly signed) 0.1.5 artifact.
    #[test]
    fn rollback_with_a_higher_announced_version_is_refused() {
        let s = Signer::new();
        let data = b"old but validly signed release";
        let sig = s.sign(data, &format!("timestamp:{}\tfile:VouchCompute_0.1.5_x64-setup.exe\tversion:0.1.5", BUILD + 10));
        assert!(plugin_verifies(&s.pubkey_b64(), &sig, data), "the signature itself is valid");
        assert!(precheck(&sig, "0.3.0", "0.1.0", BUILD).unwrap_err().contains("rollback"));
        // an old release signed before this build, even if its version string were higher
        let sig = s.sign(data, &format!("timestamp:{}\tfile:x\tversion:0.3.0", BUILD - 1));
        assert!(precheck(&sig, "0.3.0", "0.1.0", BUILD).unwrap_err().contains("before this build"));
        // signatures from CLIs that did not record the version or timestamp are refused
        let sig = s.sign(data, &format!("timestamp:{}\tfile:x", BUILD + 10));
        assert!(precheck(&sig, "0.3.0", "0.1.0", BUILD).unwrap_err().contains("does not name its version"));
        let sig = s.sign(data, "file:x\tversion:0.3.0");
        assert!(precheck(&sig, "0.3.0", "0.1.0", BUILD).unwrap_err().contains("no timestamp"));
    }

    /// Editing the trusted comment (to claim another version) breaks the global signature, so the plugin refuses the
    /// download even if our pre-check were fooled.
    #[test]
    fn trusted_comment_is_authenticated() {
        let s = Signer::new();
        let data = b"payload";
        let sig = s.sign(data, &format!("timestamp:{}\tfile:x\tversion:0.1.5", BUILD + 10));
        let text = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&sig).unwrap()).unwrap();
        let forged = b64(&text.replace("version:0.1.5", "version:0.3.0"));
        assert!(precheck(&forged, "0.3.0", "0.1.0", BUILD).is_ok(), "the pre-check alone reads the comment");
        assert!(!plugin_verifies(&s.pubkey_b64(), &forged, data), "but the plugin's global-signature check refuses it");
        // and a signature by another key never verifies
        let other = Signer::new();
        assert!(!plugin_verifies(&other.pubkey_b64(), &sig, data));
    }

    /// The real artifact signed by the dev key (Tauri CLI 2.12.5) carries the fields this policy needs.
    #[test]
    fn tauri_cli_signatures_carry_version_and_timestamp() {
        let sig = include_str!("../tests/data/payload.dev.sig");
        let info = parse_signature(sig).unwrap();
        assert!(info.timestamp.is_some());
        let shipped = include_str!("../tests/data/nsis-0.1.0.sig");
        let info = parse_signature(shipped).unwrap();
        assert_eq!(info.version.as_deref(), Some("0.1.0"));
        assert_eq!(info.timestamp, Some(1_795_052_495));
    }

    #[test]
    fn build_time_is_embedded() {
        let t = build_unix_s();
        assert!(t > 1_700_000_000 && t < 4_000_000_000, "{t}");
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

        /// Fuzz: arbitrary signature strings and versions never panic, and nothing unsigned passes.
        #[test]
        fn precheck_never_panics_and_refuses_garbage(sig in ".{0,300}", raw in proptest::collection::vec(any::<u8>(), 0..300), a in ".{0,20}", c in ".{0,20}") {
            let _ = parse_signature(&sig);
            let _ = precheck(&sig, &a, &c, 0);
            let wrapped = base64::engine::general_purpose::STANDARD.encode(&raw);
            let _ = parse_signature(&wrapped);
            prop_assert!(precheck(&wrapped, "9.9.9", "0.0.1", 0).is_err());
        }

        /// The version rule is exactly semver "greater than".
        #[test]
        fn is_newer_matches_semver(a in (0u64..5, 0u64..5, 0u64..5), b in (0u64..5, 0u64..5, 0u64..5)) {
            let (va, vb) = (format!("{}.{}.{}", a.0, a.1, a.2), format!("{}.{}.{}", b.0, b.1, b.2));
            prop_assert_eq!(is_newer(&va, &vb), b > a);
        }
    }
}
