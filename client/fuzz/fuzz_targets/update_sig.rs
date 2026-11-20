//! The app's update policy (pool-app/src-tauri/src/update_policy.rs, included as is): arbitrary signature text and
//! versions never panic, and nothing passes unless it is newer, names its version and is signed after the build.
#![no_main]
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../pool-app/src-tauri/src/update_policy.rs"]
mod update_policy;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let mut parts = s.splitn(3, '\u{0}');
    let (sig, a, c) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let _ = update_policy::parse_signature(sig);
    if let Ok(info) = update_policy::precheck(sig, a, c, 1_000) {
        assert!(update_policy::is_newer(c, a));
        assert!(info.version.is_some() && info.timestamp.unwrap_or(0) > 1_000);
    }
    let wrapped = base64::engine::general_purpose::STANDARD.encode(data);
    let _ = update_policy::precheck(&wrapped, "9.9.9", "0.0.1", 0);
});
