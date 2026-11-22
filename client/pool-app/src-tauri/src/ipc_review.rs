//! IPC allow-list and CSP review, as tests over the shipped configuration and sources. A change that widens
//! what the page can reach fails here and needs a fresh security review.

use serde_json::Value;

const CONF: &str = include_str!("../tauri.conf.json");
const CAPS: &str = include_str!("../capabilities/default.json");
const MAIN_RS: &str = include_str!("main.rs");
const CONTROL_RS: &str = include_str!("../../../crates/pool-core/src/control.rs");
const APP_JS: &str = include_str!("../../ui/app.js");
const I18N_JS: &str = include_str!("../../ui/i18n.js");
const INDEX_HTML: &str = include_str!("../../ui/index.html");

fn conf() -> Value {
    serde_json::from_str(CONF).unwrap()
}

/// The page's capability grants only `core:default` to the one window: no fs, shell, http, opener, updater or
/// dialog permission, no remote URLs.
#[test]
fn capability_grants_only_core_default_to_the_main_window() {
    let caps: Value = serde_json::from_str(CAPS).unwrap();
    assert_eq!(caps["permissions"], serde_json::json!(["core:default"]));
    assert_eq!(caps["windows"], serde_json::json!(["main"]));
    assert!(caps.get("remote").is_none(), "no remote origin may reach IPC");
    assert!(caps.get("webviews").is_none());
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(files.len(), 1, "exactly one capability file: {files:?}");
}

/// The app exposes exactly these commands. Adding one is an IPC surface change.
#[test]
fn invoke_handler_lists_exactly_the_reviewed_commands() {
    let start = MAIN_RS.find("generate_handler![").expect("handler") + "generate_handler![".len();
    let end = start + MAIN_RS[start..].find(']').unwrap();
    let mut cmds: Vec<&str> = MAIN_RS[start..end].split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    cmds.sort();
    assert_eq!(cmds, ["autostart_get", "autostart_set", "build_info", "check_update", "core", "ensure_core", "i18n_messages", "install_update", "open_link", "set_locale"]);
    // nothing takes a path, a URL or a shell command from the page
    for c in &cmds {
        let sig = MAIN_RS.find(&format!("fn {c}(")).map(|i| &MAIN_RS[i..i + MAIN_RS[i..].find('{').unwrap()]).unwrap();
        for bad in ["PathBuf", "url: String", "cmd", "command: String", "path: String"] {
            assert!(!sig.contains(bad), "{c} takes {bad}: {sig}");
        }
    }
}

/// The `core` proxy's allow-list: every method exists in the agent, none writes a wallet, and the dev-only
/// `dev.simulate` is not reachable from the page.
#[test]
fn core_proxy_allow_list_matches_the_agent() {
    let allowed = crate::core_client::ALLOWED;
    for m in allowed {
        assert!(CONTROL_RS.contains(&format!("\"{m}\" =>")), "{m} is allow-listed but the agent has no such method");
        assert!(!m.contains("wallet") || *m == "wallets", "{m}: no wallet write method may exist");
    }
    for forbidden in ["dev.simulate", "wallet.set", "wallets.set", "config.set", "settings.engine", "shell", "exec"] {
        assert!(!allowed.contains(&forbidden), "{forbidden} must not be reachable from the page");
    }
    let mut sorted = allowed.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), allowed.len(), "duplicates in ALLOWED");
    // and the UI only calls allow-listed methods and the reviewed commands
    for (i, _) in APP_JS.match_indices("core(\"") {
        let rest = &APP_JS[i + 6..];
        let m = &rest[..rest.find('"').unwrap()];
        assert!(allowed.contains(&m), "app.js calls core(\"{m}\") which is not allow-listed");
    }
    for (i, _) in APP_JS.match_indices("invoke(\"") {
        let rest = &APP_JS[i + 8..];
        let c = &rest[..rest.find('"').unwrap()];
        assert!(["core", "ensure_core", "open_link", "build_info", "check_update", "install_update", "autostart_get", "autostart_set", "set_locale", "i18n_messages"].contains(&c), "{c}");
    }
}

/// CSP: scripts and styles from the app bundle only, no inline script, no eval, IPC as the only connection, no
/// frames, no forms, no plugins.
#[test]
fn csp_is_strict() {
    let c = conf();
    let csp = c["app"]["security"]["csp"].as_str().unwrap();
    let directive = |name: &str| -> String {
        csp.split(';').map(str::trim).find(|d| d.starts_with(&format!("{name} "))).unwrap_or_else(|| panic!("{name} missing")).to_string()
    };
    assert_eq!(directive("default-src"), "default-src 'self'");
    assert_eq!(directive("script-src"), "script-src 'self'");
    assert_eq!(directive("object-src"), "object-src 'none'");
    assert_eq!(directive("base-uri"), "base-uri 'none'");
    assert_eq!(directive("form-action"), "form-action 'none'");
    assert_eq!(directive("frame-ancestors"), "frame-ancestors 'none'");
    assert_eq!(directive("connect-src"), "connect-src ipc: http://ipc.localhost");
    assert!(!csp.contains("unsafe"), "no unsafe-* source: {csp}");
    for t in csp.split_whitespace().map(|t| t.trim_matches(';')) {
        assert!(!["*", "http:", "https:", "blob:", "ws:", "wss:"].contains(&t), "wildcard source {t} in CSP: {csp}");
    }
    assert_eq!(c["app"]["security"]["freezePrototype"], true);
    assert!(c["app"]["security"].get("dangerousDisableAssetCspModification").is_none());
    assert!(c["app"]["security"].get("dangerousRemoteDomainIpcAccess").is_none());
    // no inline script or handler in the page (they would be blocked by the CSP anyway)
    assert!(!INDEX_HTML.contains("<script>") && !INDEX_HTML.contains(" onclick="), "inline script in index.html");
    for sink in ["eval(", "new Function(", "document.write(", "setTimeout(\"", "setInterval(\""] {
        assert!(!APP_JS.contains(sink), "{sink} in app.js");
        assert!(!I18N_JS.contains(sink), "{sink} in i18n.js");
    }
    // translations reach the DOM as text only: i18n.js never writes HTML itself
    for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML"] {
        assert!(!I18N_JS.contains(sink), "{sink} in i18n.js");
    }
    assert!(INDEX_HTML.contains("<script src=\"i18n.js\" defer></script>"), "index.html loads i18n.js from the bundle");
    // the windows load the bundled UI only
    for w in c["app"]["windows"].as_array().unwrap() {
        assert!(w.get("url").is_none() || w["url"].as_str().unwrap().starts_with("index"), "remote window url");
    }
}

/// The locale commands take a language tag only, and anything outside the registry becomes English: the page can
/// neither name a file nor get anything but the embedded message catalogues.
#[test]
fn locale_commands_only_select_registry_entries() {
    use crate::i18n::{resolve, ui_messages, LOCALES};
    for bad in ["../../tauri.conf.json", "C:\\Windows\\win.ini", "en/../../x", "", "\u{202e}ar"] {
        assert_eq!(LOCALES[resolve(bad)].code, "en", "{bad:?}");
        assert_eq!(ui_messages(bad), LOCALES[0].ui_text(), "{bad:?}");
    }
    for sig in ["fn set_locale(app: AppHandle, locale: String) -> String", "fn i18n_messages(locale: String) -> String"] {
        assert!(MAIN_RS.contains(sig), "reviewed signature changed: {sig}");
    }
}

/// The updater config enforces the rollback rule (signed version) and never allows downgrades.
#[test]
fn updater_config_binds_versions_and_forbids_downgrades() {
    let u = &conf()["plugins"]["updater"];
    assert_eq!(u["requireSignedVersion"], true);
    assert!(u.get("allowDowngrades").is_none() || u["allowDowngrades"] == false);
    assert!(u.get("dangerousAcceptInvalidCerts").is_none() && u.get("dangerousAcceptInvalidHostnames").is_none());
    assert!(MAIN_RS.contains("mod update_policy;"));
}
