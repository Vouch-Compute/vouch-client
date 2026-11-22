//! Which URLs `open_link` may hand to the browser.
//!
//! The page never supplies a URL: `open_link` takes a fixed `kind` and reads the URL from the agent (the configured
//! web/account-server base URLs, or the server's `verification_uri_complete` for sign-in). That last one comes from the server, so
//! it is still checked here. Previously the check was a string prefix, which let `http://127.0.0.1.evil.example/` and
//! `http://localhost.evil.example/` through in plain HTTP. Now the URL is parsed:
//!
//! * `https://` with a real host and no user-info (`https://vouchcompute.com@evil.example` is refused as a phishing shape);
//! * `http://` only in dev builds, and only to the exact loopback hosts `127.0.0.1`, `localhost` and `[::1]`;
//! * nothing else (`file:`, `javascript:`, `data:`, custom schemes, ...).

/// The `open_link` kinds whose URL is read from the agent's `status.links` (built from the configured web base URL).
/// `contributor_agreement` and `acceptable_use` are the legal documents a contributor accepts when linking a device.
pub const STATUS_KINDS: &[&str] = &["wallet", "dashboard", "earn", "trust", "devices", "recover", "verify", "contributor_agreement", "acceptable_use"];

pub fn check(url: &str, dev_build: bool) -> Result<String, String> {
    let u = tauri::Url::parse(url.trim()).map_err(|_| crate::i18n::t("error.link.invalid"))?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(crate::i18n::t("error.link.userInfo"));
    }
    let host = u.host_str().unwrap_or_default();
    if host.is_empty() {
        return Err(crate::i18n::t("error.link.noHost"));
    }
    match u.scheme() {
        "https" => Ok(u.into()),
        "http" if dev_build && matches!(host, "127.0.0.1" | "localhost" | "[::1]") => Ok(u.into()),
        "http" => Err(crate::i18n::t("error.link.notHttps")),
        _ => Err(crate::i18n::t("error.link.notWeb")),
    }
}

#[cfg(test)]
mod tests {
    use super::{check, STATUS_KINDS};

    #[test]
    fn status_kinds_are_plain_names_and_include_the_legal_documents() {
        for k in STATUS_KINDS {
            assert!(!k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{k}");
        }
        assert!(STATUS_KINDS.contains(&"contributor_agreement") && STATUS_KINDS.contains(&"acceptable_use"));
        assert!(!STATUS_KINDS.contains(&"signin"), "the sign-in URL comes from signin.status, not status.links");
    }

    #[test]
    fn https_links_pass_and_are_normalised() {
        assert_eq!(check("https://vouchcompute.example/app/link?user_code=ABCD-EFGH", false).unwrap(), "https://vouchcompute.example/app/link?user_code=ABCD-EFGH");
        assert!(check("  https://vault.vouchcompute.example:8443/x ", false).is_ok());
    }

    #[test]
    fn loopback_http_only_in_dev_builds_and_only_exact_hosts() {
        for ok in ["http://127.0.0.1:3000/app/link", "http://localhost:3000/", "http://[::1]:3000/"] {
            assert!(check(ok, true).is_ok(), "{ok}");
            assert!(check(ok, false).is_err(), "release builds never open plain http: {ok}");
        }
        // a plain prefix check would let these through
        for bad in [
            "http://127.0.0.1.evil.example/phish",
            "http://localhost.evil.example/",
            "http://127.0.0.1@evil.example/",
            "http://localhost:3000@evil.example/",
            "http://evil.example/?127.0.0.1",
        ] {
            assert!(check(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn other_schemes_and_shapes_are_refused() {
        for bad in [
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ms-settings:privacy",
            "smb://host/share",
            "https://vouchcompute.example@evil.example/",
            "https://user:pw@vouchcompute.example/",
            "",
            "not a url",
        ] {
            assert!(check(bad, true).is_err(), "{bad}");
        }
    }
}
