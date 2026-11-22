//! Native strings (tray menu, window title, errors shown to the user) in the window's language.
//!
//! Same keys and registry as the UI (`ui/i18n.js`): `locales/<code>.json` here holds the native strings, and the
//! UI's own `ui/locales/<code>.json` are embedded too so the page can load them over IPC (the CSP allows no fetch).
//! The page tells the app its language with `set_locale`; any value outside the registry becomes English. Native
//! strings use only simple `{name}` placeholders. A missing key falls back to English, then to the key itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use serde_json::Value;

pub struct Locale {
    pub code: &'static str,
    native: &'static str,
    ui: &'static str,
}

impl Locale {
    #[cfg(test)]
    pub fn ui_text(&self) -> &'static str {
        self.ui
    }
}

/// One line per language (keep in step with `LOCALES` in ui/i18n.js; the i18n tests compare the two).
macro_rules! registry {
    ($($code:literal),* $(,)?) => {
        pub const LOCALES: &[Locale] = &[$(Locale {
            code: $code,
            native: include_str!(concat!("../locales/", $code, ".json")),
            ui: include_str!(concat!("../../ui/locales/", $code, ".json")),
        }),*];
    };
}
registry!("en", "tr", "es", "pt-BR", "fr", "de", "zh-CN", "ja", "ko", "hi", "id", "ar");

type Table = HashMap<String, String>;

static CURRENT: AtomicUsize = AtomicUsize::new(0);

fn flatten(prefix: &str, v: &Value, out: &mut Table) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&key, v, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        _ => {}
    }
}

fn parse(json: &str) -> Table {
    let mut t = Table::new();
    // a broken file leaves an empty table, so every key falls back to English (the tests refuse such a file)
    if let Ok(v) = serde_json::from_str::<Value>(json) {
        flatten("", &v, &mut t);
    }
    t
}

fn tables() -> &'static [Table] {
    static TABLES: OnceLock<Vec<Table>> = OnceLock::new();
    TABLES.get_or_init(|| LOCALES.iter().map(|l| parse(l.native)).collect())
}

/// Registry index for a language tag: exact match (case-insensitive, `_` or `-`), then the first entry with the same
/// language ("pt-PT" -> pt-BR, "zh-TW" -> zh-CN), else English. Malformed input is English.
pub fn resolve(tag: &str) -> usize {
    let tag = tag.trim();
    let well_formed = (2..=35).contains(&tag.len())
        && tag.split(['-', '_']).enumerate().all(|(i, p)| {
            if i == 0 {
                (2..=3).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphabetic())
            } else {
                (1..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric())
            }
        });
    if !well_formed {
        return 0;
    }
    let tag = tag.replace('_', "-").to_ascii_lowercase();
    if let Some(i) = LOCALES.iter().position(|l| l.code.to_ascii_lowercase() == tag) {
        return i;
    }
    let lang = tag.split('-').next().unwrap_or_default();
    LOCALES.iter().position(|l| l.code.to_ascii_lowercase().split('-').next() == Some(lang)).unwrap_or(0)
}

/// Make `tag` (resolved against the registry) the language of native strings; returns the registry code.
pub fn set(tag: &str) -> &'static str {
    let i = resolve(tag);
    CURRENT.store(i, Ordering::Relaxed);
    LOCALES[i].code
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn current() -> &'static str {
    LOCALES[CURRENT.load(Ordering::Relaxed)].code
}

/// The UI's messages for a language (English for anything outside the registry), as the JSON text.
pub fn ui_messages(tag: &str) -> &'static str {
    LOCALES[resolve(tag)].ui
}

fn lookup<'a>(tables: &'a [Table], idx: usize, key: &'a str) -> &'a str {
    tables
        .get(idx)
        .and_then(|t| t.get(key))
        .filter(|s| !s.is_empty())
        .or_else(|| tables.first().and_then(|t| t.get(key)))
        .map(String::as_str)
        .unwrap_or(key)
}

fn fill(msg: &str, vars: &[(&str, &str)]) -> String {
    let mut s = msg.to_string();
    for (k, v) in vars {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

/// The native string for `key` in the current language.
pub fn t(key: &str) -> String {
    lookup(tables(), CURRENT.load(Ordering::Relaxed), key).to_string()
}

/// Same, with `{name}` placeholders filled in (values are inserted as they are; they are shown as text).
pub fn tv(key: &str, vars: &[(&str, &str)]) -> String {
    fill(lookup(tables(), CURRENT.load(Ordering::Relaxed), key), vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(pairs: &[(&str, &str)]) -> Table {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn unknown_or_malformed_locales_are_english() {
        for bad in ["", "xx", "klingon", "../etc/passwd", "en\u{0}", "zz-ZZ", "e", "<script>", "tr;de", &"a".repeat(100)] {
            assert_eq!(LOCALES[resolve(bad)].code, "en", "{bad:?}");
        }
    }

    #[test]
    fn tags_are_best_matched_against_the_registry() {
        for (tag, want) in [("tr", "tr"), ("tr-TR", "tr"), ("pt", "pt-BR"), ("pt-PT", "pt-BR"), ("pt_br", "pt-BR"), ("zh", "zh-CN"),
            ("zh-TW", "zh-CN"), ("zh-Hans-CN", "zh-CN"), ("AR-eg", "ar"), ("en-GB", "en"), ("de-AT", "de"), ("ja-JP", "ja")] {
            assert_eq!(LOCALES[resolve(tag)].code, want, "{tag}");
        }
        for l in LOCALES {
            assert_eq!(LOCALES[resolve(l.code)].code, l.code, "every registry code resolves to itself");
        }
    }

    #[test]
    fn missing_keys_fall_back_to_english_then_to_the_key() {
        let tables = vec![table(&[("a", "A"), ("b", "B")]), table(&[("a", "Ä"), ("b", "")])];
        assert_eq!(lookup(&tables, 1, "a"), "Ä");
        assert_eq!(lookup(&tables, 1, "b"), "B", "an empty translation falls back to English");
        assert_eq!(lookup(&tables, 1, "c"), "c", "a key missing everywhere shows the key");
        assert_eq!(lookup(&tables, 7, "a"), "A", "an index outside the registry is English");
    }

    #[test]
    fn placeholders_are_filled_as_text() {
        assert_eq!(fill("Could not start ({path}): {detail}", &[("path", "C:\\x"), ("detail", "{path}")]), "Could not start (C:\\x): {path}");
    }

    #[test]
    fn every_embedded_file_parses_with_the_english_keys() {
        let en = parse(LOCALES[0].native);
        assert!(en.len() > 10);
        for l in LOCALES {
            let t = parse(l.native);
            let mut a: Vec<_> = t.keys().collect();
            let mut b: Vec<_> = en.keys().collect();
            a.sort();
            b.sort();
            assert_eq!(a, b, "{}: native keys differ from en", l.code);
            assert!(t.values().all(|v| !v.trim().is_empty()), "{}: empty value", l.code);
            let ui: Value = serde_json::from_str(l.ui).unwrap_or_else(|e| panic!("{}: ui messages: {e}", l.code));
            assert!(ui.is_object());
        }
    }

    #[test]
    fn set_switches_the_tray_language_and_unknown_resets_to_english() {
        assert_eq!(set("tr-TR"), "tr");
        assert_eq!(current(), "tr");
        let tr = t("tray.open");
        assert_ne!(tr, lookup(tables(), 0, "tray.open"), "Turkish tray text is translated");
        assert!(tr.contains("Vouch Compute"));
        assert_eq!(set("nonsense"), "en");
        assert_eq!(t("tray.open"), "Open Vouch Compute");
        assert_eq!(tv("error.update.checkFailed", &[("detail", "timeout")]), "The update check failed: timeout");
        assert_eq!(ui_messages("../../secret"), LOCALES[0].ui);
    }
}
