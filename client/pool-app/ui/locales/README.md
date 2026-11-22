# App languages

The desktop app's text lives in two sets of JSON files with the same layout:

- `ui/locales/<code>.json`: everything shown in the window (loaded by `ui/i18n.js`);
- `src-tauri/locales/<code>.json`: native text (tray menu, window title, errors from the app itself), embedded in the
  binary by `src-tauri/src/i18n.rs`.

English (`en.json`) is the source of truth. Every other file has exactly the same keys. A missing or broken message
falls back to English at runtime, and the tests fail on it.

Terminology, protected names and the words we never use are in the shared glossary:
[`docs/i18n/glossary.md`](../../../../docs/i18n/glossary.md).

## Add a language

1. Copy `ui/locales/en.json` to `ui/locales/<code>.json` and `src-tauri/locales/en.json` to
   `src-tauri/locales/<code>.json`, then translate the values.
2. Add one line to the registry in `ui/i18n.js` (`{ code, name, dir }`, with the native name and `ltr` or `rtl`)
   and the same code to `registry!(...)` in `src-tauri/src/i18n.rs`. The test checks that both lists match the files.
3. Run the checks (below). Nothing else changes: the language picker, the system-language matching and the tray
   pick it up from the registry.

## Deliver a translation

The locale files start as copies of English. When a translation is complete, remove the locale from
`NOT_YET_TRANSLATED` in `tests/i18n.test.js`. From then on a string identical to English fails, unless its key is in
`SAME_AS_ENGLISH` for that locale (only for names, symbols and pure placeholders such as `{low} – {high}`).

## Add or change a key

1. Add it to both `en.json` files' namespace where it belongs (`settings.language.title`, `error.update.noKey`, ...)
   and use it from the code with a literal key: `t("...")`/`tx("...")`/`rich("...")` in `app.js`, `data-i18n` or
   `data-i18n-attr` in `index.html`, `i18n::t("...")`/`i18n::tv("...", &[...])` in Rust.
2. Add the same key to every other locale file (English text until translated).
3. Write whole sentences. Never build a sentence from fragments; use placeholders instead.

## Message syntax

A tested subset of ICU MessageFormat:

| Syntax | Use |
|---|---|
| `{name}` | a value, shown as text |
| `{n, number}`, `{r, number, percent}`, `{n, number, integer}` | numbers through `Intl` (`0.35` → `35%`, `%35` in Turkish) |
| `{d, date}`, `{t, time}` | dates and times through `Intl` |
| `{n, plural, =0 {...} one {# day} other {# days}}` | plurals; categories come from `Intl.PluralRules` for the language (`zero`, `one`, `two`, `few`, `many`, `other`); `#` is the number |
| `{k, select, a {...} other {...}}` | choices by a code value; keep the option names exactly as in English |
| `<b>...</b>`, `<link>...</link>` | the only rich-text tags; keep them as in English |
| `''` / `'{'` | an apostrophe / literal braces |

Native (Rust) messages use plain `{name}` placeholders only.

Money is never written in messages: amounts are formatted from the server's decimal strings in US dollars and passed
in as values.

## What stays English

- The hardware-identifier consent text and other texts the agent sends (they are versioned with vault). The app
  shows a short translated note that the English text is binding.
- Messages from the agent or the server without a mapped code, and the update policy's security reasons inside
  the translated update errors.
- The word typed to confirm removing a device (`REMOVE`).

## Checks

```
node pool-app/tests/i18n.test.js          # keys, ICU arguments, plural categories, glossary, identical-to-English
node pool-app/tests/i18n-render.test.js   # render functions in every locale: no raw keys or leftovers, lang/dir
cargo test -p pool-app i18n               # native lookup: fallback to English, unknown locale is English
```
