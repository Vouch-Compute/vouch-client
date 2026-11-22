// Vouch Compute UI strings: the locale registry, ICU-subset messages and Intl formatting. No dependencies. Loaded
// before app.js in the window (as `I18N`) and with require() by the node tests.
//
// Message syntax (a tested subset of ICU MessageFormat):
//   {name}                                  a value, as text
//   {n, number} {n, number, percent} {n, number, integer}
//   {d, date} {t, time}
//   {n, plural, =0 {none} one {# item} other {# items}}   (categories from Intl.PluralRules; # is the number)
//   {k, select, a {...} other {...}}
//   <b>...</b> <link>...</link>             the reviewed rich-text tags, only through rich()
//   '' is an apostrophe; '{' ... '}' quotes braces. A lone ' is literal text.
// Values and messages are text. Only rich() returns HTML: it escapes every text part and value, and the caller
// supplies the markup for the reviewed tags.
(function (root) {
  "use strict";

  // Adding a language: one entry here, ui/locales/<code>.json and src-tauri/locales/<code>.json (see locales/README.md).
  const LOCALES = [
    { code: "en", name: "English", dir: "ltr" },
    { code: "tr", name: "Türkçe", dir: "ltr" },
    { code: "es", name: "Español", dir: "ltr" },
    { code: "pt-BR", name: "Português (Brasil)", dir: "ltr" },
    { code: "fr", name: "Français", dir: "ltr" },
    { code: "de", name: "Deutsch", dir: "ltr" },
    { code: "zh-CN", name: "简体中文", dir: "ltr" },
    { code: "ja", name: "日本語", dir: "ltr" },
    { code: "ko", name: "한국어", dir: "ltr" },
    { code: "hi", name: "हिन्दी", dir: "ltr" },
    { code: "id", name: "Bahasa Indonesia", dir: "ltr" },
    { code: "ar", name: "العربية", dir: "rtl" },
  ];
  const DEFAULT = "en";
  const TAGS = ["b", "link"];
  const TYPES = ["number", "date", "time", "plural", "select"];
  const ATTRS = ["aria-label", "title", "alt", "placeholder"];

  // Best registry match for a list of language tags ("pt-PT" -> "pt-BR", "zh-TW" -> "zh-CN"), or null. Anything
  // that is not a well-formed tag is ignored, so a stored or reported value can never select something outside the
  // registry.
  function match(tags) {
    for (const raw of [].concat(tags == null ? [] : tags)) {
      if (typeof raw !== "string" || !/^[A-Za-z]{2,3}([-_][A-Za-z0-9]{1,8})*$/.test(raw.trim())) continue;
      const tag = raw.trim().replace(/_/g, "-").toLowerCase();
      const exact = LOCALES.find((l) => l.code.toLowerCase() === tag);
      if (exact) return exact.code;
      const lang = tag.split("-")[0];
      const same = LOCALES.find((l) => l.code.toLowerCase().split("-")[0] === lang);
      if (same) return same.code;
    }
    return null;
  }
  const resolve = (tag) => match([tag]) || DEFAULT;
  const info = (code) => LOCALES.find((l) => l.code === code) || LOCALES[0];

  // {"a": {"b": "x"}} -> {"a.b": "x"}
  function flatten(obj, prefix, out) {
    const o = out || {};
    for (const [k, v] of Object.entries(obj || {})) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === "object" && !Array.isArray(v)) flatten(v, key, o);
      else o[key] = v;
    }
    return o;
  }

  // ------------------------------------------------------------------ parser
  function parse(message) {
    const s = String(message);
    let i = 0;
    const fail = (m) => { throw new SyntaxError(`${m} at ${i} in ${JSON.stringify(s)}`); };
    const ws = () => { while (i < s.length && /\s/.test(s[i])) i++; };
    const word = () => {
      const m = /^[A-Za-z0-9_]+/.exec(s.slice(i));
      if (!m) fail("expected a name");
      i += m[0].length;
      return m[0];
    };
    function nodes(inPlural, end) {
      const out = [];
      let text = "";
      const flush = () => { if (text) { out.push(text); text = ""; } };
      while (i < s.length) {
        const c = s[i];
        if (c === "'") {
          const n = s[i + 1];
          if (n === "'") { text += "'"; i += 2; continue; }
          if (n === "{" || n === "}" || n === "<" || (inPlural && n === "#")) {
            const close = s.indexOf("'", i + 1);
            if (close < 0) fail("unterminated quote");
            text += s.slice(i + 1, close);
            i = close + 1;
            continue;
          }
          text += c; i++; continue;
        }
        if (c === "{") { flush(); i++; out.push(argument(inPlural)); continue; }
        if (c === "}") {
          if (end === "}") { flush(); return out; }
          fail("unexpected }");
        }
        if (c === "#" && inPlural) { flush(); out.push({ type: "pound" }); i++; continue; }
        if (c === "<") {
          const m = /^<(\/?)([a-z]+)>/.exec(s.slice(i));
          if (m && TAGS.includes(m[2])) {
            flush();
            i += m[0].length;
            if (m[1]) {
              if (end === `</${m[2]}>`) return out;
              fail(`unexpected </${m[2]}>`);
            }
            out.push({ type: "tag", name: m[2], children: nodes(inPlural, `</${m[2]}>`) });
            continue;
          }
        }
        text += c; i++;
      }
      if (end) fail(`missing ${end}`);
      flush();
      return out;
    }
    function argument(inPlural) {
      ws();
      const name = word();
      ws();
      if (s[i] === "}") { i++; return { type: "arg", name }; }
      if (s[i] !== ",") fail("expected , or }");
      i++; ws();
      const type = word();
      if (!TYPES.includes(type)) fail(`unknown type ${type}`);
      ws();
      if (type === "number" || type === "date" || type === "time") {
        let style = null;
        if (s[i] === ",") { i++; ws(); style = word(); ws(); }
        if (type === "number" && style && !["percent", "integer"].includes(style)) fail(`unknown number style ${style}`);
        if (s[i] !== "}") fail("expected }");
        i++;
        return { type: "arg", name, format: type, style };
      }
      if (s[i] !== ",") fail("expected ,");
      i++;
      const options = {};
      for (;;) {
        ws();
        if (s[i] === "}") { i++; break; }
        let key;
        if (s[i] === "=") { i++; key = `=${word()}`; if (!/^=\d+$/.test(key)) fail("bad exact value"); }
        else key = word();
        if (key in options) fail(`duplicate option ${key}`);
        ws();
        if (s[i] !== "{") fail("expected {");
        i++;
        options[key] = nodes(type === "plural" ? true : inPlural, "}");
        i++; // the closing }
      }
      if (!("other" in options)) fail(`${type} without other`);
      return { type, name, options };
    }
    const ast = nodes(false, null);
    return ast;
  }

  // ------------------------------------------------------------------ formatting
  const cache = new Map();
  function cached(kind, locale, opts, make) {
    const k = `${kind}|${locale}|${JSON.stringify(opts || {})}`;
    if (!cache.has(k)) cache.set(k, make());
    return cache.get(k);
  }
  const numberFormat = (locale, opts) => cached("n", locale, opts, () => new Intl.NumberFormat(locale, opts));
  const pluralRules = (locale) => cached("p", locale, null, () => new Intl.PluralRules(locale));

  function fmtFor(locale) {
    const validDate = (v) => { const d = v instanceof Date ? v : new Date(v); return Number.isNaN(d.getTime()) ? null : d; };
    return {
      number(x, opts) {
        const n = typeof x === "number" ? x : x === null || x === undefined || x === "" ? NaN : Number(x);
        return Number.isFinite(n) ? numberFormat(locale, opts).format(n) : "—";
      },
      date(v, opts) {
        const d = v === null || v === undefined || v === "" ? null : validDate(v);
        return d ? d.toLocaleDateString(locale, opts || { year: "numeric", month: "short", day: "numeric" }) : "—";
      },
      time(v) {
        const d = v === null || v === undefined || v === "" ? null : validDate(v);
        return d ? d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" }) : "—";
      },
      relative(value, unit) {
        const n = Number(value);
        return Number.isFinite(n) ? cached("r", locale, unit, () => new Intl.RelativeTimeFormat(locale, { numeric: "auto" })).format(n, unit) : "—";
      },
      // 0 = Monday ... 6 = Sunday (the agent's schedule bits)
      weekday(i) {
        return cached("w", locale, null, () => new Intl.DateTimeFormat(locale, { weekday: "short", timeZone: "UTC" })).format(Date.UTC(2024, 0, 1 + (Number(i) % 7)));
      },
      list(items) {
        return cached("l", locale, null, () => new Intl.ListFormat(locale, { type: "conjunction", style: "long" })).format(items.map(String));
      },
    };
  }

  function render(ast, vars, locale, out) {
    const v = vars || {};
    const fmt = fmtFor(locale);
    const e = out.esc;
    const walk = (list, pound) => list.map((n) => {
      if (typeof n === "string") return e(n);
      if (n.type === "pound") return e(fmt.number(pound));
      if (n.type === "tag") return out.tag(n.name, walk(n.children, pound));
      // undefined is a missing value (shown as {name}, which the tests catch); null is a known "no value" (shown as —)
      const has = Object.prototype.hasOwnProperty.call(v, n.name) && v[n.name] !== undefined;
      const x = has ? v[n.name] : undefined;
      if (n.type === "arg") {
        if (!has) return e(`{${n.name}}`);
        if (x === null) return e("—");
        if (n.format === "number") {
          const opts = n.style === "percent" ? { style: "percent", maximumFractionDigits: 0 } : n.style === "integer" ? { maximumFractionDigits: 0 } : undefined;
          return e(fmt.number(x, opts));
        }
        if (n.format === "date") return e(fmt.date(x));
        if (n.format === "time") return e(fmt.time(x));
        return e(String(x));
      }
      if (n.type === "plural") {
        const num = x === undefined || x === null || x === "" ? NaN : Number(x);
        const exact = n.options[`=${num}`];
        const cat = Number.isFinite(num) ? pluralRules(locale).select(num) : "other";
        return walk(exact || n.options[cat] || n.options.other, num);
      }
      // select
      const key = x === undefined || x === null ? "other" : String(x);
      return walk(Object.prototype.hasOwnProperty.call(n.options, key) ? n.options[key] : n.options.other, pound);
    }).join("");
    return walk(ast, NaN);
  }

  const escHtml = (x) =>
    String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const PLAIN = { esc: (x) => x, tag: (_name, inner) => inner };

  // ------------------------------------------------------------------ catalogues
  function create(code, messages, fallback) {
    const locale = resolve(code);
    const msgs = flatten(messages);
    const fb = flatten(fallback);
    const asts = new Map();
    const ast = (key) => {
      if (asts.has(key)) return asts.get(key);
      let a = null;
      for (const src of [msgs[key], fb[key]]) {
        if (typeof src !== "string" || src === "") continue;
        try { a = parse(src); break; } catch { /* a broken translation falls back to English */ }
      }
      asts.set(key, a);
      return a;
    };
    return {
      locale,
      dir: info(locale).dir,
      has: (key) => ast(key) !== null,
      // a missing key shows the key itself, which the render tests catch
      t: (key, vars) => { const a = ast(key); return a ? render(a, vars, locale, PLAIN) : key; },
      rich(key, vars, tags) {
        const a = ast(key);
        if (!a) return escHtml(key);
        const handlers = tags || {};
        return render(a, vars, locale, { esc: escHtml, tag: (name, inner) => (typeof handlers[name] === "function" ? handlers[name](inner) : inner) });
      },
      fmt: fmtFor(locale),
    };
  }

  // The active catalogue (one per window).
  let active = create(DEFAULT, {}, {});
  function use(code, messages, fallback) {
    active = create(code, messages, fallback);
    if (typeof document !== "undefined" && document.documentElement) {
      document.documentElement.lang = active.locale;
      document.documentElement.dir = active.dir;
    }
    return active.locale;
  }
  const fmt = {};
  for (const k of Object.keys(fmtFor(DEFAULT))) fmt[k] = (...a) => active.fmt[k](...a);

  // Static strings in index.html: data-i18n="key" sets the text, data-i18n-attr="title:key;aria-label:key" sets
  // allow-listed attributes. Always as text, never as HTML.
  function applyDom(rootEl) {
    for (const el of rootEl.querySelectorAll("[data-i18n]")) el.textContent = active.t(el.getAttribute("data-i18n"));
    for (const el of rootEl.querySelectorAll("[data-i18n-attr]")) {
      for (const pair of el.getAttribute("data-i18n-attr").split(";")) {
        const [attr, key] = pair.split(":").map((x) => x.trim());
        if (ATTRS.includes(attr) && key) el.setAttribute(attr, active.t(key));
      }
    }
  }

  const api = {
    LOCALES, DEFAULT, TAGS, match, resolve, info, flatten, parse, create, use, applyDom, fmt,
    t: (key, vars) => active.t(key, vars),
    rich: (key, vars, tags) => active.rich(key, vars, tags),
    locale: () => active.locale,
    dir: () => active.dir,
  };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.I18N = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
