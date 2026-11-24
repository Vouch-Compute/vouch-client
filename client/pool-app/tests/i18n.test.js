// Structure check for every locale, UI (ui/locales) and native (src-tauri/locales). Run: node pool-app/tests/i18n.test.js
// For each locale against en: the same keys, no empty values, the same ICU arguments, tags and select options,
// messages that parse, plural categories valid for the language, protected terms kept, no crypto vocabulary, and
// strings identical to English flagged unless the locale is still waiting for translators or the key is allow-listed.
// Also: the registry in i18n.js matches the files and the Rust registry, and every key is used (and every used key exists).
const fs = require("fs");
const path = require("path");
const { I18N, APP_JS, UI, NATIVE, uiMessages, nativeMessages } = require("./ui-loader.js");

// Locales whose files are still copies of English. Translators remove a locale from this list when they deliver it;
// from then on every string identical to English fails unless it is in SAME_AS_ENGLISH below.
const NOT_YET_TRANSLATED = [];

// Keys that may legitimately read the same as English in a translated locale (names, symbols, placeholders only).
const SAME_AS_ENGLISH = {
  "*": ["common.range", "common.unit.celsius", "hw.vram", "hw.gigabytes", "schedule.window", "tray.tooltip", "hw.backend.directml", "hw.backend.cuda", "hw.backend.metal"],
  tr: ["reliability.tier.premium", "reliability.bonusLabel"],
  es: ["reliability.tier.premium", "home.hardware.title", "common.unit.min", "common.duration.minutes", "common.duration.hoursMinutes"],
  "pt-BR": ["reliability.tier.premium", "home.hardware.title", "home.status", "common.unit.min", "common.duration.minutes", "common.duration.hoursMinutes"],
  fr: ["reliability.tier.premium", "reliability.tier.stable", "reliability.bonusLabel", "common.unit.min"],
  de: ["reliability.tier.premium", "reliability.bonusLabel", "home.hardware.title", "home.status", "hero.offline.title", "device.sandbox",
    "settings.theme.system", "settings.about.build"],
  id: ["reliability.tier.premium", "reliability.bonusLabel", "home.status", "home.mode", "device.sandbox"],
};

// Never translated (glossary): kept exactly wherever the English message has them.
const PROTECTED = ["Vouch Compute", "Airtm", "OpenRouter", "API", "USD", "US$", "Windows Hello", "Windows", "macOS", "Linux", "Apple Silicon",
  "NVIDIA", "CUDA", "Metal", "DirectML", "TPM", "TOTP", "2FA", "HTTPS"];
const protectedIn = (s) => PROTECTED.filter((p) => new RegExp(`(^|[^A-Za-z])${p.replace(/[$]/g, "\\$")}([^A-Za-z]|$)`).test(s));

// Crypto vocabulary is forbidden in every language (glossary). "wallet" only as "e-wallet" (and its translations).
const FORBIDDEN = [/\bUSDC\b/i, /\bsolana\b/i, /blockchain/i, /airdrop/i, /\bstak(e|ing)\b/i, /gas fee/i, /\bcrypto/i, /\bcoins?\b/i,
  /\bmin(ing|er|ers)\b/i, /(?<!e-)\bwallets?\b/i, /\btokens?\b/i,
  /kripto/i, /madenc/i, /(?<!e-)cüzdan/i, /blok ?zincir/i, /\bjeton/i, // tr
  /cripto/i, /minería|mineração|minage/i, /Kryptow/i, /Mining/i, // es, pt, fr, de
  /加密货币|挖矿|区块链|钱包地址/, /暗号資産|仮想通貨|マイニング|ブロックチェーン/, /암호화폐|채굴|블록체인/, /क्रिप्टो|माइनिंग|ब्लॉकचेन/,
  /عملة مشفرة|العملات المشفرة|تعدين|بلوك ?تشين/];

// "token" in the AI sense (glossary: allowed only in that sense): only these keys, and only next to the hint that says
// what it means (perf.tokenHint). Every other crypto word stays forbidden in them too.
const AI_TOKEN_KEYS = new Set(["perf.tokensPerSecond", "perf.tokenHint"]);
const TOKEN_WORDS = new Set([String(/\btokens?\b/i), String(/\bjeton/i)]);
let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };

// ICU signature of a message: arguments (name:type), tags, select options, and plural option sets.
function signature(ast) {
  const sig = { args: new Set(), tags: [], selects: {}, plurals: [] };
  const walk = (nodes) => {
    for (const n of nodes) {
      if (typeof n === "string" || n.type === "pound") continue;
      if (n.type === "tag") { sig.tags.push(n.name); walk(n.children); continue; }
      sig.args.add(`${n.name}:${n.type === "arg" ? n.format || "text" : n.type}${n.style ? ":" + n.style : ""}`);
      if (n.type === "select") sig.selects[n.name] = Object.keys(n.options).sort().join("|");
      if (n.type === "plural") sig.plurals.push(Object.keys(n.options));
      if (n.options) for (const o of Object.values(n.options)) walk(o);
    }
  };
  walk(ast);
  sig.tags.sort();
  return sig;
}
const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

function textOf(ast) {
  // the visible text of every branch, for the glossary checks
  return ast.map((n) => (typeof n === "string" ? n : n.children ? textOf(n.children) : n.options ? Object.values(n.options).map(textOf).join(" ") : "")).join("");
}

function checkSide(side, load) {
  const en = I18N.flatten(load("en"));
  const enKeys = Object.keys(en).sort();
  const enAst = {};
  for (const k of enKeys) {
    if (typeof en[k] !== "string" || !en[k].trim()) { fail(`${side} en ${k}: empty or not a string`); continue; }
    try { enAst[k] = I18N.parse(en[k]); } catch (e) { fail(`${side} en ${k}: ${e.message}`); }
  }
  for (const { code } of I18N.LOCALES) {
    let msgs;
    try { msgs = I18N.flatten(load(code)); } catch (e) { fail(`${side} ${code}: cannot read: ${e.message}`); continue; }
    const keys = Object.keys(msgs).sort();
    for (const k of enKeys) if (!(k in msgs)) fail(`${side} ${code}: missing ${k}`);
    for (const k of keys) if (!(k in en)) fail(`${side} ${code}: extra key ${k}`);
    const categories = new Intl.PluralRules(code).resolvedOptions().pluralCategories;
    const allowSame = new Set([...(SAME_AS_ENGLISH["*"] || []), ...(SAME_AS_ENGLISH[code] || [])]);
    for (const k of keys) {
      const v = msgs[k];
      if (typeof v !== "string" || !v.trim()) { fail(`${side} ${code} ${k}: empty or not a string`); continue; }
      let ast;
      try { ast = I18N.parse(v); } catch (e) { fail(`${side} ${code} ${k}: ${e.message}`); continue; }
      const text = textOf(ast);
      for (const re of FORBIDDEN) {
        if (side === "ui" && AI_TOKEN_KEYS.has(k) && TOKEN_WORDS.has(String(re))) continue;
        if (re.test(text)) fail(`${side} ${code} ${k}: forbidden crypto vocabulary ${re}: ${v}`);
      }
      if (!enAst[k]) continue;
      const a = signature(ast), b = signature(enAst[k]);
      if (!same(a.args, b.args)) fail(`${side} ${code} ${k}: arguments ${[...a.args]} differ from en ${[...b.args]}`);
      if (a.tags.join() !== b.tags.join()) fail(`${side} ${code} ${k}: tags ${a.tags} differ from en ${b.tags}`);
      if (JSON.stringify(a.selects) !== JSON.stringify(b.selects)) fail(`${side} ${code} ${k}: select options differ from en`);
      for (const opts of a.plurals) {
        // copies of English keep its categories until translated; a delivered translation uses only its own
        if (NOT_YET_TRANSLATED.includes(code)) continue;
        for (const o of opts) if (!o.startsWith("=") && !categories.includes(o)) fail(`${side} ${code} ${k}: plural category "${o}" is not used by ${code}`);
      }
      for (const p of protectedIn(textOf(enAst[k]))) if (!text.includes(p)) fail(`${side} ${code} ${k}: protected term "${p}" missing`);
      if (code !== "en" && v === en[k] && !NOT_YET_TRANSLATED.includes(code) && !allowSame.has(k)) fail(`${side} ${code} ${k}: identical to English`);
    }
  }
  return enKeys;
}

const uiKeys = checkSide("ui", uiMessages);
const nativeKeys = checkSide("native", nativeMessages);

// files <-> registries
const files = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
const codes = I18N.LOCALES.map((l) => l.code).sort();
if (!same(files(path.join(UI, "locales")), codes)) fail(`ui/locales files ${files(path.join(UI, "locales"))} differ from the registry ${codes}`);
if (!same(files(NATIVE), codes)) fail(`src-tauri/locales files differ from the registry`);
const I18N_RS = fs.readFileSync(path.join(__dirname, "..", "src-tauri", "src", "i18n.rs"), "utf8");
const rsReg = /registry!\(([^)]*)\)/.exec(I18N_RS);
const rsCodes = rsReg ? [...rsReg[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
if (JSON.stringify(rsCodes) !== JSON.stringify(I18N.LOCALES.map((l) => l.code))) fail(`Rust registry ${rsCodes} differs from i18n.js ${I18N.LOCALES.map((l) => l.code)}`);
for (const l of I18N.LOCALES) {
  if (!["ltr", "rtl"].includes(l.dir) || !l.name) fail(`registry entry ${l.code}`);
  if (I18N.resolve(l.code) !== l.code) fail(`registry code ${l.code} does not resolve to itself`);
}
if (I18N.info("ar").dir !== "rtl") fail("ar must be right-to-left");

// the locale matcher: allow-list only
for (const [tags, want] of [[["pt-PT"], "pt-BR"], [["zh-TW"], "zh-CN"], [["zh"], "zh-CN"], [["tr-TR"], "tr"], [["xx", "de-AT"], "de"],
  [["../en"], null], [["en;q=1"], null], [[null, 3, {}], null], [["ar-EG"], "ar"], [["EN-gb"], "en"]]) {
  if (I18N.match(tags) !== want) fail(`match(${JSON.stringify(tags)}) = ${I18N.match(tags)}, want ${want}`);
}

// keys used in the sources exist, and every key is used
const INDEX = fs.readFileSync(path.join(UI, "index.html"), "utf8");
// the page loads the formatter first and then the app (both deferred, so in document order)
if (JSON.stringify([...INDEX.matchAll(/<script src="([^"]+)" defer><\/script>/g)].map((m) => m[1])) !== '["i18n.js","app.js"]'
  || (INDEX.match(/<script/g) || []).length !== 2) fail("index.html must load i18n.js and then app.js");
const SRC = path.join(__dirname, "..", "src-tauri", "src");
const RUST = fs.readdirSync(SRC).filter((f) => f.endsWith(".rs")).map((f) => fs.readFileSync(path.join(SRC, f), "utf8")).join("\n");
for (const k of uiKeys) if (!APP_JS.includes(`"${k}"`) && !INDEX.includes(`"${k}"`) && !INDEX.includes(`:${k}`)) fail(`ui key ${k} is not used in app.js or index.html`);
for (const k of nativeKeys) if (!RUST.includes(`"${k}"`)) fail(`native key ${k} is not used in src-tauri/src`);
const CORE_RS = fs.readFileSync(path.join(SRC, "core_client.rs"), "utf8");
const AGENT_METHODS = new Set([...CORE_RS.slice(CORE_RS.indexOf("pub const ALLOWED")).split("];")[0].matchAll(/"([^"]+)"/g)].map((m) => m[1]));
const KEYISH = /"((?:[a-z][A-Za-z0-9]*)(?:\.[a-z][A-Za-z0-9]*)+)"/g;
const uiSet = new Set(uiKeys);
const NS = new Set(uiKeys.map((k) => k.split(".")[0]));
for (const m of APP_JS.matchAll(KEYISH)) if (NS.has(m[1].split(".")[0]) && !uiSet.has(m[1]) && !AGENT_METHODS.has(m[1]) && !/\.(json|js|css|html)$/.test(m[1])) fail(`app.js uses unknown key ${m[1]}`);
for (const m of INDEX.matchAll(/data-i18n="([^"]+)"/g)) if (!uiSet.has(m[1])) fail(`index.html uses unknown key ${m[1]}`);
for (const m of INDEX.matchAll(/data-i18n-attr="([^"]+)"/g)) for (const pair of m[1].split(";")) { const k = pair.split(":")[1]; if (!uiSet.has(k)) fail(`index.html uses unknown key ${k}`); }
const nativeSet = new Set(nativeKeys);
for (const m of RUST.matchAll(/i18n::tv?\("([^"]+)"/g)) if (!nativeSet.has(m[1])) fail(`Rust uses unknown key ${m[1]}`);
for (const m of RUST.matchAll(/i18n::t\(if [^{]+\{ "([^"]+)" \} else \{ "([^"]+)" \}/g)) for (const k of [m[1], m[2]]) if (!nativeSet.has(k)) fail(`Rust uses unknown key ${k}`);

// the ICU subset itself
const t = (msg, vars, code) => I18N.create(code || "en", { m: msg }, {}).t("m", vars);
const cases = [
  ["{n, plural, =0 {none} one {# item} other {# items}}", { n: 0 }, "none"],
  ["{n, plural, =0 {none} one {# item} other {# items}}", { n: 1 }, "1 item"],
  ["{n, plural, =0 {none} one {# item} other {# items}}", { n: 1234 }, "1,234 items"],
  ["{g, select, a {Alpha} other {Other}}", { g: "a" }, "Alpha"],
  ["{g, select, a {Alpha} other {Other}}", { g: "zzz" }, "Other"],
  ["Don't {x}", { x: "<b>" }, "Don't <b>"],
  ["'{'literal'}' and ''", {}, "{literal} and '"],
  ["{r, number, percent}", { r: 0.46 }, "46%"],
  ["{r, number, percent}", { r: 0.46 }, "%46", "tr"],
  ["{n, number}", { n: null }, "—"],
  ["{missing}", {}, "{missing}"],
  ["<b>Bold</b> <link>x</link>", {}, "Bold x"],
  ["{n, plural, one {# день} few {# дня} many {# дней} other {# дня}}", { n: 3 }, "3 дня", "ru"],
  ["{n, plural, zero {zero} one {one} two {two} few {few} many {many} other {other}}", { n: 2 }, "two", "ar"],
];
for (const [msg, vars, want, code] of cases) {
  const got = t(msg, vars, code);
  if (got !== want) fail(`format ${JSON.stringify(msg)} ${JSON.stringify(vars)} (${code || "en"}): got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}
const r = I18N.create("en", { m: "Verified: <b>{amount}</b> on the <link>web</link>" }, {})
  .rich("m", { amount: "<img src=x>" }, { b: (x) => `<strong>${x}</strong>`, link: (x) => `<button>${x}</button>` });
if (r !== "Verified: <strong>&lt;img src=x&gt;</strong> on the <button>web</button>") fail(`rich: ${r}`);
const r2 = I18N.create("en", { m: "<script>x</script> & <i>" }, {}).rich("m", {}, {});
if (r2 !== "&lt;script&gt;x&lt;/script&gt; &amp; &lt;i&gt;") fail(`rich escapes text outside the reviewed tags: ${r2}`);
for (const broken of ["{", "{n, plural, one {x}}", "{n, plural, one {x} other {y}", "<b>open", "a </link>", "{n, foo}", "{n, number, money}", "'{unterminated", "{n, select, a {x} a {y} other {z}}"]) {
  let threw = false;
  try { I18N.parse(broken); } catch { threw = true; }
  if (!threw) fail(`parse accepted ${JSON.stringify(broken)}`);
}
// a broken translation falls back to English; a missing key shows the key
const fb = I18N.create("tr", { a: "{broken", b: "B-tr" }, { a: "A-en", b: "B-en", c: "C-en" });
if (fb.t("a") !== "A-en" || fb.t("b") !== "B-tr" || fb.t("c") !== "C-en" || fb.t("nope.key") !== "nope.key") fail("fallback to English");

console.log(bad ? `${bad} failures` : `i18n: ${I18N.LOCALES.length} locales, ${uiKeys.length} UI keys and ${nativeKeys.length} native keys pass (${NOT_YET_TRANSLATED.length} locales not yet translated)`);
process.exit(bad ? 1 : 0);
