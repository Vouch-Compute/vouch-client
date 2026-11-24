// Rendered check per locale: the pure render functions of app.js run in every locale, and the output has no raw
// message keys, no "undefined", "NaN", "null" or unfilled "{...}" placeholders, and the document gets lang and dir
// (right-to-left for Arabic). Run: node pool-app/tests/i18n-render.test.js
const { I18N, uiMessages, useLocale, loadSection } = require("./ui-loader.js");

// a stand-in for the document, so use() can set lang and dir as it does in the window
globalThis.document = { documentElement: {} };

const names = ["heroState", "pilotHtml", "estimateHtml", "earningsHtml", "walletHtml", "deviceHeadHtml", "deviceStateText", "hardwareHtml", "legalAcceptHtml", "signinTermsHtml",
  "consentHtml", "benchHtml", "duration", "reliabilityHtml", "stepsHtml", "noticesHtml", "clockHtml", "heroActionHtml", "controlsHtml",
  "scheduleSummary", "languageHtml", "daysText", "perfHtml", "measuredText"];
const api = loadSection("// ---- pure (start)", "// ---- pure (end)", names);
const keys = Object.keys(I18N.flatten(uiMessages("en")));

let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };
const now = Date.UTC(2026, 10, 20, 12, 0, 0);
const settings = { mode: "idle_only", idle_minutes: 10, temp_cap_c: 80, power_pct: 90, paused_until_ms: null, daily_cap_hours: 8,
  schedule: [{ days: 31, start_min: 1320, end_min: 420 }, { days: 96, start_min: 0, end_min: 600 }, { days: 5, start_min: 60, end_min: 120 }] };
const snap = (status, extra) => ({ settings: { ...settings, ...(extra && extra.settings) }, ...extra,
  status: { connection: "connected", decision: { state: "run" }, job: null, notices: {}, ...status } });

const heroInputs = [
  null, { error: "agent not running" },
  snap({ connection: "not_signed_in" }), snap({ connection: "auth_failed" }), snap({ connection: "offline", reconnect_in_s: 1 }),
  snap({ connection: "offline", reconnect_in_s: 12 }), snap({ connection: "connecting" }), snap({ connection: "not_enrolled" }),
  snap({ connection: "update_required" }), snap({ connection: "revoked" }), snap({ job: { model_id: "whisper-small" } }), snap({ job: {} }),
  snap({ benchmark: { state: "running" } }), snap({ notices: { paused_by: "tally" } }), snap({ notices: { paused_by: "user" } }),
  snap({ decision: { state: "pause", reason: "paused_by_user" } }, { settings: { paused_until_ms: now + 3600e3 } }),
  snap({ decision: { state: "pause", reason: "paused_by_user" } }),
  ...["user_active", "fullscreen", "on_battery", "battery_low", "thermal", "outside_schedule", "daily_cap_reached", "unknown"].map((reason) =>
    snap({ decision: { state: "pause", reason } })),
  snap({ decision: { state: "pause", reason: "user_active" } }, { settings: { idle_minutes: 1 } }),
  snap({ decision: { state: "pause", reason: "thermal" } }, { settings: { temp_cap_c: null } }),
];
const estimate = { ok: { low_usd: "9.000000000", high_usd: "24.000000000", base: { low_usd: "3.500000000", high_usd: "9.000000000" },
  multiplier: 3, multiplier_end: "2027-03-01T00:00:00Z", assumptions: { utilization: 0.35, hours_per_day: 14, electricity_usd_per_kwh: 0.15, avg_watts: 180, electricity_cost_usd: "4.100000000" } } };
const estimateNoBonus = { ok: { low_usd: "1.000000000", high_usd: "2.000000000", base: { low_usd: "1.000000000", high_usd: "2.000000000" }, multiplier: 1, assumptions: {} } };
const earnings = { as_of: "2026-11-17", totals: { pending: "2.310000000", in_escrow: "6.870000000", in_review: "0.120000000", releasable: "1.250000000", sent: "4.800000000", clawed_back: "0" },
  this_week_verified_usd: "3.100000000", probation: { active: true, escrow_days: 21, ends_on: "2026-12-05" }, alerts: [] };

function render() {
  const out = [];
  for (const s of heroInputs) { const h = api.heroState(s, now); out.push(h.title, h.sub, api.heroActionHtml(h)); }
  out.push(api.pilotHtml({ pilot: true }), api.estimateHtml(null), api.estimateHtml({ err: "offline" }), api.estimateHtml(estimate), api.estimateHtml(estimateNoBonus));
  out.push(api.earningsHtml(earnings), api.earningsHtml({ ...earnings, probation: { active: true, escrow_days: 1 } }), api.earningsHtml(null));
  out.push(api.walletHtml([]), api.walletHtml([{ chain: "bank", address: "DE89370400440532013000", status: "active", payout_freeze_until: "2099-01-01" }]));
  for (const d of [null, { name: "PC", connection: "online", activity: "working", paused_by: "user" }, { connection: "offline", activity: "idle", paused_by: "tally" }, { connection: "online" }]) {
    out.push(api.deviceHeadHtml(d), api.deviceStateText(d));
  }
  out.push(api.hardwareHtml({ gpu: "RTX 4070", cpu: "Ryzen", ram_mb: 32768, vram_mb: 12282 }, "candle-cuda", "tpm"), api.hardwareHtml({}, null, "software"), api.hardwareHtml(null, "candle-cpu"));
  out.push(api.consentHtml(null), api.consentHtml({ text: "The binding text.", version: "v1", refused_message: "No." }, "refused"));
  out.push(api.benchHtml(null, now, false), api.benchHtml({ state: "running", started_ms: now - 600e3, duration_s: 1200, segments: 1 }, now, true),
    api.benchHtml({ state: "running", started_ms: now - 600e3, duration_s: 1200, segments: 46 }, now, false), api.benchHtml({ state: "sent" }, now, false), api.benchHtml({ state: "x" }, now, false));
  out.push(api.duration(5400), api.duration(60), api.duration(null));
  const m = { unit: "token", per_second: 418.26, runs: 470, backend: "onnxruntime-cpu" };
  out.push(api.benchHtml({ state: "received", measured: m }, now, false),
    api.benchHtml({ state: "running", started_ms: now - 600e3, duration_s: 1200, segments: 10, measured: { ...m, unit: "audio_second", per_second: 31 } }, now, false));
  for (const [status, tier] of [["benchmarking", "probation"], ["probation", "probation"], ["active", "established"], ["limited", "trusted"], ["suspended", "x"], ["revoked", null]]) {
    out.push(api.perfHtml([{ model_id: "bge-m3", measured: m, finished_ms: now, received: status === "active" }, { model_id: "whisper-small", measured: { unit: "audio_second", per_second: 31, backend: null }, finished_ms: now }],
      { status, tier, benchmark_date: status === "active" ? "2026-11-24" : null }, false));
  }
  out.push(api.perfHtml([], null, true), api.perfHtml(null, null, false));
  out.push(api.reliabilityHtml(null), api.reliabilityHtml({ tier: "stable", since_day: "2026-11-12", benefits: { queue_priority: "higher", bonus_pct: 5 },
    improve: ["keep_regular_hours", "avoid_disconnects", "finish_accepted_jobs", "build_tenure", "verify_identity", "use_hardware_key"] }),
  api.reliabilityHtml({ tier: "probation", benefits: { bonus_pct: 0 }, improve: [] }));
  for (const st of ["welcome", "signin", "consent", "device"]) out.push(api.stepsHtml(st));
  out.push(api.noticesHtml({ paused_by: "user", recovery_in_progress: true, reverify_required: true }), api.noticesHtml({ paused_by: "tally" }));
  out.push(api.clockHtml(7), api.clockHtml(-1), api.clockHtml(-600), api.clockHtml(61));
  out.push(api.controlsHtml(settings), api.controlsHtml({ ...settings, schedule: [] }), api.controlsHtml(null));
  out.push(...api.scheduleSummary(settings.schedule), api.daysText(127), api.daysText(0), api.daysText(1));
  out.push(api.languageHtml(null, "tr", I18N.LOCALES), api.languageHtml("ar", "en", I18N.LOCALES));
  return out;
}

const keyRe = new RegExp(`(^|[^A-Za-z0-9_.])(${keys.map((k) => k.replace(/\./g, "\\.")).join("|")})([^A-Za-z0-9_.]|$)`);
for (const { code, dir } of I18N.LOCALES) {
  if (useLocale(code) !== code) fail(`${code}: use() resolved to ${I18N.locale()}`);
  if (document.documentElement.lang !== code || document.documentElement.dir !== dir) fail(`${code}: html lang/dir ${document.documentElement.lang}/${document.documentElement.dir}`);
  const html = render().join("\n");
  const m = keyRe.exec(html);
  if (m) fail(`${code}: raw key ${m[2]} in the output`);
  for (const bad of [/undefined/, /\bNaN\b/, /\bnull\b/, /\[object /]) if (bad.test(html)) fail(`${code}: ${bad} in the output: ${html.match(new RegExp(`.{0,60}${bad.source}.{0,30}`))[0]}`);
  // braces only ever come from unfilled placeholders (no icon path or markup uses them)
  const brace = /\{[^}]*\}/.exec(html);
  if (brace) fail(`${code}: unfilled placeholder ${brace[0]}`);
  // money stays USD from the decimal strings in every language
  if (!html.includes("$9.00") || !html.includes("$24.00") || !html.includes("−$4.10")) fail(`${code}: USD amounts`);
  // the consent text stays English and is marked as such, with the binding note outside English
  const consent = api.consentHtml({ text: "The binding text.", version: "v1" }, null);
  if (!consent.includes('lang="en"') || !consent.includes("The binding text.")) fail(`${code}: consent text`);
  if ((code === "en") === consent.includes(I18N.t("consent.englishBinding"))) fail(`${code}: English-binding note`);
  // the device-link acceptance: translated lead-in, English document titles, binding note outside English
  const legal = api.legalAcceptHtml();
  if (!consent.includes(legal)) fail(`${code}: acceptance line on the consent step`);
  if (!legal.includes(I18N.t("legal.linkAccept")) || !legal.includes("Vouch Compute Contributor Agreement") || !legal.includes("Vouch Compute Acceptable Use Policy")) fail(`${code}: acceptance line`);
  if ((code === "en") === legal.includes(I18N.t("legal.englishBinding"))) fail(`${code}: legal English-binding note`);
  // the sign-in line: its own translated lead-in, the same two English document titles and binding note
  const signin = api.signinTermsHtml();
  if (!signin.includes(I18N.t("onboarding.signin.terms")) || !signin.includes("Vouch Compute Contributor Agreement") || !signin.includes("Vouch Compute Acceptable Use Policy")) fail(`${code}: sign-in terms`);
  if ((code === "en") === signin.includes(I18N.t("legal.englishBinding"))) fail(`${code}: sign-in English-binding note`);
  if (/contributor-agreement|vouchcompute\.com/.test(I18N.t("onboarding.signin.terms"))) fail(`${code}: sign-in terms still carry a URL`);
}
if (I18N.dir() !== I18N.info(I18N.locale()).dir) fail("dir()");
useLocale("ar");
if (document.documentElement.dir !== "rtl" || I18N.dir() !== "rtl") fail("ar is right-to-left");
useLocale("tr");
const trHero = api.heroState(snap({ job: { model_id: "whisper-small" } }), now);
if (trHero.title === "Earning" || !trHero.sub.includes("whisper-small")) fail("Turkish hero is translated and keeps the model id");
if (!api.estimateHtml(estimate).includes("%35")) fail("Turkish percent placement from Intl");
useLocale("en");

console.log(bad ? `${bad} failures` : `i18n render: ${I18N.LOCALES.length} locales render cleanly`);
process.exit(bad ? 1 : 0);
