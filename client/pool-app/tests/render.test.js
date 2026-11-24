// Rendering checks for app.js (hero status, escaping, pilot banner, estimate, consent). Run: node pool-app/tests/render.test.js
// Loads the DOM-free "pure" section of app.js, the same way the other UI tests load their sections, in English.
const { useLocale, loadSection } = require("./ui-loader.js");
const names = ["esc", "heroState", "isPilot", "pilotHtml", "estimateHtml", "earningsHtml", "walletHtml", "deviceHeadHtml", "hardwareHtml", "consentHtml", "legalAcceptHtml", "signinTermsHtml", "benchHtml", "sumUsd", "duration", "perfHtml", "measuredText"];
useLocale("en");
const api = loadSection("// ---- pure (start)", "// ---- pure (end)", names);

let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };
const now = Date.UTC(2026, 10, 20, 12, 0, 0);
const settings = { mode: "idle_only", idle_minutes: 10, temp_cap_c: 80, paused_until_ms: null };
const snap = (status, extra) => ({ settings: { ...settings, ...(extra && extra.settings) }, ...extra,
  status: { connection: "connected", decision: { state: "run" }, job: null, notices: {}, ...status } });

// 1. hero status mapping
const hero = (s) => api.heroState(s, now);
const cases = [
  [snap({ job: { model_id: "whisper-small", since_ms: now } }), "earning", "Earning", "pause"],
  [snap({ decision: { state: "pause", reason: "paused_by_user" } }, { settings: { paused_until_ms: now + 3600e3 } }), "paused", "Paused", "resume"],
  [snap({ notices: { paused_by: "user" } }), "paused", "Paused", "resume-server"],
  [snap({ decision: { state: "run" } }), "idle", "Idle, waiting for jobs", "pause"],
  [snap({ connection: "offline", reconnect_in_s: 12 }), "offline", "Offline", "reconnect"],
  [snap({ connection: "not_signed_in" }), "signed_out", "Signed out", "signin"],
  [snap({ connection: "auth_failed" }), "signed_out", "Signed out", "signin"],
  [{ error: "agent not running" }, "down", "Agent not running", "start"],
  [null, "loading", "Starting…", null],
];
for (const [s, key, title, action] of cases) {
  const h = hero(s);
  if (h.key !== key || h.title !== title || h.action !== action) fail(`hero ${key}: got ${JSON.stringify(h)}`);
}
// the internal wire value "tally" means "Paused by Vouch Compute"; the app offers no resume for it
const tally = hero(snap({ notices: { paused_by: "tally" } }));
if (tally.key !== "paused" || !tally.sub.includes("Paused by Vouch Compute") || tally.action !== null) fail("tally pause");
// an expired local pause is not "paused"
if (hero(snap({}, { settings: { paused_until_ms: now - 1000 } })).key !== "idle") fail("expired pause still shown as paused");

// 2. escaping of hostile agent/server values
const XSS = `<img src=x onerror=alert(1)>`;
const XSS_ESC = "&lt;img src=x onerror=alert(1)&gt;";
const noRaw = (html, what) => {
  if (/<img/i.test(html)) fail(`${what}: raw <img> in output`);
  if (/<script/i.test(html)) fail(`${what}: raw <script> in output`);
};
const devHtml = api.deviceHeadHtml({ name: XSS, connection: "online", activity: "working" });
noRaw(devHtml, "device name");
if (!devHtml.includes(XSS_ESC)) fail("device name not shown escaped");
const wallet = api.walletHtml([{ chain: `sol"ana`, address: `${XSS}9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin${XSS}`, status: XSS }]);
noRaw(wallet, "wallet");
if (wallet.includes(`sol"ana`) || !wallet.includes("sol&quot;ana")) fail("wallet chain not escaped");
if (!wallet.includes(`title="${XSS_ESC}`)) fail("wallet address title not escaped");
const hw = api.hardwareHtml({ gpu: XSS, cpu: XSS, ram_mb: 32768, vram_mb: 12282 }, `${XSS}-cpu`, "tpm");
noRaw(hw, "hardware");
const heroXss = hero(snap({ job: { model_id: XSS, since_ms: now } }));
if (!heroXss.sub.includes(XSS)) fail("hero sub should be plain text (escaped by the caller)");
const earn = api.earningsHtml({ totals: { pending: "1.000000000" }, alerts: [{ message: XSS }], as_of: "2026-11-17" });
noRaw(earn, "earnings alerts");
const est = api.estimateHtml({ err: XSS });
noRaw(est, "estimate error");
const bench = api.benchHtml({ state: "running", started_ms: now - 600e3, duration_s: 1200, segments: XSS }, now, false);
noRaw(bench, "benchmark");

// 3. pilot banner only when the snapshot says so
if (api.isPilot(null) || api.isPilot({}) || api.isPilot({ pilot: "true" }) || api.isPilot({ environment: "production" }) || api.isPilot({ error: "x", pilot: true })) fail("pilot shown without the snapshot saying so");
if (!api.isPilot({ pilot: true }) || !api.isPilot({ environment: "pilot" })) fail("pilot not shown when the snapshot says pilot");
if (api.pilotHtml({}) !== "") fail("pilot banner rendered by default");
if (!api.pilotHtml({ pilot: true }).includes("Pilot: test money, no real value")) fail("pilot banner text");

// 4. estimate: a range, the base and the temporary launch bonus shown apart, never a promise
const e = api.estimateHtml({ ok: { low_usd: "9.000000000", high_usd: "24.000000000", base: { low_usd: "3.500000000", high_usd: "9.000000000" },
  multiplier: 3, multiplier_end: "2027-03-01T00:00:00Z", assumptions: { utilization: 0.35, hours_per_day: 14, electricity_usd_per_kwh: 0.15, avg_watts: 180, electricity_cost_usd: "4.100000000" } } });
if (!e.includes("$9.00") || !e.includes("$24.00")) fail("estimate range");
if (!e.includes("Base pay") || !e.includes("$3.50 – $9.00")) fail("base pay shown separately");
if (!/Launch bonus/.test(e) || !e.includes("×3.00") || !/[Tt]emporary/.test(e)) fail("launch bonus shown separately and called temporary");
if (!/estimate/i.test(e) || !/not a promise/.test(e)) fail("estimate label");
if (/guarantee|passive income|earn \$/i.test(e)) fail("promise wording in the estimate");
const noBonus = api.estimateHtml({ ok: { low_usd: "1.000000000", high_usd: "2.000000000", base: { low_usd: "1.000000000", high_usd: "2.000000000" }, multiplier: 1 } });
if (noBonus.includes("×") || noBonus.includes("Temporary")) fail("bonus shown when there is none");

// 5. consent text rendered exactly (escaped as text, never rewritten or shortened)
const text = `Line one & "two" <three>\n  indented, 'four'. ${"x".repeat(2000)}`;
const c = api.consentHtml({ text, version: "v1", text_sha256: "ab".repeat(32), refused_message: "no" }, null);
if (!c.includes(api.esc(text))) fail("consent text not byte-identical after escaping");
if (!c.includes('id="consent-accept"') || !c.includes('id="consent-refuse"')) fail("consent buttons");

// 5a. linking a device accepts the Contributor Agreement and the AUP: English titles, opened only through open_link kinds
const legal = api.legalAcceptHtml();
for (const h of [c, legal]) {
  if (!h.includes("By continuing, you link this computer to your Vouch Compute account and agree to:")) fail("legal lead-in");
  if (!h.includes('data-link="contributor_agreement"') || !h.includes('data-link="acceptable_use"')) fail("legal links");
  if (!h.includes("Vouch Compute Contributor Agreement") || !h.includes("Vouch Compute Acceptable Use Policy")) fail("legal titles");
  if ((h.match(/data-link="[a-z_]+" lang="en" dir="ltr">Vouch Compute /g) || []).length !== 2) fail("legal titles marked as English");
  if (/href=|https?:/.test(h)) fail("the page must not carry legal URLs");
  if (h.includes("binding version")) fail("binding note shown in English");
}
// 5a'. the sign-in step names the same two documents, with its own lead-in, in the same English-title form
const signin = api.signinTermsHtml();
if (!signin.includes("By signing in and running the app on this computer, you agree to:")) fail("sign-in lead-in");
if (signin.includes("By continuing, you link")) fail("sign-in must not reuse the device-link lead-in");
if (signin.replace(/<p[^>]*>[^<]*<\/p>/, "") !== legal.replace(/<p[^>]*>[^<]*<\/p>/, "")) fail("sign-in and device-link name the same documents");
if ((signin.match(/data-link="[a-z_]+" lang="en" dir="ltr">Vouch Compute /g) || []).length !== 2) fail("sign-in titles marked as English");
if (/href=|https?:|vouchcompute\.com/.test(signin)) fail("the sign-in line must not carry legal URLs");
// every link kind the page asks for is one open_link allows (status.links kinds, plus the sign-in page)
{
  const fs = require("fs"), path = require("path");
  const src = path.join(__dirname, "..");
  const app = fs.readFileSync(path.join(src, "ui", "app.js"), "utf8");
  const rs = fs.readFileSync(path.join(src, "src-tauri", "src", "links.rs"), "utf8");
  const agent = fs.readFileSync(path.join(src, "..", "crates", "pool-core", "src", "agent.rs"), "utf8");
  const kinds = [...rs.match(/STATUS_KINDS: &\[&str\] = &\[([^\]]*)\]/)[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  const used = new Set([...app.matchAll(/data-link="([a-z_]+)"/g), ...app.matchAll(/linkTag\("([a-z_]+)"\)/g)].map((m) => m[1]));
  for (const m of legal.matchAll(/data-link="([a-z_]+)"/g)) used.add(m[1]);
  for (const k of used) if (k !== "signin" && !kinds.includes(k)) fail(`link kind ${k} is not allowed by open_link`);
  for (const k of kinds) if (!agent.includes(`"${k}": format!(`)) fail(`status.links has no ${k}`);
  if (!agent.includes('"{}/legal/contributor-agreement"') || !agent.includes('"{}/legal/acceptable-use"')) fail("legal URL slugs");
}

// 5b. the backend that ran the last job: label and "Accelerated" badge (Metal on Apple silicon, macOS)
for (const [b, label, accel] of [["candle-metal", "Graphics card (Metal)", true], ["candle-cuda", "Graphics card (CUDA)", true],
  ["onnxruntime-directml", "Graphics card (DirectML)", true], ["candle-cpu", "Processor (CPU)", false]]) {
  const h = api.hardwareHtml({ gpu: "Apple M3 Pro", cpu: "Apple M3 Pro", ram_mb: 18432 }, b, "software");
  if (!h.includes(label)) fail(`backend label for ${b}`);
  if (h.includes("Accelerated") !== accel) fail(`accelerated badge for ${b}`);
}

// 5c. performance measured during the benchmark: the app's own number, labelled as such, next to the server's status
// and tier; never a number the server did not have a say in presented as pay, and hostile values escaped
{
  const m = { unit: "token", per_second: 418.26, runs: 470, backend: "onnxruntime-cpu" };
  if (api.measuredText(m) !== "418 tokens per second") fail(`token rate: ${api.measuredText(m)}`);
  if (api.measuredText({ unit: "token", per_second: 12.345 }) !== "12.3 tokens per second") fail("rate rounding 10-100");
  if (api.measuredText({ unit: "token", per_second: 1.234 }) !== "1.23 tokens per second") fail("rate rounding < 10");
  if (api.measuredText({ unit: "token", per_second: 1234.5 }) !== "1,235 tokens per second") fail("rate grouping");
  if (api.measuredText({ unit: "audio_second", per_second: 31.04 }) !== "31× real time") fail(`audio rate: ${api.measuredText({ unit: "audio_second", per_second: 31.04 })}`);
  for (const bad of [null, {}, { per_second: 0 }, { per_second: -3 }, { per_second: "x" }, { per_second: Infinity }]) {
    if (api.measuredText(bad) !== "") fail(`no rate for ${JSON.stringify(bad)}`);
  }
  const done = api.benchHtml({ state: "received", measured: m }, now, false);
  if (!done.includes("418 tokens per second") || !done.includes("Measured by the app on this computer.")) fail("finished benchmark shows the measured rate");
  const running = api.benchHtml({ state: "running", started_ms: now - 600e3, duration_s: 1200, segments: 10, measured: m }, now, false);
  if (!running.includes("Measured so far: 418 tokens per second")) fail("running benchmark shows the rate so far");
  if (api.benchHtml({ state: "sent" }, now, false).includes("per second")) fail("no rate shown without a measurement");
  const dv = { status: "probation", tier: "probation", benchmark_date: "2026-11-24" };
  const perf = api.perfHtml([{ model_id: "bge-m3", benchmark_id: "b", measured: m, finished_ms: now, received: true }], dv, false);
  for (const want of ["418 tokens per second", "bge-m3 on Processor (CPU)", "Received by the server", "Status on the server", "Probation",
    "Tier", "Benchmark date on the server", "only verified work is paid", "Tokens are the small pieces of text"]) {
    if (!perf.includes(want)) fail(`performance card: missing ${want}`);
  }
  const empty = api.perfHtml([], { status: "benchmarking", tier: "probation" }, false);
  if (!empty.includes("appears here after its first benchmark") || !empty.includes("Benchmarking") || !empty.includes("Not yet")) fail("performance card before any benchmark");
  if (!api.perfHtml(null, null, true).includes("Loading")) fail("server part loading");
  if (!api.perfHtml(null, null, false).includes("registered and online")) fail("server part unavailable");
  const hostile = api.perfHtml([{ model_id: XSS, measured: { unit: XSS, per_second: 5, backend: XSS }, finished_ms: now }], { status: XSS, tier: XSS, benchmark_date: XSS }, false);
  noRaw(hostile, "performance card");
  if (hostile.includes("undefined") || hostile.includes("NaN")) fail("performance card with odd values");
  if (/score|threshold|canary|envelope/i.test(perf)) fail("performance card must not show verification data");
}

// 6. totals from server strings only
if (api.sumUsd("6.870000000", "0.120000000") !== "6.990000000") fail("sumUsd");
if (api.duration(5400) !== "1 h 30 min" || api.duration(600) !== "10 min" || api.duration(null) !== "0 min" && api.duration(null) !== "—") fail("duration");

console.log(bad ? `${bad} failures` : "render: all checks pass");
process.exit(bad ? 1 : 0);
