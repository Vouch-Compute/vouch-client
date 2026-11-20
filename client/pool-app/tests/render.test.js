// Rendering checks for app.js (hero status, escaping, pilot banner, estimate, consent). Run: node pool-app/tests/render.test.js
// Loads the DOM-free "pure" section of app.js, the same way the other UI tests load their sections.
const fs = require("fs");
const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "ui", "app.js"), "utf8");
const start = src.indexOf("// ---- pure (start)");
const end = src.indexOf("// ---- pure (end)");
if (start < 0 || end < 0) throw new Error("pure-section markers missing in app.js");
const names = ["esc", "heroState", "isPilot", "pilotHtml", "estimateHtml", "earningsHtml", "walletHtml", "deviceHeadHtml", "hardwareHtml", "consentHtml", "benchHtml", "sumUsd", "duration"];
const api = new Function(src.slice(start, end) + `; return { ${names.join(", ")} };`)();

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
if (!api.pilotHtml({ pilot: true }).includes("Pilot: test money (Solana devnet USDC)")) fail("pilot banner text");

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

// 6. totals from server strings only
if (api.sumUsd("6.870000000", "0.120000000") !== "6.990000000") fail("sumUsd");
if (api.duration(5400) !== "1 h 30 min" || api.duration(600) !== "10 min" || api.duration(null) !== "0 min" && api.duration(null) !== "—") fail("duration");

console.log(bad ? `${bad} failures` : "render: all checks pass");
process.exit(bad ? 1 : 0);
