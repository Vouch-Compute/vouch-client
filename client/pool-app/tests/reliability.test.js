// The app shows the server's DeviceView.reliability (tier, benefits, operational hints) and nothing else.
// Run: node pool-app/tests/reliability.test.js
// * the card renders the server's object; unknown tiers or hints are not shown; no score/threshold/verification detail/
//   latency/speed wording appears anywhere in the card or its fixed texts;
// * the app never computes or caches a tier: app.js has no browser-storage write of reliability or tier data.
const { I18N, APP_JS: src, useLocale, loadSection } = require("./ui-loader.js");
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const day = (s) => s;
useLocale("en");
const t = I18N.t;
const { reliabilityHtml, HINTS, TIER_LABELS, PRIORITY_WORDS } = loadSection("// ---- reliability (start)", "// ---- reliability (end)",
  ["reliabilityHtml", "HINTS", "TIER_LABELS", "PRIORITY_WORDS"], { esc, day });
let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };
const BANNED = /score|threshold|canar|spot.?check|latency|speed|percentile|window|rank/i;

const html = reliabilityHtml({ tier: "stable", since_day: "2026-11-12", benefits: { queue_priority: "higher", bonus_pct: 5 },
  improve: ["keep_regular_hours", "made_up_hint", "avoid_disconnects"] });
if (!html.includes("Stable")) fail("tier label");
if (!html.includes("+5% on verified work")) fail("bonus");
if (!html.includes("Higher place in the queue")) fail("queue priority");
if (!html.includes(t(HINTS.keep_regular_hours)) || !html.includes(t(HINTS.avoid_disconnects))) fail("hints");
if (html.includes("made_up_hint")) fail("unknown hint shown");
if (BANNED.test(html)) fail("banned wording in the card: " + html.match(BANNED)[0]);
for (const key of [...Object.values(HINTS), ...Object.values(TIER_LABELS), ...Object.values(PRIORITY_WORDS)]) {
  if (BANNED.test(t(key))) fail("banned wording in fixed text: " + t(key));
}
if (reliabilityHtml({ tier: "gold" }).includes("gold")) fail("unknown tier shown");
if (!reliabilityHtml(null).includes("appears here")) fail("empty state");
if (!reliabilityHtml({ tier: "probation", benefits: { queue_priority: "standard", bonus_pct: 0 }, improve: [] }).includes("New device")) fail("probation");
// no local tier: nothing about reliability or tiers goes to browser storage, and the agent's snapshot has no tier
if (/store\.set\([^)]*(reliab|tier)/i.test(src) || /localStorage[^;]*(reliab|tier)/i.test(src)) fail("tier cached in browser storage");
console.log(bad ? `${bad} failures` : "reliability card: all checks pass");
process.exit(bad ? 1 : 0);
