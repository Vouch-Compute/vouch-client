// Vouch Compute UI. Talks only to the app's allow-listed Tauri commands (core proxy, open_link, updates, autostart,
// locale). All agent and server text, and every translated string, is escaped with esc() before it reaches the DOM;
// rich() is the only way a message carries markup (the reviewed <b> and <link> tags). Without Tauri (plain browser
// preview) a demo backend is used so the screens can be reviewed.
"use strict";

const { t, rich, fmt } = I18N;
const activeLocale = I18N.locale;

// ---- pure (start)
// Rendering helpers with no DOM access (the node tests load this section on its own, with t, rich, fmt and
// activeLocale from i18n.js).
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// Money (contract 2.0.0): the server sends exact decimal strings ("12.345678901", at most 9 fractional digits).
// They are parsed into BigInt nano-USD and rounded in integers, never through a float. Cents, or 4 decimals
// below one cent so small amounts do not show as $0.00. Same rules as pool-core's money::UsdAmount::display.
const USD_RE = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?$/;
function nanos(s) {
  const m = typeof s === "string" ? USD_RE.exec(s) : null;
  if (!m) return null;
  const n = BigInt(m[2]) * 1000000000n + BigInt((m[3] || "").padEnd(9, "0") || "0");
  return m[1] ? -n : n;
}
function usd(s) {
  const n = nanos(s);
  if (n === null) return "—";
  const neg = n < 0n;
  const a = neg ? -n : n;
  const sign = neg ? "-" : "";
  if (a !== 0n && a < 10000000n) {
    const q = (a + 50000n) / 100000n; // 1e-4 USD
    return `${sign}$${q / 10000n}.${String(q % 10000n).padStart(4, "0")}`;
  }
  const q = (a + 5000000n) / 10000000n; // cents
  const whole = (q / 100n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${sign}$${whole}.${String(q % 100n).padStart(2, "0")}`;
}
// nano-USD back to the server's decimal form, so sums of server amounts go through usd() too
function fromNanos(n) {
  const neg = n < 0n;
  const a = neg ? -n : n;
  return `${neg ? "-" : ""}${a / 1000000000n}.${String(a % 1000000000n).padStart(9, "0")}`;
}
function sumUsd(...xs) {
  let tot = 0n;
  for (const x of xs) { const n = nanos(x); if (n !== null) tot += n; }
  return fromNanos(tot);
}
const day = (s) => (s ? fmt.date(s) : "—");
const time = (ms) => fmt.time(ms);
const num = (x) => fmt.number(x);
// a finite number for plural and number arguments, or null (shown as "—")
const n0 = (x) => (x !== null && x !== undefined && x !== "" && Number.isFinite(Number(x)) ? Number(x) : null);
function duration(sec) {
  const s = Number(sec);
  if (!Number.isFinite(s) || s < 0) return "—";
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  return h ? t("common.duration.hoursMinutes", { h, m: String(m % 60).padStart(2, "0") }) : t("common.duration.minutes", { m });
}
// translated text, escaped for HTML
const tx = (key, vars) => esc(t(key, vars));
// markup for the reviewed rich-text tags
const TAG_B = (inner) => `<strong>${inner}</strong>`;
const linkTag = (kind) => (inner) => `<button type="button" class="linklike" data-link="${esc(kind)}">${inner}</button>`;
const viewTag = (v) => (inner) => `<button type="button" class="linklike" data-view="${esc(v)}">${inner}</button>`;

// Icons: fixed path data (24 x 24, stroked), never built from agent or server data.
const ICONS = {
  home: "M3.5 10.5 12 3.5l8.5 7V19a1.5 1.5 0 0 1-1.5 1.5h-4v-6h-6v6H5A1.5 1.5 0 0 1 3.5 19z",
  wallet: "M4 7a2 2 0 0 1 2-2h11v3M4 7v11a2 2 0 0 0 2 2h13a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1H6a2 2 0 0 1-2-2zM16 14h.5",
  device: "M3.5 5.5a1 1 0 0 1 1-1h15a1 1 0 0 1 1 1V15a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1zM8.5 20h7M12 16v4",
  settings: "M4 7h10M18 7h2M4 17h4M12 17h8M16 5a2 2 0 1 1 0 4 2 2 0 0 1 0-4zM10 15a2 2 0 1 1 0 4 2 2 0 0 1 0-4z",
  check: "M5 12.5l4.5 4.5L19 7.5",
  pause: "M9 5.5v13M15 5.5v13",
  play: "M8 5.5v13l10.5-6.5z",
  shield: "M12 3.5 5 6.5v5c0 4.3 2.9 7.6 7 9 4.1-1.4 7-4.7 7-9v-5z",
  shieldCheck: "M12 3.5 5 6.5v5c0 4.3 2.9 7.6 7 9 4.1-1.4 7-4.7 7-9v-5zM9 12l2.2 2.2L15.5 10",
  thermo: "M10 14.5V5.5a2 2 0 1 1 4 0v9a4 4 0 1 1-4 0z",
  bolt: "M13 3 5.5 13.5h6L10.5 21 18 10.5h-6z",
  clock: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM12 7.5V12l3 2",
  calendar: "M4.5 6.5a1 1 0 0 1 1-1h13a1 1 0 0 1 1 1V19a1 1 0 0 1-1 1h-13a1 1 0 0 1-1-1zM4.5 10h15M8.5 3.5v4M15.5 3.5v4",
  refresh: "M19.5 11A7.5 7.5 0 0 0 6 7.2M4.5 4v4h4M4.5 13A7.5 7.5 0 0 0 18 16.8M19.5 20v-4h-4",
  external: "M14 4.5h5.5V10M19.5 4.5 11 13M17.5 14v4.5a1 1 0 0 1-1 1h-11a1 1 0 0 1-1-1v-11a1 1 0 0 1 1-1H10",
  sun: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2.5v2M12 19.5v2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M2.5 12h2M19.5 12h2M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4",
  moon: "M19.5 14.5A7.5 7.5 0 0 1 9.5 4.5a7.5 7.5 0 1 0 10 10z",
  alert: "M12 4 2.8 19.5h18.4zM12 10v4.5M12 17.2h.01",
  power: "M12 3.5v8M7.2 6.6a7 7 0 1 0 9.6 0",
  logout: "M14.5 4.5h4a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-4M10 16.5 14.5 12 10 7.5M14.5 12H4.5",
  trash: "M4.5 7h15M10 11v6M14 11v6M6.5 7l1 12.5h9l1-12.5M9.5 7V4.5h5V7",
  info: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM12 11v5.5M12 7.8h.01",
  wifiOff: "M3 3l18 18M8.6 15.4a5 5 0 0 1 6.2-.3M5.2 12a10 10 0 0 1 3.3-2.2M18.8 12a10 10 0 0 0-2.4-1.8M2 8.6a15 15 0 0 1 4-2.6M22 8.6A15 15 0 0 0 11 5.1M12 19h.01",
  chip: "M7.5 7.5h9v9h-9zM10 3.5v4M14 3.5v4M10 16.5v4M14 16.5v4M3.5 10h4M3.5 14h4M16.5 10h4M16.5 14h4",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 20.5a7.5 7.5 0 0 1 15 0",
  key: "M14.5 3.5a6 6 0 0 0-5.6 8.1L3.5 17v3.5H7v-2h2v-2h2l1.4-1.4a6 6 0 1 0 2.1-11.6zM16 7.5h.01",
  download: "M12 4v11M7 10.5l5 5 5-5M5 20h14",
  arrow: "M5 12h14M13 6l6 6-6 6",
  eye: "M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12zM12 9.2a2.8 2.8 0 1 0 0 5.6 2.8 2.8 0 0 0 0-5.6z",
  hourglass: "M7 3.5h10M7 20.5h10M8 3.5v3l4 5.5-4 5.5v3M16 3.5v3L12 12l4 5.5v3",
  gauge: "M4 16.5a8 8 0 1 1 16 0M12 16.5l3.5-4.5M4 16.5h2M18 16.5h2",
  layers: "M12 3.5 3 8l9 4.5L21 8zM3 12.5l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5",
  sparkle: "M12 3.5v4M12 16.5v4M3.5 12h4M16.5 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6",
  globe: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM3.5 12h17M12 3.5c2.3 2.3 3.5 5.2 3.5 8.5s-1.2 6.2-3.5 8.5c-2.3-2.3-3.5-5.2-3.5-8.5s1.2-6.2 3.5-8.5z",
};
const icon = (name, cls) =>
  `<svg class="i i-${name}${cls ? " " + cls : ""}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${ICONS[name] || ""}"/></svg>`;
// the seal-check mark from the brand guide, drawn in currentColor
const MARK = `<svg class="mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false"><path d="M38.64 14.23A22 22 0 1 0 46.8 46.93"/><path d="M20.5 27L29.5 42L55.5 9"/></svg>`;

const MODE_LABELS = { idle_only: "mode.idleOnly", scheduled: "mode.scheduled", always_on: "mode.alwaysOn" };
const modeLabel = (m) => (MODE_LABELS[m] ? t(MODE_LABELS[m]) : "—");

// The hero status. Returns plain text (escaped by the caller). `key` is one of earning, benchmark, idle, waiting,
// paused, offline, signed_out, setup, attention, down, loading; `action` picks the hero's button.
function heroState(s, now) {
  if (!s) return { key: "loading", tone: "muted", icon: "clock", title: t("hero.loading.title"), sub: t("hero.loading.sub"), action: null };
  if (s.error) return { key: "down", tone: "danger", icon: "power", title: t("hero.down.title"), sub: t("hero.down.sub"), action: "start" };
  const st = s.status || {};
  const c = st.connection;
  const d = st.decision || {};
  const set = s.settings || {};
  const n = st.notices || {};
  if (c === "not_signed_in") return { key: "signed_out", tone: "muted", icon: "user", title: t("hero.signedOut.title"), sub: t("hero.signedOut.sub"), action: "signin" };
  if (c === "auth_failed") return { key: "signed_out", tone: "danger", icon: "user", title: t("hero.signedOut.title"), sub: t("hero.signedOut.authFailed"), action: "signin" };
  if (c === "offline" || c === "connecting") {
    const r = n0(st.reconnect_in_s);
    // T-225: the server's signing keys don't verify against this app's keys: retrying can't help, an update can
    if (st.connect_problem === "untrusted_keys") return { key: "offline", tone: "danger", icon: "alert", title: t("hero.offline.title"), sub: t("hero.offline.untrustedKeys"), action: "update" };
    return { key: "offline", tone: "muted", icon: "wifiOff", title: c === "offline" ? t("hero.offline.title") : t("hero.offline.connecting"),
      sub: r === null ? t("hero.offline.sub") : t("hero.offline.subRetry", { seconds: r }), action: "reconnect" };
  }
  if (c === "not_enrolled") return { key: "setup", tone: "info", icon: "key", title: t("hero.setup.title"), sub: t("hero.setup.sub"), action: null };
  if (c === "update_required") return { key: "attention", tone: "warn", icon: "download", title: t("hero.updateRequired.title"), sub: t("hero.updateRequired.sub"), action: "update" };
  if (c === "revoked") return { key: "attention", tone: "danger", icon: "alert", title: t("hero.revoked.title"), sub: t("hero.revoked.sub"), action: null };
  if (st.job) return { key: "earning", tone: "ok", icon: "check", title: t("hero.earning.title"),
    sub: st.job.model_id ? t("hero.earning.subModel", { model: st.job.model_id }) : t("hero.earning.sub"), action: "pause" };
  if (st.benchmark && st.benchmark.state === "running") return { key: "benchmark", tone: "info", icon: "gauge", title: t("hero.benchmark.title"), sub: t("hero.benchmark.sub"), action: "pause" };
  if (n.paused_by === "tally") return { key: "paused", tone: "warn", icon: "pause", title: t("hero.paused.title"), sub: t("notices.pausedByTally"), action: null };
  if (n.paused_by === "user") return { key: "paused", tone: "warn", icon: "pause", title: t("hero.paused.title"), sub: t("notices.pausedByUser"), action: "resume-server" };
  const until = Number(set.paused_until_ms);
  if ((until && until > now) || d.reason === "paused_by_user")
    return { key: "paused", tone: "warn", icon: "pause", title: t("hero.paused.title"),
      sub: until && until > now ? t("hero.paused.until", { time: time(until) }) : t("hero.paused.local"), action: "resume" };
  if (d.state === "run") return { key: "idle", tone: "brand", icon: "clock", title: t("hero.idle.title"), sub: t("hero.idle.sub"), action: "pause" };
  const why = {
    user_active: ["muted", "clock", "hero.waiting.userActive.title", "hero.waiting.userActive.sub"],
    fullscreen: ["muted", "pause", "hero.waiting.fullscreen.title", "hero.waiting.fullscreen.sub"],
    on_battery: ["warn", "bolt", "hero.waiting.onBattery.title", "hero.waiting.onBattery.sub"],
    battery_low: ["warn", "bolt", "hero.waiting.batteryLow.title", "hero.waiting.batteryLow.sub"],
    thermal: ["warn", "thermo", "hero.waiting.thermal.title", "hero.waiting.thermal.sub"],
    outside_schedule: ["muted", "calendar", "hero.waiting.outsideSchedule.title", "hero.waiting.outsideSchedule.sub"],
    daily_cap_reached: ["muted", "hourglass", "hero.waiting.dailyCap.title", "hero.waiting.dailyCap.sub"],
  }[d.reason];
  const vars = { minutes: n0(set.idle_minutes), limit: n0(set.temp_cap_c) };
  if (why) return { key: "waiting", tone: why[0], icon: why[1], title: t(why[2]), sub: t(why[3], vars), action: "pause" };
  return { key: "paused", tone: "warn", icon: "pause", title: t("hero.paused.title"), sub: "", action: "pause" };
}

// Pilot banner: only when the agent's snapshot says so; hidden otherwise.
const isPilot = (s) => !!s && !s.error && (s.pilot === true || s.environment === "pilot");
const pilotHtml = (s) => (isPilot(s) ? `${icon("info")}<span>${tx("pilot.banner")}</span>` : "");

// The runtime of the last job, in plain words (the agent reports what really ran, never what was hoped for).
function backendLabel(b) {
  if (!b) return t("hw.backend.none");
  if (b === "onnxruntime-directml") return t("hw.backend.directml");
  if (b === "candle-cuda") return t("hw.backend.cuda");
  if (b === "candle-metal") return t("hw.backend.metal");
  if (b.endsWith("-cpu") || b === "onnxruntime") return t("hw.backend.cpu");
  return b;
}
const isAccelerated = (b) => b === "onnxruntime-directml" || b === "candle-cuda" || b === "candle-metal";

function hardwareHtml(hw, backend, keyStorage) {
  const h = hw || {};
  const gb = (mb) => (Number(mb) > 0 ? t("hw.gigabytes", { value: Math.round(Number(mb) / 1024) }) : "");
  const vram = gb(h.vram_mb);
  return `<dl class="hw">
      <div class="hw-row hw-main"><dt>${icon("chip")}${tx("hw.gpu")}</dt>
        <dd><span class="hw-value">${esc(h.gpu || t("hw.notDetected"))}${vram ? `<span class="muted">${tx("hw.vram", { size: vram })}</span>` : ""}</span>
        ${isAccelerated(backend) ? `<span class="badge badge-ok">${icon("bolt")}${tx("hw.accelerated")}</span>` : ""}</dd></div>
      <div class="hw-row"><dt>${icon("layers")}${tx("hw.cpu")}</dt><dd>${esc(h.cpu || "—")}</dd></div>
      <div class="hw-row"><dt>${icon("device")}${tx("hw.memory")}</dt><dd>${esc(gb(h.ram_mb) || "—")}</dd></div>
      <div class="hw-row"><dt>${icon("gauge")}${tx("hw.lastBackend")}</dt><dd>${esc(backendLabel(backend))}</dd></div>
      ${keyStorage === undefined ? "" : `<div class="hw-row"><dt>${icon("key")}${tx("hw.deviceKey")}</dt><dd>${keyStorage === "tpm" ? `<span class="badge badge-ok">TPM 2.0</span>` : `<span class="badge badge-warn">${tx("hw.keySoftware")}</span>`}</dd></div>`}
    </dl>`;
}

// ---- performance (start)
// The speed this app measured on this computer during the benchmark (the agent's own measurement, display only: the
// server measures the benchmark itself and only verified work is paid), next to the server's status and tier for
// this device. Plain text (escaped by the caller); "" when there is no usable number.
function measuredText(m) {
  const r = m ? Number(m.per_second) : NaN;
  if (!Number.isFinite(r) || r <= 0) return "";
  const rate = r >= 100 ? Math.round(r) : r >= 10 ? Math.round(r * 10) / 10 : Math.round(r * 100) / 100;
  return m.unit === "audio_second" ? t("perf.realtime", { rate }) : t("perf.tokensPerSecond", { rate });
}
const SERVER_STATUS = { benchmarking: "perf.status.benchmarking", probation: "perf.status.probation", active: "perf.status.active",
  limited: "perf.status.limited", suspended: "perf.status.suspended", revoked: "perf.status.revoked" };
const TRUST_TIER = { probation: "perf.tier.probation", established: "perf.tier.established", trusted: "perf.tier.trusted" };
function perfHtml(list, d, loading) {
  const rows = (Array.isArray(list) ? list : []).filter((p) => p && measuredText(p.measured));
  const results = rows.length
    ? `<ul class="perf-list">${rows.map((p) => `<li class="perf-item">
        <span class="perf-rate">${esc(measuredText(p.measured))}</span>
        <span class="muted small">${tx("perf.detail", { model: String(p.model_id || "—"), backend: p.measured.backend ? backendLabel(p.measured.backend) : "—", date: day(p.finished_ms) })}</span>
        <span class="badge ${p.received ? "badge-ok" : "badge-info"}">${p.received ? tx("perf.received") : tx("perf.sent")}</span></li>`).join("")}</ul>
      ${rows.some((p) => p.measured.unit !== "audio_second") ? `<p class="muted small">${tx("perf.tokenHint")}</p>` : ""}`
    : `<p class="muted small">${tx("perf.empty")}</p>`;
  const server = loading ? `<div class="row"><div class="spinner"></div><span class="muted">${tx("common.loading")}</span></div>`
    : d ? `<dl class="hw perf-server">
        <div class="hw-row"><dt>${tx("perf.statusLabel")}</dt><dd>${SERVER_STATUS[d.status] ? tx(SERVER_STATUS[d.status]) : "—"}</dd></div>
        <div class="hw-row"><dt>${tx("perf.tierLabel")}</dt><dd>${TRUST_TIER[d.tier] ? tx(TRUST_TIER[d.tier]) : "—"}</dd></div>
        <div class="hw-row"><dt>${tx("perf.serverBenchmark")}</dt><dd>${d.benchmark_date ? esc(day(d.benchmark_date)) : tx("perf.noServerBenchmark")}</dd></div>
      </dl>`
    : `<p class="muted small">${tx("device.relUnavailable")}</p>`;
  return `${results}${server}<p class="fine">${tx("perf.note")}</p>`;
}
// ---- performance (end)

// The agent's `benchmark.stop_reason` codes (pool-core `status::BenchProgress`); an unknown one shows no reason line.
const BENCH_STOP_REASONS = ["paused", "thermal", "on_battery", "model_not_downloaded", "runtime_failed", "other"];

function benchHtml(b, now, benchNow) {
  const pct = b ? Math.max(0, Math.min(100, Math.round(((now - Number(b.started_ms)) / 1000 / Math.max(1, Number(b.duration_s) || 1)) * 100))) || 0 : 0;
  const rate = b ? measuredText(b.measured) : "";
  const state = !b ? `<p class="muted">${tx("bench.waiting")}</p>`
    : b.state === "running" ? `<div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100" aria-label="${tx("bench.progressLabel")}"><div class="progress-fill" data-w="${pct}"></div></div>
      <p class="muted small">${tx("bench.progress", { ratio: pct / 100, rounds: n0(b.segments) })}</p>
      ${rate ? `<p class="small">${tx("perf.soFar", { value: rate })}</p>` : ""}`
    : b.state === "sent" || b.state === "received" ? `<div class="note note-ok">${icon("check")}<span>${tx("bench.finished")}</span></div>
      ${rate ? `<p class="perf-rate">${esc(rate)}</p><p class="muted small">${tx("perf.measuredHere")}</p>` : ""}`
    : `<div class="note note-warn">${icon("alert")}<span>${b.state === "declined" ? tx("bench.declined", { model: b.model_id || "—" }) : tx("bench.stopped")}${
      BENCH_STOP_REASONS.includes(b.stop_reason) ? ` ${tx("bench.whyStopped", { reason: b.stop_reason })}` : ""}</span></div>`;
  return `${state}
    <p class="muted small">${tx("bench.about")}</p>
    <div class="row"><button type="button" class="btn ${benchNow ? "" : "btn-primary"}" id="bench-now" aria-pressed="${benchNow ? "true" : "false"}">${icon(benchNow ? "clock" : "play")}${benchNow ? tx("bench.runAtIdle") : tx("bench.runNow")}</button></div>`;
}

// Hardware-identifier consent (2.1.0): the agent's text is shown word for word (escaped, whitespace kept), never
// rewritten, shortened or translated (it is versioned with vault); the buttons send back its hash. Other locales
// get a short note that the English text is the binding one.
// Linking a device means accepting these documents. The titles stay English because the English text is
// binding; only the lead-in is translated. The URLs come from the agent's config through open_link, never the page.
// The sign-in step names the same documents with its own lead-in (signing in and running the app).
const LEGAL_DOCS = [["contributor_agreement", "Vouch Compute Contributor Agreement"], ["acceptable_use", "Vouch Compute Acceptable Use Policy"]];
function legalDocsHtml(leadKey, leadClass) {
  return `<div class="legal-accept"><p${leadClass ? ` class="${leadClass}"` : ""}>${tx(leadKey)}</p>
    <ul class="legal-docs">${LEGAL_DOCS.map(([kind, title]) =>
      `<li><button type="button" class="linklike" data-link="${kind}" lang="en" dir="ltr">${esc(title)}${icon("external")}</button></li>`).join("")}</ul>
    ${activeLocale() === "en" ? "" : `<p class="muted small">${tx("legal.englishBinding")}</p>`}</div>`;
}
function legalAcceptHtml() {
  return legalDocsHtml("legal.linkAccept");
}
function signinTermsHtml() {
  return legalDocsHtml("onboarding.signin.terms", "muted small");
}

function consentHtml(c, decision) {
  if (!c || c.loading) return `<div class="row"><div class="spinner"></div><span class="muted">${tx("common.loading")}</span></div>`;
  if (c.error) return `<div class="note note-danger">${icon("alert")}<span>${esc(c.error)}</span></div>`;
  const refused = decision === "refused";
  return `
    <p class="eyebrow">${tx("onboarding.stepPermission", { current: 3, total: 3 })}</p>
    <h1 id="ob-title">${tx("consent.title")}</h1>
    <p class="lede">${tx("consent.lede")}</p>
    ${activeLocale() === "en" ? "" : `<div class="note note-info small">${icon("info")}<span>${tx("consent.englishBinding")}</span></div>`}
    <div class="consent" lang="en" dir="ltr">
      <p class="consent-text">${esc(c.text)}</p>
    </div>
    <p class="muted small">${tx("consent.sentOnly", { version: c.version })}</p>
    ${refused ? `<div class="note note-warn" role="alert">${icon("alert")}<span>${esc(c.refused_message)}</span></div>` : ""}
    ${legalAcceptHtml()}
    <div class="ob-actions"><button type="button" class="btn" data-go="signin">${tx("common.back")}</button><span class="spacer"></span>
      <button type="button" class="btn" id="consent-refuse">${tx("consent.refuse")}</button>
      <button type="button" class="btn btn-primary btn-lg" id="consent-accept">${tx("consent.accept")}</button></div>`;
}

// Server estimate: always a range, the base and the temporary launch bonus shown apart. Never a promise.
function estimateHtml(c) {
  if (!c) return `<div class="row"><div class="spinner"></div><span class="muted">${tx("estimate.loading")}</span></div>`;
  if (c.err) return `<div class="note">${icon("info")}<span>${tx("estimate.unavailable", { error: c.err })}</span></div>`;
  const e = c.ok || {};
  const a = e.assumptions || {};
  const b = e.base || {};
  const mult = Number(e.multiplier || 1);
  const bonus = mult > 1;
  const price = n0(a.electricity_usd_per_kwh);
  return `
    <div class="est">
      <div class="est-main">
        <span class="eyebrow">${tx("estimate.rangeLabel")}</span>
        <span class="range-big" aria-hidden="true"><span>${usd(e.low_usd)}</span><span class="range-dash">–</span><span>${usd(e.high_usd)}</span></span>
        <span class="sr-only">${tx("common.rangeSpoken", { low: usd(e.low_usd), high: usd(e.high_usd) })}</span>
        <span class="chip chip-soft">${icon("info")}${tx("estimate.notPromise")}</span>
      </div>
      <div class="est-split">
        <div class="tile"><span class="tile-label">${tx("estimate.base")}</span><span class="tile-value">${tx("common.range", { low: usd(b.low_usd), high: usd(b.high_usd) })}</span>
          <span class="tile-hint">${tx("estimate.baseHint")}</span></div>
        <div class="tile ${bonus ? "tile-bonus" : ""}"><span class="tile-label">${tx("estimate.bonus")} ${bonus ? `<span class="badge badge-info">${tx("estimate.temporary")}</span>` : ""}</span>
          <span class="tile-value">${bonus ? `×${esc(mult.toFixed(2))}` : tx("estimate.none")}</span>
          <span class="tile-hint">${!bonus ? tx("estimate.noBonus") : e.multiplier_end ? tx("estimate.bonusHintEnds", { date: day(e.multiplier_end) }) : tx("estimate.bonusHint")}</span></div>
        <div class="tile"><span class="tile-label">${tx("estimate.electricity")}</span><span class="tile-value">−${usd(a.electricity_cost_usd)}</span>
          <span class="tile-hint">${tx("estimate.electricityHint", { watts: n0(a.avg_watts), price: price === null ? "—" : `$${price}` })}</span></div>
      </div>
      <p class="fine">${tx("estimate.assumes", { hours: n0(a.hours_per_day), utilization: Number(a.utilization) || 0 })}</p>
    </div>`;
}

const LABELS = [["pending", "earnings.state.pending", "earnings.hint.pending"], ["in_escrow", "earnings.state.inEscrow", "earnings.hint.inEscrow"],
  ["in_review", "earnings.state.inReview", "earnings.hint.inReview"], ["releasable", "earnings.state.releasable", "earnings.hint.releasable"],
  ["sent", "earnings.state.sent", "earnings.hint.sent"], ["clawed_back", "earnings.state.clawedBack", "earnings.hint.clawedBack"]];

function earningsHtml(e) {
  const tot = (e && e.totals) || {};
  const hold = sumUsd(tot.in_escrow, tot.in_review);
  // a share bar drawn only from the server's own totals (no history is invented)
  const parts = [["pending", "seg-pending"], ["in_escrow", "seg-hold"], ["in_review", "seg-review"], ["releasable", "seg-ready"], ["sent", "seg-paid"]]
    .map(([k, cls]) => [k, cls, nanos(tot[k])]).filter(([, , n]) => n !== null && n > 0n);
  const total = parts.reduce((s, [, , n]) => s + n, 0n);
  const label = (k) => { const l = LABELS.find((x) => x[0] === k); return l ? t(l[1]) : ""; };
  const bar = total > 0n
    ? `<div class="stackbar" role="img" aria-label="${tx("earnings.splitLabel")}">${parts.map(([k, cls, n]) =>
      `<span class="${cls}" data-w="${Number((n * 10000n) / total) / 100}" title="${esc(label(k))}"></span>`).join("")}</div>`
    : `<p class="muted small">${tx("earnings.empty")}</p>`;
  const p = e && e.probation;
  return `
    <div class="totals">
      <div class="total"><span class="total-label"><span class="dot seg-pending"></span>${tx("earnings.state.pending")}</span><span class="total-value">${usd(tot.pending)}</span><span class="tile-hint">${tx("earnings.hint.pending")}</span></div>
      <div class="total"><span class="total-label"><span class="dot seg-hold"></span>${tx("earnings.onHold")}</span><span class="total-value">${usd(hold)}</span><span class="tile-hint">${tx("earnings.onHoldHint")}</span></div>
      <div class="total"><span class="total-label"><span class="dot seg-paid"></span>${tx("earnings.paid")}</span><span class="total-value">${usd(tot.sent)}</span><span class="tile-hint">${tx("earnings.paidHint")}</span></div>
    </div>
    ${bar}
    <details class="breakdown" id="earn-breakdown"><summary>${tx("earnings.allStates")}</summary>
      <dl class="kv-list">${LABELS.map(([k, l, hint]) => `<div><dt>${tx(l)}<span class="muted small">${tx(hint)}</span></dt><dd>${usd(tot[k])}</dd></div>`).join("")}</dl>
    </details>
    ${p && p.active ? `<div class="note note-info">${icon("hourglass")}<span>${p.ends_on ? tx("earnings.probationUntil", { days: n0(p.escrow_days), date: day(p.ends_on) }) : tx("earnings.probation", { days: n0(p.escrow_days) })}</span></div>` : ""}
    ${((e && e.alerts) || []).map((a) => `<div class="note note-warn">${icon("alert")}<span>${esc(a && a.message)}</span></div>`).join("")}
    <p class="fine">${rich("earnings.footer", { amount: usd(e && e.this_week_verified_usd), date: day(e && e.as_of) }, { b: TAG_B, link: linkTag("dashboard") })}</p>`;
}

// The payout account as the agent reports it (display only; it is set up and changed on the web).
function walletHtml(list) {
  if (!list || !list.length) return `<p>${tx("payout.none")}</p>`;
  return list.map((x) => {
    const addr = String((x && x.address) ?? "");
    const frozen = x.payout_freeze_until && new Date(x.payout_freeze_until) > new Date();
    return `<div class="wallet-row"><span class="badge">${esc(x.chain)}</span><span class="mono addr" title="${esc(addr)}">${esc(addr.slice(0, 6))}…${esc(addr.slice(-6))}</span>
      <span class="badge ${x.status === "active" ? "badge-ok" : "badge-warn"}">${esc(x.status)}</span>
      ${frozen ? `<span class="muted small">${tx("payout.resumes", { date: day(x.payout_freeze_until) })}</span>` : ""}</div>`;
  }).join("");
}

function deviceStateText(d) {
  if (!d) return "";
  return t("device.state", {
    connection: d.connection === "online" ? "online" : "offline",
    activity: ["idle", "working", "paused"].includes(d.activity) ? d.activity : "none",
    pausedBy: d.paused_by === "user" || d.paused_by === "tally" ? d.paused_by : "none",
  });
}
function deviceHeadHtml(d) {
  const name = d && d.name ? d.name : t("device.thisComputer");
  const online = d && d.connection === "online";
  return `<div class="dev-head">
      <div class="dev-icon" aria-hidden="true">${icon("device")}</div>
      <div class="dev-title"><h2 class="dev-name">${esc(name)}</h2>
        ${d ? `<p class="muted small"><span class="dot ${online ? "dot-ok" : "dot-muted"}"></span>${esc(deviceStateText(d))}</p>` : `<p class="muted small">${tx("device.headPending")}</p>`}</div>
    </div>`;
}

const hhmm = (m) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
function daysText(bits) {
  const b = Number(bits) & 127;
  if (b === 127) return t("schedule.everyDay");
  if (b === 31) return t("schedule.weekdays");
  if (b === 96) return t("schedule.weekends");
  if (!b) return t("schedule.noDays");
  return fmt.list([0, 1, 2, 3, 4, 5, 6].filter((i) => b & (1 << i)).map((i) => fmt.weekday(i)));
}
function scheduleSummary(schedule) {
  return (schedule || []).map((w) => t("schedule.window", { days: daysText(w.days), start: hhmm(Number(w.start_min) || 0), end: hhmm(Number(w.end_min) || 0) }));
}

// ---- reliability (start)
// the server's DeviceView.reliability, shown as it is: tier, since, benefits and the fixed operational hints. The app never
// computes, infers or stores a tier; there are no scores, thresholds or speeds to show.
const TIER_LABELS = { probation: "reliability.tier.probation", premium: "reliability.tier.premium", stable: "reliability.tier.stable",
  less_stable: "reliability.tier.lessStable", unpredictable: "reliability.tier.unpredictable" };
const PRIORITY_WORDS = { standard: "reliability.priority.standard", higher: "reliability.priority.higher", highest: "reliability.priority.highest" };
const HINTS = {
  keep_regular_hours: "reliability.hint.keepRegularHours",
  avoid_disconnects: "reliability.hint.avoidDisconnects",
  finish_accepted_jobs: "reliability.hint.finishAcceptedJobs",
  build_tenure: "reliability.hint.buildTenure",
  verify_identity: "reliability.hint.verifyIdentity",
  use_hardware_key: "reliability.hint.useHardwareKey",
};
function reliabilityHtml(r) {
  if (!r || !TIER_LABELS[r.tier]) return `<p class="muted small">${esc(t("reliability.empty"))}</p>`;
  const b = r.benefits || {};
  const bonus = typeof b.bonus_pct === "number" && b.bonus_pct > 0 ? t("reliability.bonus", { pct: b.bonus_pct }) : t("reliability.noBonus");
  const hints = (r.improve || []).filter((h) => HINTS[h]).map((h) => `<li>${esc(t(HINTS[h]))}</li>`).join("");
  return `
    <div class="row"><span class="tier tier-${esc(r.tier)}">${esc(t(TIER_LABELS[r.tier]))}</span>${r.since_day ? `<span class="muted small">${esc(t("reliability.since", { date: day(r.since_day) }))}</span>` : ""}</div>
    <dl class="kv"><dt>${esc(t("reliability.queue"))}</dt><dd>${esc(t(PRIORITY_WORDS[b.queue_priority] || PRIORITY_WORDS.standard))}</dd><dt>${esc(t("reliability.bonusLabel"))}</dt><dd>${esc(bonus)}</dd></dl>
    ${hints ? `<p class="small"><strong>${esc(t("reliability.howToImprove"))}</strong></p><ul class="small hints">${hints}</ul>` : `<p class="muted small">${esc(t("reliability.nothingToImprove"))}</p>`}
    <p class="muted small">${esc(t("reliability.about"))}</p>`;
}
// ---- reliability (end)

// Three visible setup steps: welcome, sign in, this device (the hardware consent, enrollment and "you're set").
const STEP_INDEX = { welcome: 0, signin: 1, consent: 2, device: 2 };
const STEP_LABELS = ["onboarding.steps.welcome", "onboarding.steps.signin", "onboarding.steps.device"];
function stepsHtml(current) {
  const i = STEP_INDEX[current] ?? 0;
  return `<ol class="steps" aria-label="${tx("onboarding.progress", { current: i + 1, total: STEP_LABELS.length })}">${STEP_LABELS.map((l, j) =>
    `<li class="${j < i ? "done" : j === i ? "current" : ""}"${j === i ? ` aria-current="step"` : ""}><span class="step-dot">${j < i ? icon("check") : esc(num(j + 1))}</span><span class="step-label">${tx(l)}</span></li>`).join("")}</ol>`;
}

// T-225: the device step until this computer is registered. `si` is the agent's sign-in state; `ui` is the app's view
// of its own enroll call ({ busy, timedOut }). The spinner shows only while an enroll call runs and is within its time
// limit. "Back to sign-in" and "Start over" are always there and safe mid-call (the app cancels and ignores the late
// result). A state this app doesn't know is an error with the agent's words, never a spinner.
// The agent's errors with a code are translated; others keep the agent's English words.
const ENROLL_ERRORS = { signin_expired: "onboarding.device.errors.signinExpired", no_answer: "onboarding.device.errors.noAnswer", key_changed: "onboarding.device.errors.keyChanged" };
function enrollErrorText(si) {
  return si && ENROLL_ERRORS[si.code] ? tx(ENROLL_ERRORS[si.code]) : esc(si && si.message);
}
function enrollStepHtml(si, ui) {
  const st = si && si.state;
  const head = (key) => `<p class="eyebrow">${tx("onboarding.step", { current: 3, total: 3 })}</p><h1 id="ob-title">${tx(key)}</h1>`;
  const nav = (extra) => `<div class="ob-actions"><button type="button" class="btn" id="enroll-back">${tx("onboarding.device.error.backToSignin")}</button>
    <button type="button" class="btn btn-ghost" id="enroll-reset">${tx("onboarding.device.startOver")}</button><span class="spacer"></span>${extra || ""}</div>`;
  const retry = `<button type="button" class="btn btn-primary" data-replace="">${tx("onboarding.device.error.tryAgain")}</button>`;
  const failed = (text) => `${head("onboarding.device.error.title")}<div class="note note-danger" role="alert">${icon("alert")}<span>${text}</span></div>${nav(retry)}`;
  if (ui && ui.timedOut) return failed(tx("onboarding.device.timeout"));
  if ((ui && ui.busy) || st === "enrolling") {
    return `${head("onboarding.device.enrolling.title")}<div class="row" role="status"><div class="spinner" aria-hidden="true"></div><span>${tx("onboarding.device.enrolling.creating")}</span></div>${nav()}`;
  }
  if (st === "choose_replace") {
    const c = si.candidates || [];
    return `${head("onboarding.device.replace.title")}
      <p class="lede">${tx("onboarding.device.replace.lede", { count: c.length })}</p>
      <div class="choice-list">${c.map((x) => `<button type="button" class="choice-btn" data-replace="${esc(x.device_id)}">${icon("refresh")}<span><strong>${tx("onboarding.device.replace.item", { name: x.name || t("onboarding.device.replace.unnamed") })}</strong>${x.last_seen_day ? `<span class="muted small">${tx("onboarding.device.replace.lastSeen", { date: day(x.last_seen_day) })}</span>` : ""}</span></button>`).join("")}
        <button type="button" class="choice-btn choice-primary" data-replace="">${icon("sparkle")}<span><strong>${tx("onboarding.device.replace.new")}</strong><span class="muted small">${tx("onboarding.device.replace.newHint")}</span></span></button></div>
      ${legalAcceptHtml()}${nav()}`;
  }
  if (st === "blocked") {
    const fix = si.code === "hardware_in_use" ? `<button type="button" class="btn" data-link="devices">${icon("external")}${tx("onboarding.device.blocked.openDevices")}</button>`
      : si.code === "device_limit" ? `<button type="button" class="btn" data-link="verify">${icon("external")}${tx("onboarding.device.blocked.verify")}</button><button type="button" class="btn" data-link="devices">${tx("onboarding.device.blocked.manage")}</button>`
      : si.code === "consent_refused" || si.code === "consent_required" ? `<button type="button" class="btn btn-primary" data-go="consent">${tx("onboarding.device.blocked.reviewPermission")}</button>`
      : si.code === "replace_not_confirmed" ? `<button type="button" class="btn btn-primary" data-replace="">${tx("onboarding.device.blocked.registerNew")}</button>` : "";
    const again = si.code === "consent_refused" || si.code === "consent_required" || si.code === "replace_not_confirmed" ? "" : retry;
    // reasons with a translation; others show the agent's English text
    const reason = si.code === "hw_ids_required" ? tx("onboarding.device.blocked.reasonHwIds")
      : si.code === "attestation_invalid" ? tx("onboarding.device.blocked.reasonAttestation") : esc(si.message);
    return `${head("onboarding.device.blocked.title")}<div class="note note-warn" role="alert">${icon("alert")}<span>${reason}</span></div>${nav(fix + again)}`;
  }
  if (st === "error") return failed(enrollErrorText(si));
  if (!st || st === "idle" || st === "done") {
    return `${head("onboarding.device.ready.title")}<p class="lede">${tx("onboarding.device.ready.lede")}</p>
      ${nav(`<button type="button" class="btn btn-primary" data-replace="">${tx("onboarding.device.ready.button")}</button>`)}`;
  }
  return failed(si.message ? esc(si.message) : tx("onboarding.device.unknownState", { state: String(st) }));
}

// ------------------------------------------------------------------ account notices (node protocol 1.2.0)
// Banners only. They carry no reason; offers are not affected (a paused device simply receives none).
function noticesHtml(n) {
  if (!n) return "";
  const out = [];
  if (n.paused_by === "user") out.push(`<div class="note note-info" role="status">${icon("pause")}<span>${tx("notices.pausedByUser")}</span><button type="button" class="btn btn-sm" data-control="resume">${tx("common.resume")}</button></div>`);
  if (n.paused_by === "tally") out.push(`<div class="note note-warn" role="status">${icon("pause")}<span>${tx("notices.pausedByTally")}</span></div>`);
  if (n.recovery_in_progress) out.push(`<div class="note note-warn" role="alert">${icon("alert")}<span>${tx("notices.recovery")}</span><button type="button" class="btn btn-sm" data-link="recover">${tx("notices.openWeb")}</button></div>`);
  if (n.reverify_required) out.push(`<div class="note note-warn" role="status">${icon("user")}<span>${tx("notices.reverify")}</span><button type="button" class="btn btn-sm" data-link="verify">${tx("notices.verify")}</button></div>`);
  return out.length ? `<div class="notices">${out.join("")}</div>` : "";
}

// The agent signs with the server's clock anyway; this only tells the user their clock is off.
function clockHtml(off) {
  if (typeof off !== "number" || Math.abs(off) < 5) return "";
  const n = Math.abs(off);
  const offset = n >= 120 ? t("clock.minutes", { n: Math.round(n / 60) }) : t("clock.seconds", { n });
  return `<div class="note note-info" role="status">${icon("clock")}<span>${tx(off > 0 ? "clock.behind" : "clock.ahead", { offset })}</span></div>`;
}

const pageHead = (title, lede, extra) => `<header class="page-head"><div><h1>${title}</h1>${lede ? `<p class="lede">${lede}</p>` : ""}</div>${extra || ""}</header>`;
const cardHead = (id, ic, title, sub) => `<header class="card-head"><span class="icon-bubble">${icon(ic)}</span><div><h2 id="${id}">${title}</h2>${sub ? `<p class="card-sub">${sub}</p>` : ""}</div></header>`;

function heroActionHtml(h) {
  switch (h.action) {
    case "pause": return `<button type="button" class="btn btn-band" id="pause">${icon("pause")}${tx("actions.pauseHour")}</button>`;
    case "resume": return `<button type="button" class="btn btn-primary btn-lg" id="resume">${icon("play")}${tx("actions.resumeNow")}</button>`;
    case "resume-server": return `<button type="button" class="btn btn-primary btn-lg" data-control="resume">${icon("play")}${tx("common.resume")}</button>`;
    case "signin": return `<button type="button" class="btn btn-primary btn-lg" data-go-onboard="signin">${icon("user")}${tx("common.signIn")}</button>`;
    case "reconnect": return `<button type="button" class="btn btn-band" id="reconnect">${icon("refresh")}${tx("actions.tryAgainNow")}</button>`;
    case "update": return `<button type="button" class="btn btn-primary btn-lg" data-view="settings">${icon("download")}${tx("actions.goToUpdates")}</button>`;
    default: return "";
  }
}

function controlsHtml(s) {
  if (!s) return `<p class="muted">${tx("controls.none")}</p>`;
  const windows = (s.schedule || []).map((w, i) => `
    <div class="window-row" data-win="${i}">
      <div class="days" role="group" aria-label="${tx("controls.daysFor", { n: i + 1 })}">${[0, 1, 2, 3, 4, 5, 6].map((d) =>
        `<label><input type="checkbox" data-day="${d}" ${Number(w.days) & (1 << d) ? "checked" : ""}/><span>${esc(fmt.weekday(d))}</span></label>`).join("")}</div>
      <div class="row">
        <label class="row small">${tx("controls.from")} <input type="time" data-k="start" value="${esc(hhmm(Number(w.start_min) || 0))}"/></label>
        <label class="row small">${tx("controls.to")} <input type="time" data-k="end" value="${esc(hhmm(Number(w.end_min) || 0))}"/></label>
        <button type="button" class="btn btn-ghost btn-sm" data-remove="${i}" aria-label="${tx("controls.removeWindow", { n: i + 1 })}">${icon("trash")}${tx("controls.remove")}</button>
      </div>
    </div>`).join("");
  const radio = (v, title, hint) => `<label class="choice"><input type="radio" name="mode" value="${v}" ${s.mode === v ? "checked" : ""}/>
      <span><strong>${tx(title)}</strong><span class="muted small">${tx(hint)}</span></span></label>`;
  return `
  <form id="controls" novalidate>
    <section class="card" aria-labelledby="mode-h"><fieldset>
      <legend class="sr-only">${tx("controls.modeTitle")}</legend>
      ${cardHead("mode-h", "clock", tx("controls.modeTitle"), "")}
      <div class="choices">
        ${radio("idle_only", "controls.idleOnly.title", "controls.idleOnly.hint")}
        ${radio("scheduled", "controls.scheduled.title", "controls.scheduled.hint")}
        ${radio("always_on", "controls.alwaysOn.title", "controls.alwaysOn.hint")}
      </div>
      <div class="field"><div class="field-top"><label for="idle">${tx("controls.idleAfter")}</label><span class="field-val"><output id="idle-out" for="idle">${esc(s.idle_minutes)}</output> ${tx("common.unit.min")}</span></div>
        <input id="idle" type="range" min="1" max="60" value="${esc(s.idle_minutes)}" name="idle_minutes"/></div>
    </fieldset></section>
    <section class="card" aria-labelledby="sched-h"><fieldset>
      <legend class="sr-only">${tx("schedule.title")}</legend>
      ${cardHead("sched-h", "calendar", tx("schedule.title"), tx("controls.scheduleSub"))}
      <div id="windows">${windows || `<p class="muted small">${tx("controls.noWindowsYet")}</p>`}</div>
      <div class="row"><button type="button" class="btn" id="add-window">${icon("calendar")}${tx("controls.addWindow")}</button></div>
      <div class="field"><label for="cap">${tx("controls.capLabel")}</label>
        <input id="cap" class="input-narrow" type="number" min="0.5" max="24" step="0.5" value="${esc(s.daily_cap_hours ?? "")}" name="daily_cap_hours"/></div>
    </fieldset></section>
  </form>`;
}

// The language picker: native names, each marked with its own language.
function languageHtml(saved, system, locales) {
  const opt = (v, label, lang, sel) => `<option value="${esc(v)}"${lang ? ` lang="${esc(lang)}"` : ""}${sel ? " selected" : ""}>${esc(label)}</option>`;
  const auto = locales.find((l) => l.code === system) || locales[0];
  return `<div class="field"><label for="locale-select">${tx("settings.language.label")}</label>
      <select id="locale-select" class="input-narrow">
        ${opt("", t("settings.language.system", { name: auto.name }), null, !saved)}
        ${locales.map((l) => opt(l.code, l.name, l.code, saved === l.code)).join("")}
      </select></div>`;
}
// ---- pure (end)

const TAURI = window.__TAURI__ && window.__TAURI__.core;
const invoke = TAURI ? TAURI.invoke : demoInvoke;
const $app = document.getElementById("app");
const $main = document.getElementById("main");
const $tabs = document.getElementById("tabs");
const $live = document.getElementById("live");
const $pilot = document.getElementById("pilot");
const $toast = document.getElementById("toast");
const $sideStatus = document.getElementById("side-status");
// Browser preview only: #view=<name>, #step=<name>, #theme=<light|dark>, #lang=<code>, plus demo states (see demoInvoke).
const PREVIEW = new URLSearchParams(!TAURI && location.hash ? location.hash.slice(1) : "");

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
};

async function core(method, params) {
  return invoke("core", { method, params: params ?? null });
}
function announce(msg) { $live.textContent = ""; setTimeout(() => ($live.textContent = msg), 30); }
let toastTimer = null;
function toast(msg, tone) {
  $toast.textContent = msg;
  $toast.dataset.tone = tone || "ok";
  $toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $toast.classList.remove("show"), tone === "danger" ? 6000 : 1800);
}

// ------------------------------------------------------------------ language
// The saved choice (an app setting in this window's storage), else the system language as the webview reports it,
// best-matched against the registry, else English. Stored and reported values only ever select a registry entry.
let enMessages = null;
const savedLocale = () => I18N.match([store.get("vouch.locale", null)]);
const systemLocale = () => I18N.match(navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language]) || I18N.DEFAULT;
async function loadMessages(code) {
  return JSON.parse(await invoke("i18n_messages", { locale: code }));
}
async function applyLocale(code) {
  const c = I18N.resolve(code);
  try {
    if (!enMessages) enMessages = await loadMessages(I18N.DEFAULT);
    I18N.use(c, c === I18N.DEFAULT ? enMessages : await loadMessages(c), enMessages);
  } catch (e) {
    I18N.use(I18N.DEFAULT, enMessages || {}, enMessages || {});
  }
  I18N.applyDom(document);
  // the tray menu and the native error texts follow the window
  if (TAURI) invoke("set_locale", { locale: I18N.locale() }).catch(() => {});
}
async function chooseLocale(v) {
  const code = v ? I18N.match([v]) : null;
  store.set("vouch.locale", code);
  await applyLocale(code || systemLocale());
  render({ force: true });
  announce(t("settings.language.changed", { name: I18N.info(I18N.locale()).name }));
}

// ------------------------------------------------------------------ theme
function currentTheme() { return document.documentElement.dataset.theme || "system"; }
function setTheme(mode) {
  if (mode === "light" || mode === "dark") document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  store.set("vouch.theme", mode === "light" || mode === "dark" ? mode : null);
  announce(mode === "light" ? t("settings.theme.announceLight") : mode === "dark" ? t("settings.theme.announceDark") : t("settings.theme.announceSystem"));
  render({ force: true });
}
(function theme() {
  const saved = store.get("vouch.theme", null);
  if (saved) document.documentElement.dataset.theme = saved;
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(dark ? "light" : "dark");
  });
})();

// ------------------------------------------------------------------ state
let snap = null;
let view = "home";
const VIEWS = ["home", "earnings", "device", "settings"];
const VIEW_ALIASES = { status: "home", controls: "settings" };
function normStep(s) {
  if (s in STEP_INDEX) return s;
  return ["benchmark", "estimate", "controls"].includes(s) ? "device" : "welcome";
}
let onboardStep = store.get("vouch.onboarded", false) ? null : normStep(store.get("vouch.step", "welcome"));
let devBuild = true;
let buildInfo = null;
let estimateCache = null;
let earnCache = null;
let walletCache = null;
let deviceCache = null;
let consentCache = null;
let recoverOpen = false;
let recoverMsg = null;
let updateState = null;
let booted = false;
const inflight = new Set();

// When a benchmark changes state (finished, received), the server's status and tier for this device may change too:
// the Device page asks the server again.
let lastBenchState;
async function refresh() {
  try {
    snap = await core("status");
  } catch (e) {
    snap = { error: String(e) };
  }
  trackEnroll(snap);
  const bs = (snap && snap.status && snap.status.benchmark && snap.status.benchmark.state) || null;
  if (lastBenchState !== undefined && bs !== lastBenchState && view === "device") loadDevice();
  lastBenchState = bs;
  render();
}

function setView(v) {
  view = VIEWS.includes(v) ? v : VIEW_ALIASES[v] || "home";
  for (const b of $tabs.querySelectorAll("button")) b.setAttribute("aria-current", b.dataset.view === view ? "page" : "false");
  loadFor(view);
  render({ force: true, enter: true });
  $main.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}
$tabs.addEventListener("click", (e) => { const b = e.target.closest("button[data-view]"); if (b) setView(b.dataset.view); });

let lastHtml = "";
function paint(html, o) {
  const a = document.activeElement;
  const editing = a && $main.contains(a) && a.matches("input,select,textarea");
  // avoid re-rendering (and stealing focus from) an unchanged view, and never clobber a form being edited
  if (!o.force && (html === lastHtml || editing)) return;
  const kept = {};
  const open = [];
  if (!o.enter) {
    for (const el of $main.querySelectorAll("input[data-keep]")) kept[el.id] = el.value;
    for (const d of $main.querySelectorAll("details[id]")) if (d.open) open.push(d.id);
  }
  const focusId = !o.enter && a && $main.contains(a) ? a.id : "";
  lastHtml = html;
  $main.innerHTML = html;
  for (const [id, v] of Object.entries(kept)) { const el = document.getElementById(id); if (el) el.value = v; }
  for (const id of open) { const d = document.getElementById(id); if (d) d.open = true; }
  // widths of bars go through the CSSOM (the CSP blocks inline style attributes)
  for (const el of $main.querySelectorAll("[data-w]")) el.style.width = `${Math.max(0, Math.min(100, Number(el.dataset.w) || 0))}%`;
  if (focusId) { const f = document.getElementById(focusId); if (f) f.focus({ preventScroll: true }); }
  if (o.enter) { $main.classList.remove("enter"); void $main.offsetWidth; $main.classList.add("enter"); }
}

function render(opts) {
  // nothing is drawn before the messages are loaded (index.html shows its English shell meanwhile)
  if (!booted) return;
  const o = opts || {};
  const p = pilotHtml(snap);
  if ($pilot.innerHTML !== p) $pilot.innerHTML = p;
  $pilot.hidden = !p;
  if (onboardStep) {
    $app.classList.add("is-onboarding");
    $tabs.hidden = true;
    return paint(renderOnboarding(), o);
  }
  $app.classList.remove("is-onboarding");
  $tabs.hidden = false;
  const h = heroState(snap, Date.now());
  $sideStatus.dataset.tone = h.tone;
  $sideStatus.querySelector(".side-status-text").textContent = h.title;
  if (!snap) return paint(renderLoading(), o);
  if (snap.error) return paint(renderAgentDown(), o);
  const views = { home: renderHome, earnings: renderEarnings, device: renderDevice, settings: renderSettings };
  paint((views[view] || renderHome)(), o);
}

// ------------------------------------------------------------------ loaders (results are cached and rendered)
async function once(key, fn) {
  if (inflight.has(key)) return;
  inflight.add(key);
  try { await fn(); } finally { inflight.delete(key); }
  render();
}
function loadEstimate() {
  return once("estimate", async () => {
    try { estimateCache = { ok: await core("estimate") }; } catch (e) { estimateCache = { err: String(e) }; }
  });
}
function loadEarnings() {
  return once("earnings", async () => {
    try { earnCache = { ok: await core("earnings") }; } catch (e) { earnCache = { err: String(e) }; }
    try {
      const w = await core("wallets");
      walletCache = { ok: (w && w.data) || (Array.isArray(w) ? w : []) };
    } catch (e) { walletCache = { err: String(e) }; }
  });
}
function loadDevice() {
  return once("device", async () => {
    try { deviceCache = { ok: await core("device") }; } catch (e) { deviceCache = { err: String(e) }; }
  });
}
function loadConsent() {
  return once("consent", async () => {
    try { consentCache = await core("hw_consent.get"); } catch (e) { consentCache = { error: String(e) }; }
  });
}
function loadFor(v) {
  if (onboardStep) return;
  if (v === "home" || v === "earnings") loadEstimate();
  if (v === "earnings") loadEarnings();
  if (v === "device") loadDevice();
  if (v === "settings") loadAutostart();
}

// ------------------------------------------------------------------ enrollment calls (T-225)
// `seq` identifies the current call: Back, Start over and the time limit move it on, so a late answer changes nothing.
// `since` also covers an enrollment the agent runs on its own (resumed at start).
const ENROLL_TIMEOUT_MS = 60000;
let enrollUi = { seq: 0, busy: false, timedOut: false, since: 0 };
function enrollReset() {
  enrollUi = { seq: enrollUi.seq + 1, busy: false, timedOut: false, since: 0 };
}
async function startEnroll(replaces) {
  enrollReset();
  const seq = enrollUi.seq;
  enrollUi.busy = true;
  enrollUi.since = Date.now();
  render({ force: true });
  try {
    await core("enroll", { replaces_device_id: replaces });
  } finally {
    if (enrollUi.seq === seq) enrollUi.busy = false;
  }
  if (enrollUi.seq === seq) return refresh();
}
function trackEnroll(s) {
  // a later answer from the agent (a refusal, a choice, an error, registered, signed out) replaces the timeout message
  const st = s && s.signin && s.signin.state;
  if (enrollUi.timedOut && (!s || !s.signed_in || s.device_id || ["blocked", "choose_replace", "error", "done", "pending"].includes(st))) enrollReset();
  const running = enrollUi.busy || st === "enrolling";
  if (!running) { if (!enrollUi.timedOut) enrollUi.since = 0; return; }
  if (!enrollUi.since) enrollUi.since = Date.now();
  if (!enrollUi.timedOut && Date.now() - enrollUi.since >= ENROLL_TIMEOUT_MS) {
    enrollUi = { seq: enrollUi.seq + 1, busy: false, timedOut: true, since: enrollUi.since };
    core("enroll.cancel").catch(() => {});
  }
}
async function leaveEnroll(reset) {
  enrollReset();
  if (reset) await core("signin.reset");
  else core("enroll.cancel").catch(() => {});
  await refresh();
  return goStep("signin");
}

// ------------------------------------------------------------------ onboarding (3 visible steps)
function goStep(s) {
  // finishing setup applies the start-at-sign-in switch as shown, unless the user already decided
  const as = document.getElementById("autostart");
  if (!s && as && TAURI && !store.get("vouch.autostart_decided", false)) setAutostart(as.checked);
  onboardStep = s ? normStep(s) : null;
  if (onboardStep) store.set("vouch.step", onboardStep);
  else { store.set("vouch.onboarded", true); return setView("home"); }
  if (onboardStep === "consent" || onboardStep === "device") loadConsent();
  render({ force: true, enter: true });
  $main.focus({ preventScroll: true });
}

const stepLine = (n) => tx("onboarding.step", { current: n, total: 3 });

function renderOnboarding() {
  const s = snap && !snap.error ? snap : null;
  const st = onboardStep;
  let body = "";
  if (st === "welcome") {
    const items = [
      ["shield", "onboarding.welcome.items.sandbox"],
      ["eye", "onboarding.welcome.items.inputs"],
      ["bolt", "onboarding.welcome.items.electricity"],
      ["wifiOff", "onboarding.welcome.items.provider"],
      ["info", "onboarding.welcome.items.taxes"],
      ["check", "onboarding.welcome.items.dollars"],
      ["hourglass", "onboarding.welcome.items.probation"],
      ["settings", "onboarding.welcome.items.defaults"],
    ];
    body = `
      <div class="ob-hero"><div class="ob-mark">${MARK}</div>
        <div><p class="eyebrow">${stepLine(1)}</p><h1 id="ob-title">${tx("onboarding.welcome.title")}</h1>
        <p class="lede">${tx("onboarding.welcome.lede")}</p></div></div>
      <div class="disclosure" tabindex="0" id="disclosure" role="region" aria-label="${tx("onboarding.welcome.regionLabel")}">
        <ul class="disc-list">${items.map(([i, k]) => `<li><span class="disc-icon">${icon(i)}</span><span>${rich(k, null, { b: TAG_B })}</span></li>`).join("")}</ul>
      </div>
      <div class="ob-actions"><span class="muted small" id="scroll-hint">${tx("onboarding.welcome.scrollHint")}</span><span class="spacer"></span>
        <button type="button" class="btn btn-primary btn-lg" id="agree" disabled>${tx("onboarding.welcome.agree")}${icon("arrow")}</button></div>`;
  } else if (st === "signin") {
    const si = s && s.signin;
    if (s && s.signed_in && si && si.state !== "pending") {
      body = `<div class="ob-center"><div class="ob-success">${icon("check")}</div>
        <p class="eyebrow">${stepLine(2)}</p><h1 id="ob-title">${tx("onboarding.signin.doneTitle")}</h1><p class="lede">${tx("onboarding.signin.doneLede")}</p></div>
        <div class="ob-actions"><span class="spacer"></span><button type="button" class="btn btn-primary btn-lg" data-go="device">${tx("common.continue")}${icon("arrow")}</button></div>`;
    } else if (si && si.state === "pending") {
      body = `
        <p class="eyebrow">${stepLine(2)}</p><h1 id="ob-title">${tx("onboarding.signin.pendingTitle")}</h1>
        <p class="lede">${tx("onboarding.signin.pendingLede")}</p>
        <div class="code-wrap"><span class="code" aria-label="${tx("onboarding.signin.codeLabel")}" dir="ltr">${esc(si.user_code)}</span></div>
        <div class="row"><button type="button" class="btn btn-primary" data-link="signin">${icon("external")}${tx("onboarding.signin.openPage")}</button>
          <span class="row muted small"><span class="spinner" aria-hidden="true"></span> ${tx("onboarding.signin.waiting")}</span></div>
        <p class="muted small">${tx("onboarding.signin.readOnly")}</p>`;
    } else {
      const err = si && si.state === "error" ? `<div class="note note-danger" role="alert">${icon("alert")}<span>${enrollErrorText(si)}</span></div>` : "";
      const down = snap && snap.error ? `<div class="note note-warn">${icon("alert")}<span>${esc(snap.error)}</span></div>` : "";
      body = `
        <div class="ob-hero"><div class="ob-mark ob-mark-soft">${icon("user")}</div>
          <div><p class="eyebrow">${stepLine(2)}</p><h1 id="ob-title">${tx("common.signIn")}</h1>
          <p class="lede">${tx("onboarding.signin.lede")}</p></div></div>
        ${err}${down}
        ${signinTermsHtml()}
        <div class="ob-actions"><button type="button" class="btn" data-go="welcome">${tx("common.back")}</button><span class="spacer"></span>
          <button type="button" class="btn btn-primary btn-lg" id="signin-start">${icon("external")}${tx("onboarding.signin.start")}</button></div>`;
    }
  } else {
    body = renderDeviceStep(s);
  }
  return `<section class="onboard" aria-labelledby="ob-title">${stepsHtml(st)}<div class="ob-card">${body}</div></section>`;
}

// Step 3: the hardware-identifier consent comes first (the agent will not enroll without it), then the
// "is this a reinstall?" choice, enrollment, and a "you're set" summary with the benchmark and start-at-sign-in.
function renderDeviceStep(s) {
  const si = (s && s.signin) || {};
  const head = (key) => `<p class="eyebrow">${stepLine(3)}</p><h1 id="ob-title">${tx(key)}</h1>`;
  if (!s || !s.signed_in) {
    return `${head("onboarding.device.signInFirst.title")}<p class="lede">${tx("onboarding.device.signInFirst.lede")}</p>
      <div class="ob-actions"><button type="button" class="btn btn-primary" data-go="signin">${tx("onboarding.device.signInFirst.button")}</button></div>`;
  }
  const enrolled = !!s.device_id || si.state === "done";
  if (onboardStep === "consent" || (!enrolled && (si.state === "consent_required" || (s.hw_consent !== "accepted" && si.state !== "blocked")))) {
    if (!consentCache) loadConsent();
    return consentHtml(consentCache, s.hw_consent);
  }
  if (!enrolled) return enrollStepHtml(si, enrollUi);
  const set = s.settings || {};
  const b = s.status && s.status.benchmark;
  const limits = { minutes: n0(set.idle_minutes), temp: n0(set.temp_cap_c) };
  return `
    <div class="ob-center"><div class="ob-success">${icon("check")}</div>
      ${head("onboarding.device.done.title")}<p class="lede">${tx("onboarding.device.done.lede")}</p></div>
    <div class="setup-grid">
      <section class="inset" aria-labelledby="su-hw"><h2 id="su-hw">${icon("device")}${tx("device.thisComputer")}</h2>${hardwareHtml(s.hardware, s.status && s.status.backend, s.key_storage)}
        <p class="muted small">${tx("onboarding.device.done.infoOnly")}</p>
        ${cappedDevice(s) ? `<div class="note note-warn small">${icon("alert")}<span>${tx("device.capped")}</span></div>` : ""}</section>
      <section class="inset" aria-labelledby="su-bench"><h2 id="su-bench">${icon("gauge")}${tx("bench.title")}</h2>${benchHtml(b, Date.now(), set.benchmark_now)}</section>
    </div>
    <section class="inset">${autostartHtml()}</section>
    <p class="muted small">${set.never_on_battery ? tx("onboarding.device.done.summaryBattery", limits) : tx("onboarding.device.done.summary", limits)}</p>
    <div class="ob-actions"><span class="spacer"></span><button type="button" class="btn btn-primary btn-lg" data-go="">${tx("onboarding.device.done.open")}${icon("arrow")}</button></div>`;
}

// CR-T213-01: the server enrolled this device as capped (no verified hardware security chip: Probation for good).
// Before the server's answer, a software key means the same.
function cappedDevice(snap) {
  return snap.trust_ceiling ? snap.trust_ceiling === "capped" : snap.key_storage !== "tpm";
}

// ------------------------------------------------------------------ main views
function renderLoading() {
  return `<div class="skeleton" aria-busy="true" aria-label="${tx("common.loading")}"><div class="sk sk-hero"></div><div class="grid-2"><div class="sk sk-card"></div><div class="sk sk-card"></div></div>
    <p class="row muted"><span class="spinner" aria-hidden="true"></span>${tx("loading.starting")}</p></div>`;
}

function renderAgentDown() {
  return `<section class="state-page" aria-labelledby="down-h">
    <div class="state-icon tone-danger">${icon("power")}</div>
    <h1 id="down-h">${tx("agentDown.title")}</h1>
    <p class="lede">${tx("agentDown.lede")}</p>
    <p class="state-detail mono">${esc(snap.error)}</p>
    <div class="row row-center"><button type="button" class="btn btn-primary btn-lg" id="start-core">${icon("play")}${tx("agentDown.start")}</button></div>
  </section>`;
}

function renderHome() {
  const s = snap;
  const st = s.status || {};
  const set = s.settings || {};
  const h = heroState(s, Date.now());
  const cap = Number(set.daily_cap_hours);
  const capPct = cap > 0 ? Math.min(100, Math.round((Number(s.worked_today_s) || 0) / 36 / cap)) : 0;
  const est = estimateCache && estimateCache.ok;
  const estMult = est ? Number(est.multiplier || 1) : 1;
  return `${noticesHtml(st.notices)}${clockHtml(st.clock_offset_s)}
    <section class="hero tone-${h.tone}" aria-labelledby="hero-title">
      <div class="orb orb-${h.key}" aria-hidden="true"><span class="orb-ring"></span><span class="orb-ring orb-ring-2"></span><span class="orb-core">${icon(h.icon)}</span></div>
      <div class="hero-text">
        <p class="eyebrow">${tx("home.status")}</p>
        <h1 id="hero-title">${esc(h.title)}</h1>
        ${h.sub ? `<p class="hero-sub">${esc(h.sub)}</p>` : ""}
        <div class="chips"><span class="chip">${icon("settings")}${tx("home.mode", { mode: modeLabel(set.mode) })}</span><span class="chip">${icon("shieldCheck")}${tx("home.onlyVerified")}</span></div>
      </div>
      <div class="hero-action">${heroActionHtml(h)}</div>
    </section>
    <div class="grid-2">
      <section class="card" aria-labelledby="today-h">
        ${cardHead("today-h", "clock", tx("home.today.title"), tx("home.today.sub"))}
        <div class="today-main"><span class="today-value">${esc(duration(s.worked_today_s))}</span><span class="metric-label">${tx("home.today.worked")}</span></div>
        <div class="metrics">
          <div class="metric"><span class="metric-value">${esc(num(st.jobs_completed))}</span><span class="metric-label">${tx("home.today.jobsFinished")}</span></div>
          <div class="metric"><span class="metric-value">${esc(num(st.jobs_abandoned))}</span><span class="metric-label">${tx("home.today.stoppedEarly")}</span></div>
        </div>
        ${cap > 0 ? `<div class="meter"><div class="meter-top"><span class="small muted">${tx("home.today.dailyLimit")}</span><span class="small">${tx("home.today.capUsage", { ratio: capPct / 100, hours: cap })}</span></div>
          <div class="progress" role="progressbar" aria-valuenow="${esc(capPct)}" aria-valuemin="0" aria-valuemax="100" aria-label="${tx("home.today.capLabel")}"><div class="progress-fill" data-w="${esc(capPct)}"></div></div></div>`
          : `<p class="muted small">${rich("home.today.noLimit", null, { link: viewTag("settings") })}</p>`}
      </section>
      <section class="card" aria-labelledby="hw-h">
        ${cardHead("hw-h", "chip", tx("home.hardware.title"), tx("home.hardware.sub"))}
        ${hardwareHtml(s.hardware, st.backend)}
      </section>
    </div>
    ${est ? `<section class="card card-row" aria-labelledby="est-mini-h">
        <span class="icon-bubble icon-bubble-ok">${icon("wallet")}</span>
        <div class="grow"><h2 id="est-mini-h" class="small-h">${tx("home.estimate.title")}</h2>
          <p class="est-mini"><strong>${tx("common.range", { low: usd(est.low_usd), high: usd(est.high_usd) })}</strong> <span class="muted small">${estMult > 1 ? tx("home.estimate.noteBonus") : tx("home.estimate.note")}</span></p></div>
        <button type="button" class="btn" data-view="earnings">${tx("home.estimate.seeEarnings")}${icon("arrow")}</button>
      </section>` : ""}
    ${st.last_error && st.connection !== "connected" ? `<div class="note">${icon("info")}<span>${tx("home.lastProblem", { error: st.last_error })}</span></div>` : ""}`;
}

function renderEarnings() {
  const e = earnCache;
  const w = walletCache;
  return `${pageHead(tx("earnings.title"), tx("earnings.lede"))}
    <section class="card" aria-labelledby="est-h">
      ${cardHead("est-h", "sparkle", tx("estimate.title"), tx("estimate.sub"))}
      ${estimateHtml(estimateCache)}
    </section>
    <section class="card" aria-labelledby="tot-h">
      ${cardHead("tot-h", "hourglass", tx("earnings.statusTitle"), tx("earnings.statusSub"))}
      ${!e ? `<div class="row"><div class="spinner"></div><span class="muted">${tx("common.loading")}</span></div>`
        : e.err ? `<div class="note">${icon("info")}<span>${tx("earnings.unavailable", { error: e.err })}</span></div>`
        : earningsHtml(e.ok)}
    </section>
    <section class="card" aria-labelledby="wallet-h">
      ${cardHead("wallet-h", "wallet", tx("payout.title"), tx("payout.sub"))}
      <div class="wallets">${!w ? `<span class="muted">${tx("common.loading")}</span>` : w.err ? `<p class="muted">${tx("payout.unavailable")}</p>` : walletHtml(w.ok)}</div>
      <div class="row"><button type="button" class="btn" data-link="wallet">${icon("external")}${tx("payout.manage")}</button>
        <button type="button" class="btn btn-ghost" data-link="verify">${tx("payout.verify")}</button></div>
      <p class="fine">${tx("payout.fine")}</p>
    </section>`;
}

function renderDevice() {
  const st = snap.status || {};
  const set = snap.settings || {};
  const d = deviceCache && deviceCache.ok;
  const sched = scheduleSummary(set.schedule);
  return `${pageHead(tx("device.title"), tx("device.lede"))}
    <section class="card" aria-label="${tx("device.cardLabel")}">
      ${deviceHeadHtml(d)}
      ${hardwareHtml(snap.hardware, st.backend, snap.key_storage)}
      ${cappedDevice(snap) ? `<div class="note note-warn small">${icon("alert")}<span>${tx("device.capped")}</span></div>` : ""}
      <details class="more" id="dev-more"><summary>${tx("device.technical")}</summary>
        <dl class="kv">
          <dt>${tx("device.id")}</dt><dd class="mono small">${esc(snap.device_id || t("device.notRegistered"))}</dd>
          <dt>${tx("hw.deviceKey")}</dt><dd>${snap.key_storage === "tpm" ? tx("device.keyTpm") : tx("device.keySoftware")}</dd>
          <dt>${tx("device.trustCeiling")}</dt><dd>${esc(snap.trust_ceiling || "—")}</dd>
          <dt>${tx("device.sandbox")}</dt><dd>${esc(st.sandbox || t("device.notUsedYet"))}</dd>
          <dt>${tx("device.agentVersion")}</dt><dd>${esc(snap.version)}</dd>
        </dl></details>
      <p class="fine">${tx("device.sandboxFine")}</p>
    </section>
    <section class="card" aria-labelledby="perf-h">${cardHead("perf-h", "gauge", tx("perf.title"), tx("perf.sub"))}
      ${perfHtml(snap.performance, d, !deviceCache)}</section>
    <div class="grid-2">
      <section class="card" aria-labelledby="bench-h">${cardHead("bench-h", "gauge", tx("bench.title"), "")}${benchHtml(st.benchmark, Date.now(), set.benchmark_now)}</section>
      <section class="card" aria-labelledby="rel-h">${cardHead("rel-h", "shieldCheck", tx("reliability.title"), "")}
        ${!deviceCache ? `<div class="row"><div class="spinner"></div><span class="muted">${tx("common.loading")}</span></div>` : d ? reliabilityHtml(d.reliability) : `<p class="muted small">${tx("device.relUnavailable")}</p>`}</section>
    </div>
    <form id="controls" novalidate>
      <section class="card" aria-labelledby="lim-h">
        ${cardHead("lim-h", "thermo", tx("device.limits.title"), tx("device.limits.sub"))}
        <div class="field"><div class="field-top"><label for="temp">${tx("device.limits.pauseAbove")}</label><span class="field-val"><output id="temp-out" for="temp">${esc(set.temp_cap_c)}</output> ${tx("common.unit.celsius")}</span></div>
          <input id="temp" type="range" min="65" max="85" value="${esc(set.temp_cap_c)}" name="temp_cap_c"/>
          <span class="muted small">${tx("device.limits.tempMax")}</span></div>
        <div class="field"><div class="field-top"><label for="power">${tx("device.limits.power")}</label><span class="field-val"><output id="power-out" for="power">${esc(set.power_pct)}</output>%</span></div>
          <input id="power" type="range" min="10" max="100" step="10" value="${esc(set.power_pct)}" name="power_pct"/></div>
        <div class="switch"><label for="batt"><strong>${tx("device.limits.battery.title")}</strong><span class="muted small">${tx("device.limits.battery.hint")}</span></label>
          <input id="batt" class="toggle" type="checkbox" name="never_on_battery" ${set.never_on_battery ? "checked" : ""}/></div>
        <div class="switch"><label for="fs"><strong>${tx("device.limits.fullscreen.title")}</strong><span class="muted small">${tx("device.limits.fullscreen.hint")}</span></label>
          <input id="fs" class="toggle" type="checkbox" name="pause_in_fullscreen" ${set.pause_in_fullscreen ? "checked" : ""}/></div>
      </section>
    </form>
    <section class="card" aria-labelledby="sch-h">
      ${cardHead("sch-h", "calendar", tx("schedule.title"), tx("device.scheduleSub", { mode: modeLabel(set.mode) }))}
      ${sched.length ? `<ul class="sched">${sched.map((x) => `<li>${icon("clock")}${esc(x)}</li>`).join("")}</ul>` : `<p class="muted small">${tx("device.noWindows")}</p>`}
      <div class="row"><button type="button" class="btn" data-view="settings">${tx("device.changeSchedule")}</button>
        ${set.daily_cap_hours ? `<span class="muted small">${tx("device.dailyLimit", { hours: n0(set.daily_cap_hours) })}</span>` : `<span class="muted small">${tx("device.noDailyLimit")}</span>`}</div>
    </section>
    <section class="card" aria-labelledby="act-h">
      ${cardHead("act-h", "user", tx("device.account.title"), "")}
      <p class="muted small">${esc(deviceStateText(d))}</p>
      <div class="row">
        <button type="button" class="btn" data-control="pause">${icon("pause")}${tx("device.account.pause")}</button>
        <button type="button" class="btn" data-control="resume">${icon("play")}${tx("common.resume")}</button>
        <button type="button" class="btn btn-ghost" data-link="devices">${icon("external")}${tx("device.account.manage")}</button>
      </div>
      <p class="fine">${tx("device.account.fine")}</p>
    </section>`;
}

// Start at sign-in (the app's login item, not an agent setting). During setup the switch proposes "on" until the
// user decides; afterwards it shows the real state.
let autostartState = null;
function autostartHtml() {
  const proposed = autostartState === null ? !store.get("vouch.autostart_decided", false) : autostartState;
  return `<div class="switch"><label for="autostart"><strong>${tx("autostart.title")}</strong>
    <span class="muted small">${tx("autostart.hint")}</span></label>
    <input id="autostart" class="toggle" type="checkbox" ${proposed ? "checked" : ""}/></div>`;
}
async function loadAutostart() {
  if (!TAURI || !store.get("vouch.autostart_decided", false)) return;
  try {
    autostartState = await invoke("autostart_get");
    const el = document.getElementById("autostart");
    if (el) el.checked = autostartState;
  } catch (e) { /* leave the switch as drawn */ }
}
async function setAutostart(enabled) {
  store.set("vouch.autostart_decided", true);
  try {
    autostartState = await invoke("autostart_set", { enabled });
    announce(autostartState ? t("autostart.on") : t("autostart.off"));
  } catch (e) { const m = t("autostart.failed", { error: String(e) }); announce(m); toast(m, "danger"); }
  const el = document.getElementById("autostart");
  if (el && autostartState !== null) el.checked = autostartState;
}

function updateHtml() {
  const u = updateState;
  if (!u) return "";
  if (u.checking) return tx("update.checking");
  if (u.err) return esc(u.err);
  return u.ok && u.ok.available ? `${tx("update.available", { version: u.ok.version })} <button type="button" class="btn btn-primary btn-sm" id="install-update">${icon("download")}${tx("update.install")}</button>` : tx("update.upToDate");
}

function renderSettings() {
  const th = currentTheme();
  const seg = (v, key, ic) => `<button type="button" class="seg-btn" data-theme-set="${v}" aria-pressed="${th === v ? "true" : "false"}">${icon(ic)}${tx(key)}</button>`;
  const consent = snap.hw_consent === "accepted" ? t("settings.privacy.consentAllowed") : snap.hw_consent === "refused" ? t("settings.privacy.consentRefused") : t("settings.privacy.consentNone");
  const devTitle = tx("common.devBuildTitle");
  return `${pageHead(tx("settings.title"), tx("settings.lede"))}
    ${controlsHtml(snap.settings)}
    <section class="card" aria-labelledby="lang-h">${cardHead("lang-h", "globe", tx("settings.language.title"), tx("settings.language.sub"))}
      ${languageHtml(savedLocale(), systemLocale(), I18N.LOCALES)}</section>
    <section class="card" aria-labelledby="start-h">${cardHead("start-h", "power", tx("settings.startup"), "")}${autostartHtml()}</section>
    <section class="card" aria-labelledby="look-h">${cardHead("look-h", "sun", tx("settings.theme.title"), tx("settings.theme.sub"))}
      <div class="seg" role="group" aria-label="${tx("settings.theme.group")}">${seg("system", "settings.theme.system", "device")}${seg("light", "settings.theme.light", "sun")}${seg("dark", "settings.theme.dark", "moon")}</div></section>
    <section class="card" aria-labelledby="priv-h">${cardHead("priv-h", "eye", tx("settings.privacy.title"), "")}
      <ul class="bullets small">
        <li>${tx("settings.privacy.sandbox")}</li>
        <li>${tx("settings.privacy.inputs")}</li>
        <li>${tx("settings.privacy.readOnly")}</li>
        <li>${tx("settings.privacy.counted")}</li>
      </ul>
      <dl class="kv"><dt>${tx("consent.title")}</dt><dd>${esc(consent)}</dd></dl>
      <div class="row"><button type="button" class="btn btn-ghost" data-link="trust">${icon("external")}${tx("settings.privacy.howVerification")}</button></div></section>
    <section class="card" aria-labelledby="acct-h">${cardHead("acct-h", "user", tx("settings.account.title"), snap.signed_in ? tx("settings.account.signedIn") : tx("settings.account.notSignedIn"))}
      <div class="row"><button type="button" class="btn" data-link="dashboard">${icon("external")}${tx("settings.account.openDashboard")}</button>
        <span class="spacer"></span>${snap.signed_in && !snap.device_id ? `<button type="button" class="btn btn-ghost" id="enroll-reset">${tx("onboarding.device.startOver")}</button>` : ""}${snap.signed_in ? `<button type="button" class="btn btn-ghost" id="signout">${icon("logout")}${tx("settings.account.signOut")}</button>` : `<button type="button" class="btn btn-primary" data-go-onboard="signin">${icon("user")}${tx("common.signIn")}</button>`}</div>
      <div class="sub-block"><h3>${tx("settings.recover.title")}</h3>
        <p class="muted small">${tx("settings.recover.hint")}</p>
        ${recoverMsg !== null ? `<div class="note note-info">${icon("info")}<span>${esc(recoverMsg)}</span></div>`
          : recoverOpen ? `<div class="field"><label for="recover-code">${tx("settings.recover.codeLabel")}</label><input id="recover-code" data-keep autocomplete="off" spellcheck="false" dir="ltr"/></div>
            <div class="row"><button type="button" class="btn btn-primary" id="recover-send">${icon("key")}${tx("settings.recover.sign")}</button></div>`
          : `<button type="button" class="btn" id="recover-start">${tx("settings.recover.start")}</button>`}</div>
      <details class="more" id="adv-repair"><summary>${tx("settings.repair.summary")}</summary>
        <p class="small">${tx("settings.repair.text")}</p>
        <button type="button" class="btn" id="repair-identity">${icon("key")}${tx("settings.repair.button")}</button></details></section>
    <section class="card" aria-labelledby="about-h">${cardHead("about-h", "info", tx("settings.about.title"), tx("settings.about.sub"))}
      <dl class="kv">
        <dt>${tx("device.agentVersion")}</dt><dd>${esc(snap.version || "—")}</dd>
        <dt>${tx("settings.about.channel")}</dt><dd>${esc((buildInfo && buildInfo.channel) || "—")}</dd>
        <dt>${tx("settings.about.build")}</dt><dd>${devBuild ? `<span class="badge badge-dev" title="${devTitle}">${tx("common.devBuild")}</span>` : tx("settings.about.release")}</dd>
      </dl>
      <div class="row"><button type="button" class="btn" id="check-update">${icon("refresh")}${tx("settings.about.check")}</button><span id="update-result" class="muted small" role="status">${updateHtml()}</span></div></section>
    <section class="card card-danger" aria-labelledby="rm-h">${cardHead("rm-h", "trash", tx("settings.remove.title"), "")}
      <p class="small">${tx("settings.remove.text")}</p>
      <div class="row"><label class="row small" for="remove-confirm">${tx("settings.remove.confirmLabel", { word: REMOVE_WORD })}</label><input id="remove-confirm" class="input-narrow" data-keep autocomplete="off" dir="ltr"/>
        <button type="button" class="btn btn-danger" id="remove-device">${icon("trash")}${tx("settings.remove.title")}</button></div></section>`;
}
// the word typed to confirm removal stays the same in every language (the agent checks a fixed value)
const REMOVE_WORD = "REMOVE";

function readControls(form, base) {
  const s = structuredClone(base);
  const el = form.elements;
  const mode = form.querySelector('input[name="mode"]:checked');
  if (mode) s.mode = mode.value;
  if (el.idle_minutes) s.idle_minutes = Number(el.idle_minutes.value);
  if (el.temp_cap_c) s.temp_cap_c = Number(el.temp_cap_c.value);
  if (el.power_pct) s.power_pct = Number(el.power_pct.value);
  if (el.never_on_battery) s.never_on_battery = el.never_on_battery.checked;
  if (el.pause_in_fullscreen) s.pause_in_fullscreen = el.pause_in_fullscreen.checked;
  if (el.daily_cap_hours) {
    const cap = el.daily_cap_hours.value.trim();
    s.daily_cap_hours = cap === "" ? null : Number(cap);
  }
  if (form.querySelector("#windows")) {
    const toMin = (v) => { const [h, m] = (v || "0:0").split(":").map(Number); return h * 60 + m; };
    s.schedule = [...form.querySelectorAll("[data-win]")].map((row) => ({
      days: [...row.querySelectorAll("[data-day]")].reduce((acc, c) => acc | (c.checked ? 1 << Number(c.dataset.day) : 0), 0),
      start_min: toMin(row.querySelector('[data-k="start"]').value),
      end_min: toMin(row.querySelector('[data-k="end"]').value),
    }));
  }
  return s;
}

let saveTimer = null;
let pendingSettings = null;
function saveControls(form, immediate) {
  pendingSettings = readControls(form, snap.settings);
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const next = pendingSettings;
    try {
      snap.settings = await core("settings.set", next);
      announce(t("toast.settingsSaved"));
      toast(t("toast.saved"));
    } catch (e) { const m = t("toast.saveFailed", { error: String(e) }); announce(m); toast(m, "danger"); }
  }, immediate ? 0 : 350);
}
const OUTS = { idle_minutes: "idle-out", temp_cap_c: "temp-out", power_pct: "power-out" };
document.addEventListener("input", (e) => {
  const form = e.target.closest && e.target.closest("#controls");
  if (!form || !snap || !snap.settings) return;
  const o = OUTS[e.target.name];
  if (o) { const out = document.getElementById(o); if (out) out.textContent = e.target.value; }
  saveControls(form, false);
});
document.addEventListener("change", (e) => {
  if (e.target.id === "autostart") return setAutostart(e.target.checked);
  if (e.target.id === "locale-select") return chooseLocale(e.target.value);
  const form = e.target.closest && e.target.closest("#controls");
  if (form && snap && snap.settings) saveControls(form, true);
});

// ------------------------------------------------------------------ events
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn || btn.closest("#tabs")) return;
  try {
    if (btn.dataset.go !== undefined) return goStep(btn.dataset.go || null);
    if (btn.dataset.goOnboard) return goStep(btn.dataset.goOnboard);
    if (btn.dataset.view) return setView(btn.dataset.view);
    if (btn.dataset.themeSet) return setTheme(btn.dataset.themeSet);
    if (btn.dataset.link) return await invoke("open_link", { kind: btn.dataset.link });
    if (btn.dataset.control) {
      await core("device.control", { action: btn.dataset.control });
      const m = btn.dataset.control === "pause" ? t("toast.pausedServer") : t("toast.resumed");
      announce(m);
      toast(m);
      deviceCache = null;
      if (view === "device") loadDevice();
      return refresh();
    }
    if (btn.dataset.replace !== undefined) return await startEnroll(btn.dataset.replace || null);
    if (btn.dataset.remove !== undefined) {
      const form = document.getElementById("controls");
      const s = readControls(form, snap.settings);
      s.schedule.splice(Number(btn.dataset.remove), 1);
      snap.settings = await core("settings.set", s);
      return render({ force: true });
    }
    switch (btn.id) {
      case "agree": return goStep("signin");
      case "consent-accept":
        await core("hw_consent.set", { accept: true, text_sha256: consentCache.text_sha256 });
        await refresh();
        return goStep("device");
      case "consent-refuse":
        await core("hw_consent.set", { accept: false, text_sha256: consentCache.text_sha256 });
        return refresh().then(() => render({ force: true }));
      case "add-window": {
        const form = document.getElementById("controls");
        const s = readControls(form, snap.settings);
        snap.settings = await core("settings.set", { ...s, schedule: [...s.schedule, { days: 0b0011111, start_min: 22 * 60, end_min: 7 * 60 }] });
        return render({ force: true });
      }
      case "remove-device": {
        const v = (document.getElementById("remove-confirm") || {}).value || "";
        if (v.trim() !== REMOVE_WORD) { const m = t("settings.remove.confirmLabel", { word: REMOVE_WORD }); announce(m); toast(m, "danger"); return; }
        await core("device.control", { action: "self_revoke", confirm: "remove" });
        announce(t("toast.removed"));
        toast(t("toast.removed"));
        return refresh();
      }
      case "recover-start":
        recoverOpen = true;
        render({ force: true });
        { const c = document.getElementById("recover-code"); if (c) c.focus(); }
        return;
      case "recover-send": {
        const code = document.getElementById("recover-code").value;
        const r = await core("recovery.prove", { code });
        recoverMsg = String((r && r.message) ?? "");
        return render({ force: true });
      }
      case "repair-identity": await core("identity.repair"); announce(t("toast.repaired")); toast(t("toast.repaired")); return refresh();
      case "signin-start":
        btn.disabled = true;
        await core("signin.start");
        await refresh();
        await invoke("open_link", { kind: "signin" }).catch(() => {});
        return;
      case "bench-now": await core("benchmark.now", { enabled: btn.getAttribute("aria-pressed") !== "true" }); return refresh();
      case "pause": await core("pause", { minutes: 60 }); announce(t("toast.pausedHour")); return refresh();
      case "resume": await core("resume"); announce(t("toast.resumed")); return refresh();
      case "reconnect": await core("reconnect"); announce(t("toast.reconnecting")); toast(t("toast.reconnecting")); return refresh();
      case "start-core": await invoke("ensure_core"); return refresh();
      case "signout": enrollReset(); await core("signout"); return refresh();
      case "enroll-back": return await leaveEnroll(false);
      case "enroll-reset": return await leaveEnroll(true);
      case "check-update": {
        updateState = { checking: true };
        render({ force: true });
        try { updateState = { ok: await invoke("check_update") }; } catch (err) { updateState = { err: String(err) }; }
        return render({ force: true });
      }
      case "install-update": return await invoke("install_update");
    }
  } catch (err) {
    announce(String(err));
    toast(String(err), "danger");
    if (btn.id === "signin-start") btn.disabled = false;
  }
});

document.addEventListener("scroll", onDisclosureScroll, true);
function onDisclosureScroll(e) {
  if (!(e.target instanceof Element) || e.target.id !== "disclosure") return;
  const d = e.target;
  if (d.scrollTop + d.clientHeight >= d.scrollHeight - 8) {
    const b = document.getElementById("agree");
    if (b && b.disabled) { b.disabled = false; document.getElementById("scroll-hint").textContent = ""; }
  }
}
// short screens: if the disclosure doesn't scroll at all, enable right away
new MutationObserver(() => {
  const d = document.getElementById("disclosure");
  const b = document.getElementById("agree");
  if (d && b && b.disabled && d.scrollHeight <= d.clientHeight + 8) { b.disabled = false; document.getElementById("scroll-hint").textContent = ""; }
}).observe($main, { childList: true });

// ------------------------------------------------------------------ boot
// Browser preview only: #view=<home|earnings|device|settings> skips onboarding, #step=<welcome|signin|consent|device>
// opens a setup step, #theme=<light|dark> picks a theme, #lang=<code> picks a language.
if (!TAURI && location.hash) {
  if (PREVIEW.get("view")) { onboardStep = null; view = PREVIEW.get("view"); }
  if (PREVIEW.get("step")) onboardStep = normStep(PREVIEW.get("step"));
  if (PREVIEW.get("theme")) document.documentElement.dataset.theme = PREVIEW.get("theme");
}
let ticks = 0;
let localeRetry = false;
(async () => {
  await applyLocale((!TAURI && I18N.match([PREVIEW.get("lang")])) || savedLocale() || systemLocale());
  booted = true;
  setView(view);
  if (TAURI) { try { await invoke("ensure_core"); } catch (e) { /* shown by refresh */ } }
  await refresh();
  if (onboardStep === "consent" || onboardStep === "device") loadConsent();
  loadFor(view);
  // "DEV BUILD" stays unless both the app and its agent are release builds
  try {
    const b = await invoke("build_info");
    buildInfo = b;
    const agentDev = !snap || snap.error || !snap.build || snap.build.dev_build !== false;
    const badge = document.getElementById("dev-badge");
    if (b && b.dev_build === false && !agentDev) { devBuild = false; if (badge) badge.remove(); }
  } catch (e) { /* keep the marker */ }
  render({ force: true });
  setInterval(() => {
    // the English messages are the fallback for every locale: if they did not arrive at start, keep asking
    if (!enMessages && !localeRetry) {
      localeRetry = true;
      applyLocale(savedLocale() || systemLocale()).then(() => { if (enMessages) render({ force: true }); }).finally(() => { localeRetry = false; });
    }
    refresh();
    if (++ticks % 20 === 0) loadFor(view); // server figures again every 30 s while a view is open
  }, 1500);
})();

// ------------------------------------------------------------------ demo backend (browser preview only)
// Hash options: #state=<earning|idle|paused|offline|signedout|down|tally|update>, #signin=<idle|pending|consent_required|
// choose_replace|blocked|enrolling|done>, #pilot=1, #bench=<running|sent|none>, #name=<device name>. The demo's agent and
// server texts stay English, like the real ones.
function demoInvoke(cmd, args) {
  const now = Date.now();
  const p = PREVIEW;
  const step = p.get("step");
  const conf = demoInvoke.conf || (demoInvoke.conf = (() => {
    const signin = p.get("signin") || (step === "welcome" ? "idle" : step === "signin" ? "pending" : step === "consent" ? "consent_required" : "done");
    return {
      state: p.get("state") || "earning", signin,
      consent: p.get("consent") || (["idle", "pending", "consent_required"].includes(signin) ? null : "accepted"),
      pilot: p.get("pilot") === "1", bench: p.get("bench") || (step === "device" ? "running" : "sent"), why: p.get("why"), autostart: true,
    };
  })());
  const settings = demoInvoke.settings || (demoInvoke.settings = { mode: "idle_only", idle_minutes: 10, temp_cap_c: 80, power_pct: 90, never_on_battery: true, pause_in_fullscreen: true,
    schedule: [{ days: 0b0011111, start_min: 22 * 60, end_min: 7 * 60 }], daily_cap_hours: 8, paused_until_ms: conf.state === "paused" ? now + 47 * 60000 : null, benchmark_now: false });
  const m = args && args.method;
  const R = (v) => Promise.resolve(v);
  if (cmd === "ensure_core") { if (conf.state === "down") conf.state = "earning"; return R(null); }
  if (cmd === "open_link") return R(null);
  if (cmd === "check_update") return R({ available: false });
  if (cmd === "install_update") return R(null);
  if (cmd === "build_info") return R({ channel: "dev", dev_build: true });
  if (cmd === "i18n_messages") return fetch(`locales/${encodeURIComponent(I18N.resolve(args && args.locale))}.json`).then((r) => r.text());
  if (cmd === "set_locale") return R(I18N.resolve(args && args.locale));
  if (cmd === "autostart_get") return R(conf.autostart);
  if (cmd === "autostart_set") { conf.autostart = !!(args && args.enabled); return R(conf.autostart); }
  if (conf.state === "down") return Promise.reject("agent not running");
  if (m === "hw_consent.get") return R({ kind: "hw_identifiers", version: "2026-11-19.draft-2", text: "The desktop app sends identifiers of this computer's hardware (security chip, graphics card, board, disk, network adapters) to Vouch Compute so that one physical machine counts as one device. We keep only keyed fingerprints of them, never the raw values such as MAC addresses or serial numbers. Withdrawing this stops further reports, and a device without it cannot be enrolled for paid work.", text_sha256: "0".repeat(64), decision: conf.consent, refused_message: "Vouch Compute can't register this computer for paid work without the hardware check." });
  if (m === "hw_consent.set") {
    conf.consent = args.params.accept ? "accepted" : "refused";
    if (args.params.accept && ["consent_required", "blocked"].includes(conf.signin)) conf.signin = "done";
    else if (!args.params.accept && conf.signin === "consent_required") conf.signin = "blocked";
    return R({});
  }
  if (m === "signin.start") { conf.signin = "pending"; return R({ state: "pending" }); }
  if (m === "enroll") { conf.signin = "done"; return R({ state: "done" }); }
  if (m === "signout" || m === "signin.reset") { conf.state = "signedout"; conf.signin = "idle"; return R({}); }
  if (m === "enroll.cancel") { if (conf.signin === "enrolling") conf.signin = "idle"; return R({ state: conf.signin }); }
  if (m === "pause") { settings.paused_until_ms = now + args.params.minutes * 60000; conf.state = "paused"; return R(settings); }
  if (m === "resume") { settings.paused_until_ms = null; conf.state = "earning"; return R(settings); }
  if (m === "reconnect" || m === "device.control" || m === "identity.repair") return R({});
  if (m === "benchmark.now") { settings.benchmark_now = !!args.params.enabled; return R(settings); }
  if (m === "recovery.prove") return R({ message: "This device signed the recovery. Finish it on the web." });
  if (m === "device") {
    if (conf.state === "signedout" || conf.state === "offline") return Promise.reject("device not enrolled");
    return R({ device_id: "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f", name: p.get("name") || "Gaming PC", connection: "online", activity: conf.state === "earning" ? "working" : conf.state === "paused" ? "paused" : "idle",
      paused_by: conf.state === "tally" ? "tally" : null, status: "probation", tier: "probation", benchmark_date: "2026-11-24", reliability: { tier: "stable", since_day: "2026-11-12", benefits: { queue_priority: "higher", bonus_pct: 5 }, improve: ["keep_regular_hours", "avoid_disconnects"] } });
  }
  if (m === "status") {
    const signedIn = conf.state !== "signedout" && !["idle", "pending", "error"].includes(conf.signin);
    const enrolled = signedIn && conf.signin === "done";
    const connection = !signedIn ? "not_signed_in" : !enrolled ? "not_enrolled" : { offline: "offline", update: "update_required" }[conf.state] || "connected";
    const signinObj = { pending: { state: "pending", user_code: "QJ4K-7XPM", verification_uri: "", verification_uri_complete: "", expires_at_ms: now + 600000 },
      choose_replace: { state: "choose_replace", candidates: [{ device_id: "1a2b3c4d-0000-4000-8000-000000000001", name: "Gaming PC", last_seen_day: "2026-10-02" }] },
      blocked: conf.consent === "refused" ? { state: "blocked", code: "consent_refused", message: "Vouch Compute can't register this computer for paid work without the hardware check." }
        : { state: "blocked", code: "device_limit", message: "Your account has reached its device limit. Verify your identity on the web to add more." } }[conf.signin] || { state: conf.signin };
    const measured = { unit: "token", per_second: conf.bench === "running" ? 412.6 : 418.3, runs: conf.bench === "running" ? 180 : 470, backend: "onnxruntime-cpu" };
    const bench = conf.bench === "none" ? null : { benchmark_id: "b", state: conf.bench, started_ms: conf.bench === "running" ? now - 460000 : now - 1300000, duration_s: 1200,
      segments: conf.bench === "running" ? 7 : 20, model_id: "bge-m3", measured, ...(conf.why ? { stop_reason: conf.why } : {}) };
    const performance = conf.bench === "sent" ? [{ model_id: "bge-m3", benchmark_id: "b", measured, finished_ms: now - 100000, received: true }] : [];
    const decision = conf.state === "paused" ? { state: "pause", reason: "paused_by_user" } : { state: "run" };
    return R({ version: "0.2.1", signed_in: signedIn, device_id: enrolled ? "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f" : null, trust_ceiling: "capped", key_storage: "tpm",
      settings, worked_today_s: 5400 + (conf.state === "earning" ? 1260 : 0), signin: signinObj, performance, hw_consent: conf.consent, build: { dev_build: true }, links: {}, ...(conf.pilot ? { pilot: true } : {}),
      hardware: { os: "windows", arch: "x86_64", cpu: "AMD Ryzen 7 7800X3D 8-Core Processor", ram_mb: 32768, gpu: "NVIDIA GeForce RTX 4070 Ti", vram_mb: 12282 },
      status: { connection, decision, job: conf.state === "earning" && enrolled ? { model_id: "whisper-small", since_ms: now - 20000 } : null, jobs_completed: 37, jobs_abandoned: 1, benchmark: bench,
        sandbox: "WindowsLpac", last_error: conf.state === "offline" ? "connection refused (os error 10061)" : null, reconnect_in_s: conf.state === "offline" ? 12 : null, backend: "candle-cuda",
        notices: { paused_by: conf.state === "tally" ? "tally" : null, recovery_in_progress: false, reverify_required: false } } });
  }
  if (m === "settings.set") { Object.assign(settings, args.params); return R(settings); }
  if (conf.state === "signedout") return Promise.reject("not signed in");
  if (m === "estimate") return R({ low_usd: "9.000000000", high_usd: "24.000000000", period: "month", base: { low_usd: "3.500000000", high_usd: "9.000000000" }, multiplier: 3, multiplier_end: "2027-03-01T00:00:00Z", assumptions: { utilization: 0.35, hours_per_day: 14, electricity_usd_per_kwh: 0.15, avg_watts: 180, electricity_cost_usd: "4.100000000" }, rate_card_version: 1 });
  if (m === "earnings") return R({ as_of: "2026-11-17", totals: { pending: "2.310000000", in_escrow: "6.870000000", in_review: "0.120000000", releasable: "1.250000000", sent: "4.800000000", clawed_back: "0.000000000" }, this_week_verified_usd: "3.100000000", probation: { active: true, escrow_days: 21, ends_on: "2026-12-05" }, alerts: [] });
  if (m === "wallets") return R({ data: [{ wallet_id: "w", chain: "solana", address: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", status: "active", linked_at: "2026-11-01T00:00:00Z", payout_freeze_until: "2026-11-04T00:00:00Z" }] });
  return R({});
}
