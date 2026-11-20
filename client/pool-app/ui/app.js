// Vouch Compute UI. Talks only to the app's allow-listed Tauri commands (core proxy, open_link, updates, autostart).
// All agent and server text is escaped with esc() before it reaches the DOM. Without Tauri (plain browser preview) a
// demo backend is used so the screens can be reviewed.
"use strict";

// ---- pure (start)
// Rendering helpers with no DOM access (the node tests load this section on its own).
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
  let t = 0n;
  for (const x of xs) { const n = nanos(x); if (n !== null) t += n; }
  return fromNanos(t);
}
const day = (s) => (s ? new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—");
const time = (ms) => new Date(ms).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const num = (x) => (x !== null && x !== undefined && x !== "" && Number.isFinite(Number(x)) ? Number(x).toLocaleString() : "—");
function duration(sec) {
  const s = Number(sec);
  if (!Number.isFinite(s) || s < 0) return "—";
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  return h ? `${h} h ${String(m % 60).padStart(2, "0")} min` : `${m} min`;
}

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
};
const icon = (name, cls) =>
  `<svg class="i${cls ? " " + cls : ""}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${ICONS[name] || ""}"/></svg>`;
// the seal-check mark from the brand guide, drawn in currentColor
const MARK = `<svg class="mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false"><path d="M38.64 14.23A22 22 0 1 0 46.8 46.93"/><path d="M20.5 27L29.5 42L55.5 9"/></svg>`;

const MODE_LABELS = { idle_only: "When I'm away", scheduled: "On a schedule", always_on: "Always on" };

// The hero status. Returns plain text (escaped by the caller). `key` is one of earning, benchmark, idle, waiting,
// paused, offline, signed_out, setup, attention, down, loading; `action` picks the hero's button.
function heroState(s, now) {
  if (!s) return { key: "loading", tone: "muted", icon: "clock", title: "Starting…", sub: "Connecting to the Vouch Compute agent.", action: null };
  if (s.error) return { key: "down", tone: "danger", icon: "power", title: "Agent not running", sub: "The background agent that does the work isn't running.", action: "start" };
  const st = s.status || {};
  const c = st.connection;
  const d = st.decision || {};
  const set = s.settings || {};
  const n = st.notices || {};
  if (c === "not_signed_in") return { key: "signed_out", tone: "muted", icon: "user", title: "Signed out", sub: "Sign in so this computer can take verified work.", action: "signin" };
  if (c === "auth_failed") return { key: "signed_out", tone: "danger", icon: "user", title: "Signed out", sub: "This device was not recognised. Sign in again to re-register it.", action: "signin" };
  if (c === "offline" || c === "connecting") {
    const r = st.reconnect_in_s != null && Number.isFinite(Number(st.reconnect_in_s)) ? ` Retrying in ${Number(st.reconnect_in_s)} s.` : "";
    return { key: "offline", tone: "muted", icon: "wifiOff", title: c === "offline" ? "Offline" : "Connecting…", sub: `Can't reach the Vouch Compute network right now.${r}`, action: "reconnect" };
  }
  if (c === "not_enrolled") return { key: "setup", tone: "info", icon: "key", title: "Setting up this device", sub: "Registering this computer's key with your account.", action: null };
  if (c === "update_required") return { key: "attention", tone: "warn", icon: "download", title: "Update needed", sub: "This version can no longer connect. Install the update from Settings.", action: "update" };
  if (c === "revoked") return { key: "attention", tone: "danger", icon: "alert", title: "Device paused or suspended", sub: "This device can't take work right now. Vouch Compute retries now and then; check Devices on the web.", action: null };
  if (st.job) return { key: "earning", tone: "ok", icon: "check", title: "Earning", sub: `Running a ${st.job.model_id || "model"} job in the sandbox. It is paid once the server verifies it.`, action: "pause" };
  if (st.benchmark && st.benchmark.state === "running") return { key: "benchmark", tone: "info", icon: "gauge", title: "Benchmarking", sub: "Running the 20-minute sustained benchmark. It is not paid work.", action: "pause" };
  if (n.paused_by === "tally") return { key: "paused", tone: "warn", icon: "pause", title: "Paused", sub: "Paused by Vouch Compute. Contact support.", action: null };
  if (n.paused_by === "user") return { key: "paused", tone: "warn", icon: "pause", title: "Paused", sub: "Paused from the web or this app. This device gets no work until you resume it.", action: "resume-server" };
  const until = Number(set.paused_until_ms);
  if ((until && until > now) || d.reason === "paused_by_user")
    return { key: "paused", tone: "warn", icon: "pause", title: "Paused", sub: until && until > now ? `Until ${time(until)}. No new work starts while paused.` : "No new work starts while paused.", action: "resume" };
  if (d.state === "run") return { key: "idle", tone: "brand", icon: "clock", title: "Idle, waiting for jobs", sub: "Ready for work. Earnings depend on demand, so there may be quiet periods.", action: "pause" };
  const why = {
    user_active: ["muted", "clock", "Waiting for you to step away", `Starts after ${num(set.idle_minutes)} minutes without keyboard or mouse use.`],
    fullscreen: ["muted", "pause", "Paused for your game or presentation", "Resumes when you leave fullscreen."],
    on_battery: ["warn", "bolt", "Paused on battery", "Vouch Compute only works while plugged in."],
    battery_low: ["warn", "bolt", "Battery low", "Vouch Compute never runs on battery below 30%."],
    thermal: ["warn", "thermo", "Cooling down", `Paused until the temperature drops below your ${num(set.temp_cap_c)} °C limit.`],
    outside_schedule: ["muted", "calendar", "Outside your schedule", "Vouch Compute works only in the hours you chose."],
    daily_cap_reached: ["muted", "hourglass", "Daily limit reached", "Resumes tomorrow."],
  }[d.reason];
  if (why) return { key: "waiting", tone: why[0], icon: why[1], title: why[2], sub: why[3], action: "pause" };
  return { key: "paused", tone: "warn", icon: "pause", title: "Paused", sub: "", action: "pause" };
}

// Pilot banner: only when the agent's snapshot says so; hidden otherwise.
const isPilot = (s) => !!s && !s.error && (s.pilot === true || s.environment === "pilot");
const pilotHtml = (s) => (isPilot(s) ? `${icon("info")}<span>Pilot: test money (Solana devnet USDC)</span>` : "");

// The runtime of the last job, in plain words (the agent reports what really ran, never what was hoped for).
function backendLabel(b) {
  if (!b) return "No job yet";
  if (b === "onnxruntime-directml") return "Graphics card (DirectML)";
  if (b === "candle-cuda") return "Graphics card (CUDA)";
  if (b.endsWith("-cpu") || b === "onnxruntime") return "Processor (CPU)";
  return b;
}
const isAccelerated = (b) => b === "onnxruntime-directml" || b === "candle-cuda";

function hardwareHtml(hw, backend, keyStorage) {
  const h = hw || {};
  const gb = (mb) => (Number(mb) > 0 ? `${Math.round(Number(mb) / 1024)} GB` : "");
  const vram = gb(h.vram_mb);
  return `<dl class="hw">
      <div class="hw-row hw-main"><dt>${icon("chip")}Graphics card</dt>
        <dd><span class="hw-value">${esc(h.gpu || "Not detected")}${vram ? `<span class="muted">, ${esc(vram)}</span>` : ""}</span>
        ${isAccelerated(backend) ? `<span class="badge badge-ok">${icon("bolt")}Accelerated</span>` : ""}</dd></div>
      <div class="hw-row"><dt>${icon("layers")}Processor</dt><dd>${esc(h.cpu || "—")}</dd></div>
      <div class="hw-row"><dt>${icon("device")}Memory</dt><dd>${esc(gb(h.ram_mb) || "—")}</dd></div>
      <div class="hw-row"><dt>${icon("gauge")}Last job ran on</dt><dd>${esc(backendLabel(backend))}</dd></div>
      ${keyStorage === undefined ? "" : `<div class="hw-row"><dt>${icon("key")}Device key</dt><dd>${keyStorage === "tpm" ? `<span class="badge badge-ok">TPM 2.0</span>` : `<span class="badge badge-warn">Software key (dev)</span>`}</dd></div>`}
    </dl>`;
}

function benchHtml(b, now, benchNow) {
  const pct = b ? Math.max(0, Math.min(100, Math.round(((now - Number(b.started_ms)) / 1000 / Math.max(1, Number(b.duration_s) || 1)) * 100))) || 0 : 0;
  const state = !b ? `<p class="muted">Waiting for the network to send your benchmark. Keep Vouch Compute open and plugged in.</p>`
    : b.state === "running" ? `<div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Benchmark progress"><div class="progress-fill" data-w="${pct}"></div></div>
      <p class="muted small">${pct}% · ${esc(num(b.segments))} rounds done. You can keep using your computer lightly; moving the mouse doesn't cancel it if you chose "Run now".</p>`
    : b.state === "sent" || b.state === "received" ? `<div class="note note-ok">${icon("check")}<span>Benchmark finished. Results are checked by the server.</span></div>`
    : `<div class="note note-warn">${icon("alert")}<span>The benchmark stopped before it finished. It will start again later.</span></div>`;
  return `${state}
    <p class="muted small">A signed, 20-minute sustained test measures what this computer can really do. It is never paid, and you can stop it at any time.</p>
    <div class="row"><button type="button" class="btn ${benchNow ? "" : "btn-primary"}" id="bench-now" aria-pressed="${benchNow ? "true" : "false"}">${icon(benchNow ? "clock" : "play")}${benchNow ? "Run at first idle instead" : "Run now"}</button></div>`;
}

// Hardware-identifier consent (2.1.0): the agent's text is shown word for word (escaped, whitespace kept), never
// rewritten or shortened; the buttons send back its hash.
function consentHtml(c, decision) {
  if (!c || c.loading) return `<div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div>`;
  if (c.error) return `<div class="note note-danger">${icon("alert")}<span>${esc(c.error)}</span></div>`;
  const refused = decision === "refused";
  return `
    <p class="eyebrow">Step 3 of 3 · Permission</p>
    <h1 id="ob-title">Hardware identifiers</h1>
    <p class="lede">Before this computer can be registered, Vouch Compute needs your answer. This is the full text:</p>
    <div class="consent">
      <p class="consent-text">${esc(c.text)}</p>
      <p class="muted small">Sent only to Vouch Compute's account service, never to the job network. Version ${esc(c.version)}.</p>
    </div>
    ${refused ? `<div class="note note-warn" role="alert">${icon("alert")}<span>${esc(c.refused_message)}</span></div>` : ""}
    <div class="ob-actions"><button type="button" class="btn" data-go="signin">Back</button><span class="spacer"></span>
      <button type="button" class="btn" id="consent-refuse">Don't allow</button>
      <button type="button" class="btn btn-primary btn-lg" id="consent-accept">Allow and continue</button></div>`;
}

// Server estimate: always a range, the base and the temporary launch bonus shown apart. Never a promise.
function estimateHtml(c) {
  if (!c) return `<div class="row"><div class="spinner"></div><span class="muted">Asking the server for an estimate…</span></div>`;
  if (c.err) return `<div class="note">${icon("info")}<span>An estimate needs a finished benchmark and a connection to the server. (${esc(c.err)})</span></div>`;
  const e = c.ok || {};
  const a = e.assumptions || {};
  const b = e.base || {};
  const mult = Number(e.multiplier || 1);
  const bonus = mult > 1;
  return `
    <div class="est">
      <div class="est-main">
        <span class="eyebrow">Estimated range per month, after electricity</span>
        <span class="range-big"><span>${usd(e.low_usd)}</span><span class="range-dash" aria-hidden="true">–</span><span class="sr-only"> to </span><span>${usd(e.high_usd)}</span></span>
        <span class="chip chip-soft">${icon("info")}An estimate, not a promise</span>
      </div>
      <div class="est-split">
        <div class="tile"><span class="tile-label">Base pay</span><span class="tile-value">${usd(b.low_usd)} – ${usd(b.high_usd)}</span>
          <span class="tile-hint">What the work earns on its own.</span></div>
        <div class="tile ${bonus ? "tile-bonus" : ""}"><span class="tile-label">Launch bonus ${bonus ? `<span class="badge badge-info">Temporary</span>` : ""}</span>
          <span class="tile-value">${bonus ? `×${esc(mult.toFixed(2))}` : "None"}</span>
          <span class="tile-hint">${bonus ? `A temporary launch bonus${e.multiplier_end ? `, ends ${esc(day(e.multiplier_end))}` : ""}. It tapers as paid demand grows.` : "No launch bonus right now."}</span></div>
        <div class="tile"><span class="tile-label">Electricity</span><span class="tile-value">−${usd(a.electricity_cost_usd)}</span>
          <span class="tile-hint">${esc(a.avg_watts ?? "?")} W at $${esc(a.electricity_usd_per_kwh ?? "?")}/kWh, already subtracted.</span></div>
      </div>
      <p class="fine">Assumes ${esc(a.hours_per_day ?? "?")} h/day available and ${esc(Math.round((Number(a.utilization) || 0) * 100))}% of that time with work. This is a range, not a promise: earnings depend on demand, and only verified work is paid.</p>
    </div>`;
}

const LABELS = [["pending", "Pending", "Held 72 h before release"], ["in_escrow", "In escrow", "Probation: held 21 days"],
  ["in_review", "In review", "Being checked, not forfeited"], ["releasable", "Releasable", "Goes out with the next weekly payout"],
  ["sent", "Sent", "Paid to your wallet"], ["clawed_back", "Clawed back", "Reversed after review"]];

function earningsHtml(e) {
  const t = (e && e.totals) || {};
  const hold = sumUsd(t.in_escrow, t.in_review);
  // a share bar drawn only from the server's own totals (no history is invented)
  const parts = [["pending", "seg-pending"], ["in_escrow", "seg-hold"], ["in_review", "seg-review"], ["releasable", "seg-ready"], ["sent", "seg-paid"]]
    .map(([k, cls]) => [k, cls, nanos(t[k])]).filter(([, , n]) => n !== null && n > 0n);
  const total = parts.reduce((s, [, , n]) => s + n, 0n);
  const bar = total > 0n
    ? `<div class="stackbar" role="img" aria-label="How your earnings split by status">${parts.map(([k, cls, n]) =>
      `<span class="${cls}" data-w="${Number((n * 10000n) / total) / 100}" title="${esc((LABELS.find((l) => l[0] === k) || [])[1])}"></span>`).join("")}</div>`
    : `<p class="muted small">Nothing earned yet. Verified work shows up here a day after it is done.</p>`;
  return `
    <div class="totals">
      <div class="total"><span class="total-label"><span class="dot seg-pending"></span>Pending</span><span class="total-value">${usd(t.pending)}</span><span class="tile-hint">Held 72 h before release</span></div>
      <div class="total"><span class="total-label"><span class="dot seg-hold"></span>On hold</span><span class="total-value">${usd(hold)}</span><span class="tile-hint">In escrow or being checked</span></div>
      <div class="total"><span class="total-label"><span class="dot seg-paid"></span>Paid</span><span class="total-value">${usd(t.sent)}</span><span class="tile-hint">Sent to your wallet</span></div>
    </div>
    ${bar}
    <details class="breakdown" id="earn-breakdown"><summary>All payout states</summary>
      <dl class="kv-list">${LABELS.map(([k, l, hint]) => `<div><dt>${l}<span class="muted small">${hint}</span></dt><dd>${usd(t[k])}</dd></div>`).join("")}</dl>
    </details>
    ${e && e.probation && e.probation.active ? `<div class="note note-info">${icon("hourglass")}<span>New device: earnings are held for ${esc(num(e.probation.escrow_days))} days while work is verified${e.probation.ends_on ? ` (until ${esc(day(e.probation.ends_on))})` : ""}.</span></div>` : ""}
    ${((e && e.alerts) || []).map((a) => `<div class="note note-warn">${icon("alert")}<span>${esc(a && a.message)}</span></div>`).join("")}
    <p class="fine">Verified this week: <strong>${usd(e && e.this_week_verified_usd)}</strong>. As of ${esc(day(e && e.as_of))}. Detailed history is on the <button type="button" class="linklike" data-link="dashboard">web dashboard</button>.</p>`;
}

function walletHtml(list) {
  if (!list || !list.length) return `<p>No wallet linked yet. Earnings keep accruing; link one on the web before your first payout.</p>`;
  return list.map((x) => {
    const addr = String((x && x.address) ?? "");
    const frozen = x.payout_freeze_until && new Date(x.payout_freeze_until) > new Date();
    return `<div class="wallet-row"><span class="badge">${esc(x.chain)}</span><span class="mono addr" title="${esc(addr)}">${esc(addr.slice(0, 6))}…${esc(addr.slice(-6))}</span>
      <span class="badge ${x.status === "active" ? "badge-ok" : "badge-warn"}">${esc(x.status)}</span>
      ${frozen ? `<span class="muted small">Payouts resume ${esc(day(x.payout_freeze_until))}</span>` : ""}</div>`;
  }).join("");
}

const ACTIVITY = { idle: "idle", working: "working", paused: "paused" };
function deviceStateText(d) {
  if (!d) return "";
  return `${d.connection === "online" ? "Online" : "Offline"}${d.activity && ACTIVITY[d.activity] ? `, ${ACTIVITY[d.activity]}` : ""}${d.paused_by === "user" ? ". Paused by you." : d.paused_by === "tally" ? ". Paused by Vouch Compute." : ""}`;
}
function deviceHeadHtml(d) {
  const name = d && d.name ? d.name : "This computer";
  const online = d && d.connection === "online";
  return `<div class="dev-head">
      <div class="dev-icon" aria-hidden="true">${icon("device")}</div>
      <div class="dev-title"><h2 class="dev-name">${esc(name)}</h2>
        ${d ? `<p class="muted small"><span class="dot ${online ? "dot-ok" : "dot-muted"}"></span>${esc(deviceStateText(d))}</p>` : `<p class="muted small">Account details appear once this device is registered and online.</p>`}</div>
    </div>`;
}

const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const hhmm = (m) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
function daysText(bits) {
  const b = Number(bits) & 127;
  if (b === 127) return "Every day";
  if (b === 31) return "Weekdays";
  if (b === 96) return "Weekends";
  if (!b) return "No days";
  return DAY_NAMES.filter((_, i) => b & (1 << i)).join(", ");
}
function scheduleSummary(schedule) {
  return (schedule || []).map((w) => `${daysText(w.days)}, ${hhmm(Number(w.start_min) || 0)}–${hhmm(Number(w.end_min) || 0)}`);
}

// ---- reliability (start)
// the server's DeviceView.reliability, shown as it is: tier, since, benefits and the fixed operational hints. The app never
// computes, infers or stores a tier; there are no scores, thresholds or speeds to show.
const TIER_LABELS = { probation: "New device", premium: "Premium", stable: "Stable", less_stable: "Less stable", unpredictable: "Unpredictable" };
const PRIORITY_WORDS = { standard: "Standard place in the queue", higher: "Higher place in the queue", highest: "Highest place in the queue" };
const HINTS = {
  keep_regular_hours: "Keep regular hours: be available at similar times each week.",
  avoid_disconnects: "Avoid disconnects: a steady connection helps.",
  finish_accepted_jobs: "Finish the jobs you accept: avoid stopping work midway, for example by setting idle and schedule limits that fit your use.",
  build_tenure: "Keep going: reliability builds up over weeks.",
  verify_identity: "Verify your identity on the web.",
  use_hardware_key: "Use a computer with a hardware security chip (TPM).",
};
function reliabilityHtml(r) {
  if (!r || !TIER_LABELS[r.tier]) return `<p class="muted small">Your reliability tier appears here once the server has one for this device.</p>`;
  const b = r.benefits || {};
  const bonus = typeof b.bonus_pct === "number" && b.bonus_pct > 0 ? `+${b.bonus_pct}% on verified work` : "No reliability bonus";
  const hints = (r.improve || []).filter((h) => HINTS[h]).map((h) => `<li>${esc(HINTS[h])}</li>`).join("");
  return `
    <div class="row"><span class="tier tier-${esc(r.tier)}">${esc(TIER_LABELS[r.tier])}</span>${r.since_day ? `<span class="muted small">since ${esc(day(r.since_day))}</span>` : ""}</div>
    <dl class="kv"><dt>Queue</dt><dd>${esc(PRIORITY_WORDS[b.queue_priority] || PRIORITY_WORDS.standard)}</dd><dt>Bonus</dt><dd>${esc(bonus)}</dd></dl>
    ${hints ? `<p class="small"><strong>How to improve</strong></p><ul class="small hints">${hints}</ul>` : `<p class="muted small">Nothing to improve right now.</p>`}
    <p class="muted small">Tiers are decided by the server from how reliably the device is available and finishes work, and change at most once a day.</p>`;
}
// ---- reliability (end)
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
// Browser preview only: #view=<name>, #step=<name>, #theme=<light|dark>, plus demo states (see demoInvoke).
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

// ------------------------------------------------------------------ theme
function currentTheme() { return document.documentElement.dataset.theme || "system"; }
function setTheme(mode) {
  if (mode === "light" || mode === "dark") document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  store.set("vouch.theme", mode === "light" || mode === "dark" ? mode : null);
  announce(mode === "system" ? "Theme follows your system" : `${mode} theme`);
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
// Three visible setup steps: welcome, sign in, this device (the hardware consent, enrollment and "you're set").
const STEP_INDEX = { welcome: 0, signin: 1, consent: 2, device: 2 };
const STEP_LABELS = ["Welcome", "Sign in", "This device"];
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
const inflight = new Set();

async function refresh() {
  try {
    snap = await core("status");
  } catch (e) {
    snap = { error: String(e) };
  }
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

// ------------------------------------------------------------------ onboarding (3 visible steps)
function stepsHtml(current) {
  const i = STEP_INDEX[current] ?? 0;
  return `<ol class="steps" aria-label="Setup progress, step ${i + 1} of ${STEP_LABELS.length}">${STEP_LABELS.map((l, j) =>
    `<li class="${j < i ? "done" : j === i ? "current" : ""}"${j === i ? ` aria-current="step"` : ""}><span class="step-dot">${j < i ? icon("check") : j + 1}</span><span class="step-label">${l}</span></li>`).join("")}</ol>`;
}
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

function renderOnboarding() {
  const s = snap && !snap.error ? snap : null;
  const st = onboardStep;
  let body = "";
  if (st === "welcome") {
    const items = [
      ["shield", "What runs.", "Speech-to-text and text embeddings of non-sensitive data, inside a sandbox that has no network access and cannot see your files."],
      ["eye", "Your computer can technically see job inputs", "while it processes them. Inputs are kept in memory only and are never saved to disk."],
      ["bolt", "Electricity.", "Work uses power. Your estimate subtracts an electricity cost so you can judge whether it is worth it."],
      ["wifiOff", "Your internet provider", "may restrict commercial use of a home connection. Check your contract."],
      ["info", "Taxes", "on what you earn are your responsibility."],
      ["check", "This is not mining.", "No cryptocurrency is mined on your computer. Earnings are paid in USDC."],
      ["hourglass", "New devices start on probation.", "Earnings are held in escrow for 21 days while work is verified. Unverified work is not paid."],
      ["settings", "Defaults are conservative:", "work starts only when you've been away for 10 minutes, stops the moment you're back, pauses for games and on battery, and respects a temperature limit."],
    ];
    body = `
      <div class="ob-hero"><div class="ob-mark">${MARK}</div>
        <div><p class="eyebrow">Step 1 of 3</p><h1 id="ob-title">Welcome to Vouch Compute</h1>
        <p class="lede">Vouch Compute uses your computer's spare time for small, verified AI jobs and pays you for the work that checks out. Please read this first.</p></div></div>
      <div class="disclosure" tabindex="0" id="disclosure" role="region" aria-label="What you are agreeing to">
        <ul class="disc-list">${items.map(([i, b, t]) => `<li><span class="disc-icon">${icon(i)}</span><span><strong>${b}</strong> ${t}</span></li>`).join("")}</ul>
      </div>
      <div class="ob-actions"><span class="muted small" id="scroll-hint">Scroll to the end to continue.</span><span class="spacer"></span>
        <button type="button" class="btn btn-primary btn-lg" id="agree" disabled>I understand${icon("arrow")}</button></div>`;
  } else if (st === "signin") {
    const si = s && s.signin;
    if (s && s.signed_in && si && si.state !== "pending") {
      body = `<div class="ob-center"><div class="ob-success">${icon("check")}</div>
        <p class="eyebrow">Step 2 of 3</p><h1 id="ob-title">You're signed in</h1><p class="lede">Next, this computer gets its own key.</p></div>
        <div class="ob-actions"><span class="spacer"></span><button type="button" class="btn btn-primary btn-lg" data-go="device">Continue${icon("arrow")}</button></div>`;
    } else if (si && si.state === "pending") {
      body = `
        <p class="eyebrow">Step 2 of 3</p><h1 id="ob-title">Confirm in your browser</h1>
        <p class="lede">Open the sign-in page, sign in with your username, password and second factor, then check that this code matches:</p>
        <div class="code-wrap"><span class="code" aria-label="Device code">${esc(si.user_code)}</span></div>
        <div class="row"><button type="button" class="btn btn-primary" data-link="signin">${icon("external")}Open sign-in page</button>
          <span class="row muted small"><span class="spinner" aria-hidden="true"></span> Waiting for you to approve…</span></div>
        <p class="muted small">The app only gets read access to your earnings and devices. Wallet changes always happen on the web.</p>`;
    } else {
      const err = si && si.state === "error" ? `<div class="note note-danger" role="alert">${icon("alert")}<span>${esc(si.message)}</span></div>` : "";
      const down = snap && snap.error ? `<div class="note note-warn">${icon("alert")}<span>${esc(snap.error)}</span></div>` : "";
      body = `
        <div class="ob-hero"><div class="ob-mark ob-mark-soft">${icon("user")}</div>
          <div><p class="eyebrow">Step 2 of 3</p><h1 id="ob-title">Sign in</h1>
          <p class="lede">Use your Vouch Compute account. Sign-in happens in your browser with your username, password and second factor, so this window never sees your password or codes.</p></div></div>
        ${err}${down}
        <div class="ob-actions"><button type="button" class="btn" data-go="welcome">Back</button><span class="spacer"></span>
          <button type="button" class="btn btn-primary btn-lg" id="signin-start">${icon("external")}Sign in with the browser</button></div>`;
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
  const head = (t) => `<p class="eyebrow">Step 3 of 3</p><h1 id="ob-title">${t}</h1>`;
  if (!s || !s.signed_in) {
    return `${head("Sign in first")}<p class="lede">This computer is registered to your account, so sign in before setting it up.</p>
      <div class="ob-actions"><button type="button" class="btn btn-primary" data-go="signin">Go to sign-in</button></div>`;
  }
  const enrolled = !!s.device_id || si.state === "done";
  if (onboardStep === "consent" || (!enrolled && (si.state === "consent_required" || (s.hw_consent !== "accepted" && si.state !== "blocked")))) {
    if (!consentCache) loadConsent();
    return consentHtml(consentCache, s.hw_consent);
  }
  if (si.state === "choose_replace") {
    const c = si.candidates || [];
    return `${head("Is this a computer you used before?")}
      <p class="lede">Your account already has ${c.length === 1 ? "a device" : "devices"} like this one. If you reinstalled Windows or the app, replace the old entry. Its tier is not carried over: the replacement starts as a new device.</p>
      <div class="choice-list">${c.map((x) => `<button type="button" class="choice-btn" data-replace="${esc(x.device_id)}">${icon("refresh")}<span><strong>Replace “${esc(x.name || "Unnamed device")}”</strong>${x.last_seen_day ? `<span class="muted small">Last seen ${esc(day(x.last_seen_day))}</span>` : ""}</span></button>`).join("")}
        <button type="button" class="choice-btn choice-primary" data-replace="">${icon("sparkle")}<span><strong>No, this is a new computer</strong><span class="muted small">Register it as a new device</span></span></button></div>`;
  }
  if (si.state === "blocked") {
    const fix = si.code === "hardware_in_use" ? `<button type="button" class="btn" data-link="devices">${icon("external")}Open Devices on the web</button>`
      : si.code === "device_limit" ? `<button type="button" class="btn" data-link="verify">${icon("external")}Verify on the web</button><button type="button" class="btn" data-link="devices">Manage devices</button>`
      : si.code === "consent_refused" || si.code === "consent_required" || si.code === "hw_ids_required" ? `<button type="button" class="btn btn-primary" data-go="consent">Review the hardware permission</button>`
      : si.code === "replace_not_confirmed" ? `<button type="button" class="btn btn-primary" data-replace="">Register as a new device</button>` : "";
    return `${head("This computer can't be registered yet")}<div class="note note-warn" role="alert">${icon("alert")}<span>${esc(si.message)}</span></div><div class="ob-actions">${fix}</div>`;
  }
  if (si.state === "enrolling" || (!enrolled && si.state !== "error")) {
    return `${head("Registering this device…")}<div class="row"><div class="spinner"></div><span>Creating this computer's key</span></div>`;
  }
  if (si.state === "error" && !enrolled) {
    return `${head("Registration didn't finish")}<div class="note note-danger" role="alert">${icon("alert")}<span>${esc(si.message)}</span></div>
      <div class="ob-actions"><button type="button" class="btn" data-go="signin">Back to sign-in</button><span class="spacer"></span><button type="button" class="btn btn-primary" data-replace="">Try again</button></div>`;
  }
  const set = s.settings || {};
  const b = s.status && s.status.benchmark;
  return `
    <div class="ob-center"><div class="ob-success">${icon("check")}</div>
      ${head("You're set")}<p class="lede">This computer is registered. A short benchmark comes next; then Vouch Compute works on its own, within your limits.</p></div>
    <div class="setup-grid">
      <section class="inset" aria-labelledby="su-hw"><h2 id="su-hw">${icon("device")}This computer</h2>${hardwareHtml(s.hardware, s.status && s.status.backend, s.key_storage)}
        <p class="muted small">For your information only. What you can earn is decided by a benchmark, never by what the app reports.</p>
        ${s.key_storage === "tpm" ? "" : `<div class="note note-warn small">${icon("alert")}<span>Without a hardware security chip this device stays in the Probation tier, with capped earnings.</span></div>`}</section>
      <section class="inset" aria-labelledby="su-bench"><h2 id="su-bench">${icon("gauge")}Benchmark</h2>${benchHtml(b, Date.now(), set.benchmark_now)}</section>
    </div>
    <section class="inset">${autostartHtml()}</section>
    <p class="muted small">Starts after ${esc(num(set.idle_minutes))} minutes away, pauses above ${esc(num(set.temp_cap_c))} °C${set.never_on_battery ? ", never on battery" : ""}. You can change this any time in Settings.</p>
    <div class="ob-actions"><span class="spacer"></span><button type="button" class="btn btn-primary btn-lg" data-go="">Open Vouch Compute${icon("arrow")}</button></div>`;
}

// ------------------------------------------------------------------ account notices (node protocol 1.2.0)
// Banners only. They carry no reason; offers are not affected (a paused device simply receives none).
function noticesHtml(n) {
  if (!n) return "";
  const out = [];
  if (n.paused_by === "user") out.push(`<div class="note note-info" role="status">${icon("pause")}<span>Paused from the web or this app. This device gets no work until you resume it.</span><button type="button" class="btn btn-sm" data-control="resume">Resume</button></div>`);
  if (n.paused_by === "tally") out.push(`<div class="note note-warn" role="status">${icon("pause")}<span>Paused by Vouch Compute. Contact support.</span></div>`);
  if (n.recovery_in_progress) out.push(`<div class="note note-warn" role="alert">${icon("alert")}<span>Account recovery requested. If this wasn't you, cancel it on the web now.</span><button type="button" class="btn btn-sm" data-link="recover">Open the web</button></div>`);
  if (n.reverify_required) out.push(`<div class="note note-warn" role="status">${icon("user")}<span>Please verify your identity again on the web.</span><button type="button" class="btn btn-sm" data-link="verify">Verify</button></div>`);
  return out.length ? `<div class="notices">${out.join("")}</div>` : "";
}

// The agent signs with the server's clock anyway; this only tells the user their clock is off.
function clockHtml(off) {
  if (typeof off !== "number" || Math.abs(off) < 5) return "";
  const n = Math.abs(off), unit = n >= 120 ? `${Math.round(n / 60)} minutes` : `${n} seconds`;
  return `<div class="note note-info" role="status">${icon("clock")}<span>Your computer's clock is ${unit} ${off > 0 ? "behind" : "ahead"}. Vouch Compute corrects for it, but setting the time automatically in your system settings is best.</span></div>`;
}

// ------------------------------------------------------------------ main views
const pageHead = (title, lede, extra) => `<header class="page-head"><div><h1>${title}</h1>${lede ? `<p class="lede">${lede}</p>` : ""}</div>${extra || ""}</header>`;
const cardHead = (id, ic, title, sub) => `<header class="card-head"><span class="icon-bubble">${icon(ic)}</span><div><h2 id="${id}">${title}</h2>${sub ? `<p class="card-sub">${sub}</p>` : ""}</div></header>`;

function renderLoading() {
  return `<div class="skeleton" aria-busy="true" aria-label="Loading"><div class="sk sk-hero"></div><div class="grid-2"><div class="sk sk-card"></div><div class="sk sk-card"></div></div>
    <p class="row muted"><span class="spinner" aria-hidden="true"></span>Starting Vouch Compute…</p></div>`;
}

function renderAgentDown() {
  return `<section class="state-page" aria-labelledby="down-h">
    <div class="state-icon tone-danger">${icon("power")}</div>
    <h1 id="down-h">The Vouch Compute agent isn't running</h1>
    <p class="lede">The agent runs in the background: it does the work and keeps this computer's key. Start it to continue.</p>
    <p class="state-detail mono">${esc(snap.error)}</p>
    <div class="row row-center"><button type="button" class="btn btn-primary btn-lg" id="start-core">${icon("play")}Start it</button></div>
  </section>`;
}

function heroActionHtml(h) {
  switch (h.action) {
    case "pause": return `<button type="button" class="btn btn-band" id="pause">${icon("pause")}Pause for 1 hour</button>`;
    case "resume": return `<button type="button" class="btn btn-primary btn-lg" id="resume">${icon("play")}Resume now</button>`;
    case "resume-server": return `<button type="button" class="btn btn-primary btn-lg" data-control="resume">${icon("play")}Resume</button>`;
    case "signin": return `<button type="button" class="btn btn-primary btn-lg" data-go-onboard="signin">${icon("user")}Sign in</button>`;
    case "reconnect": return `<button type="button" class="btn btn-band" id="reconnect">${icon("refresh")}Try again now</button>`;
    case "update": return `<button type="button" class="btn btn-primary btn-lg" data-view="settings">${icon("download")}Go to updates</button>`;
    default: return "";
  }
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
        <p class="eyebrow">Status</p>
        <h1 id="hero-title">${esc(h.title)}</h1>
        ${h.sub ? `<p class="hero-sub">${esc(h.sub)}</p>` : ""}
        <div class="chips"><span class="chip">${icon("settings")}Mode: ${esc(MODE_LABELS[set.mode] || "—")}</span><span class="chip">${icon("shieldCheck")}Only verified work is paid</span></div>
      </div>
      <div class="hero-action">${heroActionHtml(h)}</div>
    </section>
    <div class="grid-2">
      <section class="card" aria-labelledby="today-h">
        ${cardHead("today-h", "clock", "Today's work", "Counted on this computer. The server verifies each job before it is paid.")}
        <div class="today-main"><span class="today-value">${esc(duration(s.worked_today_s))}</span><span class="metric-label">Worked today</span></div>
        <div class="metrics">
          <div class="metric"><span class="metric-value">${esc(num(st.jobs_completed))}</span><span class="metric-label">Jobs finished this session</span></div>
          <div class="metric"><span class="metric-value">${esc(num(st.jobs_abandoned))}</span><span class="metric-label">Stopped early (not paid)</span></div>
        </div>
        ${cap > 0 ? `<div class="meter"><div class="meter-top"><span class="small muted">Daily limit</span><span class="small">${esc(capPct)}% of ${esc(num(cap))} h</span></div>
          <div class="progress" role="progressbar" aria-valuenow="${esc(capPct)}" aria-valuemin="0" aria-valuemax="100" aria-label="Share of today's limit used"><div class="progress-fill" data-w="${esc(capPct)}"></div></div></div>`
          : `<p class="muted small">No daily limit. <button type="button" class="linklike" data-view="settings">Set one in Settings</button></p>`}
      </section>
      <section class="card" aria-labelledby="hw-h">
        ${cardHead("hw-h", "chip", "Hardware", "What this computer reports. Pay is set by the benchmark, not by this list.")}
        ${hardwareHtml(s.hardware, st.backend)}
      </section>
    </div>
    ${est ? `<section class="card card-row" aria-labelledby="est-mini-h">
        <span class="icon-bubble icon-bubble-ok">${icon("wallet")}</span>
        <div class="grow"><h2 id="est-mini-h" class="small-h">Estimated range per month</h2>
          <p class="est-mini"><strong>${usd(est.low_usd)} – ${usd(est.high_usd)}</strong> <span class="muted small">after electricity${estMult > 1 ? ", including a temporary launch bonus" : ""}. An estimate, not a promise.</span></p></div>
        <button type="button" class="btn" data-view="earnings">See earnings${icon("arrow")}</button>
      </section>` : ""}
    ${st.last_error && st.connection !== "connected" ? `<div class="note">${icon("info")}<span>Last problem: ${esc(st.last_error)}</span></div>` : ""}`;
}

function renderEarnings() {
  const e = earnCache;
  const w = walletCache;
  return `${pageHead("Earnings", "Figures come from the server once a day and cover work from at least 24 hours ago.")}
    <section class="card" aria-labelledby="est-h">
      ${cardHead("est-h", "sparkle", "Your estimate", "Computed by the server from your benchmark and current demand.")}
      ${estimateHtml(estimateCache)}
    </section>
    <section class="card" aria-labelledby="tot-h">
      ${cardHead("tot-h", "hourglass", "Payout status", "Only verified work is counted. New earnings are held before they are paid.")}
      ${!e ? `<div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div>`
        : e.err ? `<div class="note">${icon("info")}<span>Earnings are available once you're signed in and online. (${esc(e.err)})</span></div>`
        : earningsHtml(e.ok)}
    </section>
    <section class="card" aria-labelledby="wallet-h">
      ${cardHead("wallet-h", "wallet", "Payout wallet", "Display only. Wallets are linked and changed on the web.")}
      <div class="wallets">${!w ? `<span class="muted">Loading…</span>` : w.err ? `<p class="muted">Wallet details are available once you're signed in.</p>` : walletHtml(w.ok)}</div>
      <div class="row"><button type="button" class="btn" data-link="wallet">${icon("external")}Link or change wallet on the web</button>
        <button type="button" class="btn btn-ghost" data-link="verify">Verify your identity</button></div>
      <p class="fine">For your safety, wallets are linked only on the web, with a signed message from the wallet and your second factor. Any change pauses payouts for 72 hours. Verify your identity on the web to get paid.</p>
    </section>`;
}

function renderDevice() {
  const st = snap.status || {};
  const set = snap.settings || {};
  const d = deviceCache && deviceCache.ok;
  const sched = scheduleSummary(set.schedule);
  return `${pageHead("Device", "This computer, its benchmark and its limits.")}
    <section class="card" aria-label="This device">
      ${deviceHeadHtml(d)}
      ${hardwareHtml(snap.hardware, st.backend, snap.key_storage)}
      <details class="more" id="dev-more"><summary>Technical details</summary>
        <dl class="kv">
          <dt>Device ID</dt><dd class="mono small">${esc(snap.device_id || "Not registered")}</dd>
          <dt>Device key</dt><dd>${snap.key_storage === "tpm" ? "TPM 2.0 (hardware, non-exportable)" : "Software key (dev tier: capped at Probation)"}</dd>
          <dt>Trust ceiling</dt><dd>${esc(snap.trust_ceiling || "—")}</dd>
          <dt>Sandbox</dt><dd>${esc(st.sandbox || "Not used yet")}</dd>
          <dt>Agent version</dt><dd>${esc(snap.version)}</dd>
        </dl></details>
      <p class="fine">Jobs run in a separate sandboxed process with no network access and no access to your files. Inputs stay in memory and are never written to disk.</p>
    </section>
    <div class="grid-2">
      <section class="card" aria-labelledby="bench-h">${cardHead("bench-h", "gauge", "Benchmark", "")}${benchHtml(st.benchmark, Date.now(), set.benchmark_now)}</section>
      <section class="card" aria-labelledby="rel-h">${cardHead("rel-h", "shieldCheck", "Reliability", "")}
        ${!deviceCache ? `<div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div>` : d ? reliabilityHtml(d.reliability) : `<p class="muted small">Available once this device is registered and online.</p>`}</section>
    </div>
    <form id="controls" novalidate>
      <section class="card" aria-labelledby="lim-h">
        ${cardHead("lim-h", "thermo", "Limits", "Vouch Compute pauses before this computer gets too hot, and you choose how hard it works.")}
        <div class="field"><div class="field-top"><label for="temp">Pause above</label><span class="field-val"><output id="temp-out" for="temp">${esc(set.temp_cap_c)}</output> °C</span></div>
          <input id="temp" type="range" min="65" max="85" value="${esc(set.temp_cap_c)}" name="temp_cap_c"/>
          <span class="muted small">Vouch Compute never exceeds 90 °C, whatever this is set to.</span></div>
        <div class="field"><div class="field-top"><label for="power">Power use</label><span class="field-val"><output id="power-out" for="power">${esc(set.power_pct)}</output>%</span></div>
          <input id="power" type="range" min="10" max="100" step="10" value="${esc(set.power_pct)}" name="power_pct"/></div>
        <div class="switch"><label for="batt"><strong>Never run on battery</strong><span class="muted small">Below 30% battery it never runs, regardless.</span></label>
          <input id="batt" class="toggle" type="checkbox" name="never_on_battery" ${set.never_on_battery ? "checked" : ""}/></div>
        <div class="switch"><label for="fs"><strong>Pause during games and fullscreen</strong><span class="muted small">Resumes when you leave fullscreen.</span></label>
          <input id="fs" class="toggle" type="checkbox" name="pause_in_fullscreen" ${set.pause_in_fullscreen ? "checked" : ""}/></div>
      </section>
    </form>
    <section class="card" aria-labelledby="sch-h">
      ${cardHead("sch-h", "calendar", "Schedule", `Mode: ${esc(MODE_LABELS[set.mode] || "—")}. The hours below apply in "On a schedule" mode.`)}
      ${sched.length ? `<ul class="sched">${sched.map((x) => `<li>${icon("clock")}${esc(x)}</li>`).join("")}</ul>` : `<p class="muted small">No time windows set.</p>`}
      <div class="row"><button type="button" class="btn" data-view="settings">Change mode and schedule</button>
        ${set.daily_cap_hours ? `<span class="muted small">Daily limit ${esc(num(set.daily_cap_hours))} h</span>` : `<span class="muted small">No daily limit</span>`}</div>
    </section>
    <section class="card" aria-labelledby="act-h">
      ${cardHead("act-h", "user", "This device on your account", "")}
      <p class="muted small">${esc(deviceStateText(d))}</p>
      <div class="row">
        <button type="button" class="btn" data-control="pause">${icon("pause")}Pause on the server</button>
        <button type="button" class="btn" data-control="resume">${icon("play")}Resume</button>
        <button type="button" class="btn btn-ghost" data-link="devices">${icon("external")}Manage on the web</button>
      </div>
      <p class="fine">Pausing here works like pausing on the web: no new work arrives until you resume. A running job finishes and is paid if it verifies.</p>
    </section>`;
}

function controlsHtml(s) {
  if (!s) return `<p class="muted">Controls appear once the agent is running.</p>`;
  const windows = (s.schedule || []).map((w, i) => `
    <div class="window-row" data-win="${i}">
      <div class="days" role="group" aria-label="Days for window ${i + 1}">${DAY_NAMES.map((n, d) =>
        `<label><input type="checkbox" data-day="${d}" ${Number(w.days) & (1 << d) ? "checked" : ""}/><span>${n}</span></label>`).join("")}</div>
      <div class="row">
        <label class="row small">From <input type="time" data-k="start" value="${esc(hhmm(Number(w.start_min) || 0))}"/></label>
        <label class="row small">to <input type="time" data-k="end" value="${esc(hhmm(Number(w.end_min) || 0))}"/></label>
        <button type="button" class="btn btn-ghost btn-sm" data-remove="${i}" aria-label="Remove window ${i + 1}">${icon("trash")}Remove</button>
      </div>
    </div>`).join("");
  const radio = (v, title, hint) => `<label class="choice"><input type="radio" name="mode" value="${v}" ${s.mode === v ? "checked" : ""}/>
      <span><strong>${title}</strong><span class="muted small">${hint}</span></span></label>`;
  return `
  <form id="controls" novalidate>
    <section class="card" aria-labelledby="mode-h"><fieldset>
      <legend class="sr-only">When should Vouch Compute work?</legend>
      ${cardHead("mode-h", "clock", "When should Vouch Compute work?", "")}
      <div class="choices">
        ${radio("idle_only", "When I'm away (recommended)", "Starts after you've been idle, stops within seconds when you're back.")}
        ${radio("scheduled", "On a schedule", "Only in the hours you pick below.")}
        ${radio("always_on", "Always on", "Desktops only. Your computer will feel slower while it works.")}
      </div>
      <div class="field"><div class="field-top"><label for="idle">Start after being idle for</label><span class="field-val"><output id="idle-out" for="idle">${esc(s.idle_minutes)}</output> min</span></div>
        <input id="idle" type="range" min="1" max="60" value="${esc(s.idle_minutes)}" name="idle_minutes"/></div>
    </fieldset></section>
    <section class="card" aria-labelledby="sched-h"><fieldset>
      <legend class="sr-only">Schedule</legend>
      ${cardHead("sched-h", "calendar", "Schedule", `Used in "On a schedule" mode. Times are local; a window can run past midnight.`)}
      <div id="windows">${windows || `<p class="muted small">No windows yet.</p>`}</div>
      <div class="row"><button type="button" class="btn" id="add-window">${icon("calendar")}Add a time window</button></div>
      <div class="field"><label for="cap">Daily limit (hours, empty for none)</label>
        <input id="cap" class="input-narrow" type="number" min="0.5" max="24" step="0.5" value="${esc(s.daily_cap_hours ?? "")}" name="daily_cap_hours"/></div>
    </fieldset></section>
  </form>`;
}

// Start at sign-in (the app's login item, not an agent setting). During setup the switch proposes "on" until the
// user decides; afterwards it shows the real state.
let autostartState = null;
function autostartHtml() {
  const proposed = autostartState === null ? !store.get("vouch.autostart_decided", false) : autostartState;
  return `<div class="switch"><label for="autostart"><strong>Start Vouch Compute when I sign in to this computer</strong>
    <span class="muted small">It opens in the tray (the icon next to the clock), not as a window, and follows your limits. You can turn this off here or in your system's startup settings.</span></label>
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
    announce(autostartState ? "Vouch Compute will start when you sign in" : "Vouch Compute will not start by itself");
  } catch (e) { announce(`Could not change the startup setting: ${e}`); toast(`Could not change the startup setting: ${e}`, "danger"); }
  const el = document.getElementById("autostart");
  if (el && autostartState !== null) el.checked = autostartState;
}

function updateHtml() {
  const u = updateState;
  if (!u) return "";
  if (u.checking) return "Checking…";
  if (u.err) return esc(u.err);
  return u.ok && u.ok.available ? `Version ${esc(u.ok.version)} is available. <button type="button" class="btn btn-primary btn-sm" id="install-update">${icon("download")}Install and restart</button>` : "You're up to date.";
}

function renderSettings() {
  const th = currentTheme();
  const seg = (v, l, ic) => `<button type="button" class="seg-btn" data-theme-set="${v}" aria-pressed="${th === v ? "true" : "false"}">${icon(ic)}${l}</button>`;
  const consent = snap.hw_consent === "accepted" ? "Allowed" : snap.hw_consent === "refused" ? "Not allowed" : "Not answered yet";
  return `${pageHead("Settings", "How and when Vouch Compute works on this computer.")}
    ${controlsHtml(snap.settings)}
    <section class="card" aria-labelledby="start-h">${cardHead("start-h", "power", "Startup", "")}${autostartHtml()}</section>
    <section class="card" aria-labelledby="look-h">${cardHead("look-h", "sun", "Appearance", "Follows your system unless you pick a theme.")}
      <div class="seg" role="group" aria-label="Theme">${seg("system", "System", "device")}${seg("light", "Light", "sun")}${seg("dark", "Dark", "moon")}</div></section>
    <section class="card" aria-labelledby="priv-h">${cardHead("priv-h", "eye", "Data and privacy", "")}
      <ul class="bullets small">
        <li>Jobs run in a sandbox with no network access and no access to your files. Inputs stay in memory and are never written to disk.</li>
        <li>Only non-sensitive data is processed. Your computer can technically see job inputs while it works on them.</li>
        <li>This app gets read-only access to your earnings and devices. Wallet changes happen only on the web.</li>
        <li>Work is counted by the server, never from what this app reports. Only verified work is paid.</li>
      </ul>
      <dl class="kv"><dt>Hardware identifiers</dt><dd>${esc(consent)}</dd></dl>
      <div class="row"><button type="button" class="btn btn-ghost" data-link="trust">${icon("external")}How verification works</button></div></section>
    <section class="card" aria-labelledby="acct-h">${cardHead("acct-h", "user", "Account", snap.signed_in ? "Signed in on this computer." : "Not signed in.")}
      <div class="row"><button type="button" class="btn" data-link="dashboard">${icon("external")}Open web dashboard</button>
        <span class="spacer"></span>${snap.signed_in ? `<button type="button" class="btn btn-ghost" id="signout">${icon("logout")}Sign out</button>` : `<button type="button" class="btn btn-primary" data-go-onboard="signin">${icon("user")}Sign in</button>`}</div>
      <div class="sub-block"><h3>Recover my account</h3>
        <p class="muted small">Only if you started an account recovery on the web and it asks for a code from this app.</p>
        ${recoverMsg !== null ? `<div class="note note-info">${icon("info")}<span>${esc(recoverMsg)}</span></div>`
          : recoverOpen ? `<div class="field"><label for="recover-code">Code from the web</label><input id="recover-code" data-keep autocomplete="off" spellcheck="false"/></div>
            <div class="row"><button type="button" class="btn btn-primary" id="recover-send">${icon("key")}Sign with this device</button></div>`
          : `<button type="button" class="btn" id="recover-start">I have a recovery code</button>`}</div>
      <details class="more" id="adv-repair"><summary>Advanced: repair device identity</summary>
        <p class="small">Creates a new key for this computer, vouched for by the current one, and keeps its tier. Use it only if support asks you to.</p>
        <button type="button" class="btn" id="repair-identity">${icon("key")}Repair device identity</button></details></section>
    <section class="card" aria-labelledby="about-h">${cardHead("about-h", "info", "Updates and about", "Updates are signed; Vouch Compute refuses any update whose signature doesn't verify.")}
      <dl class="kv">
        <dt>Agent version</dt><dd>${esc(snap.version || "—")}</dd>
        <dt>App channel</dt><dd>${esc((buildInfo && buildInfo.channel) || "—")}</dd>
        <dt>Build</dt><dd>${devBuild ? `<span class="badge badge-dev" title="Development build: dev keys, dev update channel, test network. Not a release.">DEV BUILD</span>` : "Release"}</dd>
      </dl>
      <div class="row"><button type="button" class="btn" id="check-update">${icon("refresh")}Check for updates</button><span id="update-result" class="muted small" role="status">${updateHtml()}</span></div></section>
    <section class="card card-danger" aria-labelledby="rm-h">${cardHead("rm-h", "trash", "Remove this device", "")}
      <p class="small">Removes this computer from your account and deletes its key. Earnings stay with your account. This can't be undone; registering again makes it a new device.</p>
      <div class="row"><label class="row small" for="remove-confirm">Type REMOVE to confirm</label><input id="remove-confirm" class="input-narrow" data-keep autocomplete="off"/>
        <button type="button" class="btn btn-danger" id="remove-device">${icon("trash")}Remove this device</button></div></section>`;
}

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
      announce("Settings saved");
      toast("Saved");
    } catch (e) { announce(`Could not save: ${e}`); toast(`Could not save: ${e}`, "danger"); }
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
  const form = e.target.closest && e.target.closest("#controls");
  if (form && snap && snap.settings) saveControls(form, true);
});

// ------------------------------------------------------------------ events
document.addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t || t.closest("#tabs")) return;
  try {
    if (t.dataset.go !== undefined) return goStep(t.dataset.go || null);
    if (t.dataset.goOnboard) return goStep(t.dataset.goOnboard);
    if (t.dataset.view) return setView(t.dataset.view);
    if (t.dataset.themeSet) return setTheme(t.dataset.themeSet);
    if (t.dataset.link) return await invoke("open_link", { kind: t.dataset.link });
    if (t.dataset.control) {
      await core("device.control", { action: t.dataset.control });
      announce(t.dataset.control === "pause" ? "Paused on the server" : "Resumed");
      toast(t.dataset.control === "pause" ? "Paused on the server" : "Resumed");
      deviceCache = null;
      if (view === "device") loadDevice();
      return refresh();
    }
    if (t.dataset.replace !== undefined) {
      await core("enroll", { replaces_device_id: t.dataset.replace || null });
      return refresh();
    }
    if (t.dataset.remove !== undefined) {
      const form = document.getElementById("controls");
      const s = readControls(form, snap.settings);
      s.schedule.splice(Number(t.dataset.remove), 1);
      snap.settings = await core("settings.set", s);
      return render({ force: true });
    }
    switch (t.id) {
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
        if (v.trim() !== "REMOVE") { announce("Type REMOVE to confirm"); toast("Type REMOVE to confirm", "danger"); return; }
        await core("device.control", { action: "self_revoke", confirm: "remove" });
        announce("This device was removed");
        toast("This device was removed");
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
      case "repair-identity": await core("identity.repair"); announce("Device identity repaired"); toast("Device identity repaired"); return refresh();
      case "signin-start":
        t.disabled = true;
        await core("signin.start");
        await refresh();
        await invoke("open_link", { kind: "signin" }).catch(() => {});
        return;
      case "bench-now": await core("benchmark.now", { enabled: t.getAttribute("aria-pressed") !== "true" }); return refresh();
      case "pause": await core("pause", { minutes: 60 }); announce("Paused for one hour"); return refresh();
      case "resume": await core("resume"); announce("Resumed"); return refresh();
      case "reconnect": await core("reconnect"); announce("Trying to reconnect"); toast("Trying to reconnect"); return refresh();
      case "start-core": await invoke("ensure_core"); return refresh();
      case "signout": await core("signout"); return refresh();
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
    if (t.id === "signin-start") t.disabled = false;
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
// opens a setup step, #theme=<light|dark> picks a theme.
if (!TAURI && location.hash) {
  if (PREVIEW.get("view")) { onboardStep = null; view = PREVIEW.get("view"); }
  if (PREVIEW.get("step")) onboardStep = normStep(PREVIEW.get("step"));
  if (PREVIEW.get("theme")) document.documentElement.dataset.theme = PREVIEW.get("theme");
}
setView(view);
let ticks = 0;
(async () => {
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
    refresh();
    if (++ticks % 20 === 0) loadFor(view); // server figures again every 30 s while a view is open
  }, 1500);
})();

// ------------------------------------------------------------------ demo backend (browser preview only)
// Hash options: #state=<earning|idle|paused|offline|signedout|down|tally|update>, #signin=<idle|pending|consent_required|
// choose_replace|blocked|enrolling|done>, #pilot=1, #bench=<running|sent|none>, #name=<device name>.
function demoInvoke(cmd, args) {
  const now = Date.now();
  const p = PREVIEW;
  const step = p.get("step");
  const conf = demoInvoke.conf || (demoInvoke.conf = (() => {
    const signin = p.get("signin") || (step === "welcome" ? "idle" : step === "signin" ? "pending" : step === "consent" ? "consent_required" : "done");
    return {
      state: p.get("state") || "earning", signin,
      consent: p.get("consent") || (["idle", "pending", "consent_required"].includes(signin) ? null : "accepted"),
      pilot: p.get("pilot") === "1", bench: p.get("bench") || (step === "device" ? "running" : "sent"), autostart: true,
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
  if (m === "signout") { conf.state = "signedout"; conf.signin = "idle"; return R({}); }
  if (m === "pause") { settings.paused_until_ms = now + args.params.minutes * 60000; conf.state = "paused"; return R(settings); }
  if (m === "resume") { settings.paused_until_ms = null; conf.state = "earning"; return R(settings); }
  if (m === "reconnect" || m === "device.control" || m === "identity.repair") return R({});
  if (m === "benchmark.now") { settings.benchmark_now = !!args.params.enabled; return R(settings); }
  if (m === "recovery.prove") return R({ message: "This device signed the recovery. Finish it on the web." });
  if (m === "device") {
    if (conf.state === "signedout" || conf.state === "offline") return Promise.reject("device not enrolled");
    return R({ device_id: "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f", name: p.get("name") || "Gaming PC", connection: "online", activity: conf.state === "earning" ? "working" : conf.state === "paused" ? "paused" : "idle",
      paused_by: conf.state === "tally" ? "tally" : null, reliability: { tier: "stable", since_day: "2026-11-12", benefits: { queue_priority: "higher", bonus_pct: 5 }, improve: ["keep_regular_hours", "avoid_disconnects"] } });
  }
  if (m === "status") {
    const signedIn = conf.state !== "signedout" && !["idle", "pending", "error"].includes(conf.signin);
    const enrolled = signedIn && conf.signin === "done";
    const connection = !signedIn ? "not_signed_in" : !enrolled ? "not_enrolled" : { offline: "offline", update: "update_required" }[conf.state] || "connected";
    const signinObj = { pending: { state: "pending", user_code: "QJ4K-7XPM", verification_uri: "", verification_uri_complete: "", expires_at_ms: now + 600000 },
      choose_replace: { state: "choose_replace", candidates: [{ device_id: "1a2b3c4d-0000-4000-8000-000000000001", name: "Gaming PC", last_seen_day: "2026-10-02" }] },
      blocked: conf.consent === "refused" ? { state: "blocked", code: "consent_refused", message: "Vouch Compute can't register this computer for paid work without the hardware check." }
        : { state: "blocked", code: "device_limit", message: "Your account has reached its device limit. Verify your identity on the web to add more." } }[conf.signin] || { state: conf.signin };
    const bench = conf.bench === "none" ? null : { benchmark_id: "b", state: conf.bench, started_ms: conf.bench === "running" ? now - 460000 : now - 1300000, duration_s: 1200, segments: conf.bench === "running" ? 46 : 120 };
    const decision = conf.state === "paused" ? { state: "pause", reason: "paused_by_user" } : { state: "run" };
    return R({ version: "0.1.0", signed_in: signedIn, device_id: enrolled ? "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f" : null, trust_ceiling: "capped", key_storage: "tpm",
      settings, worked_today_s: 5400 + (conf.state === "earning" ? 1260 : 0), signin: signinObj, hw_consent: conf.consent, build: { dev_build: true }, links: {}, ...(conf.pilot ? { pilot: true } : {}),
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
