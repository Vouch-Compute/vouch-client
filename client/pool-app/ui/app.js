// Vouch Compute UI. Talks only to the app's allow-listed Tauri commands (core proxy, open_link, updates).
// All server text is escaped before it reaches the DOM. Without Tauri (plain browser preview) a demo
// backend is used so the screens can be reviewed.
"use strict";

const TAURI = window.__TAURI__ && window.__TAURI__.core;
const invoke = TAURI ? TAURI.invoke : demoInvoke;
const $main = document.getElementById("main");
const $tabs = document.getElementById("tabs");
const $live = document.getElementById("live");

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
const day = (s) => (s ? new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—");
const time = (ms) => new Date(ms).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
};

async function core(method, params) {
  return invoke("core", { method, params: params ?? null });
}
function announce(msg) { $live.textContent = ""; setTimeout(() => ($live.textContent = msg), 30); }

// ------------------------------------------------------------------ theme
(function theme() {
  const saved = store.get("vouch.theme", null);
  if (saved) document.documentElement.dataset.theme = saved;
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    store.set("vouch.theme", next);
    announce(`${next} theme`);
  });
})();

// ------------------------------------------------------------------ state
let snap = null;
let view = "status";
let onboardStep = store.get("vouch.onboarded", false) ? null : store.get("vouch.step", "welcome");
const STEPS = ["welcome", "consent", "signin", "device", "benchmark", "estimate", "controls"];

async function refresh() {
  try {
    snap = await core("status");
  } catch (e) {
    snap = { error: String(e) };
  }
  render();
}

function setView(v) {
  view = v;
  for (const b of $tabs.querySelectorAll("button")) b.setAttribute("aria-current", b.dataset.view === v ? "page" : "false");
  render(true);
  $main.focus();
}
$tabs.addEventListener("click", (e) => { const b = e.target.closest("button[data-view]"); if (b) setView(b.dataset.view); });

let lastHtml = "";
function paint(html, force) {
  // avoid re-rendering (and stealing focus from) an unchanged view, and never clobber a form being edited
  if (!force && (html === lastHtml || $main.contains(document.activeElement) && document.activeElement.matches("input,select"))) return;
  lastHtml = html;
  $main.innerHTML = html;
}

function render(force) {
  if (onboardStep) {
    $tabs.hidden = true;
    return paint(renderOnboarding(), force);
  }
  $tabs.hidden = false;
  if (!snap) return paint(`<div class="row"><div class="spinner"></div><span>Starting Vouch Compute…</span></div>`, force);
  if (snap.error) return paint(renderAgentDown(), force);
  const views = { status: renderStatus, controls: renderControls, earnings: renderEarnings, device: renderDevice };
  paint((views[view] || renderStatus)(), force);
  if (view === "controls" || view === "earnings") wireAsync(view);
  if (view === "device") loadDevice();
}

// ------------------------------------------------------------------ status words
function describe(s) {
  const st = s.status;
  const c = st.connection;
  const d = st.decision || {};
  if (c === "not_signed_in") return ["state-idle", "Sign in to start", "Vouch Compute needs your account before it can do any work."];
  if (c === "not_enrolled") return ["state-info", "Setting up this device", "Registering this computer's key with your account."];
  if (c === "auth_failed") return ["state-danger", "This device was not recognised", "Sign in again to re-register it."];
  if (c === "update_required") return ["state-warn", "Update needed", "This version can no longer connect. Install the update from the Device tab."];
  if (c === "revoked") return ["state-danger", "Device paused or suspended", "This device can't take work right now. Vouch Compute retries now and then; check Devices on the web."];
  if (c === "offline" || c === "connecting") {
    const r = st.reconnect_in_s != null ? ` Retrying in ${st.reconnect_in_s}s.` : "";
    return ["state-idle", c === "offline" ? "Offline" : "Connecting…", `Can't reach the Vouch Compute network right now.${r}`];
  }
  if (st.job) return ["state-ok", "Working", `Running a ${esc(st.job.model_id)} job in the sandbox.`];
  if (st.benchmark && st.benchmark.state === "running") return ["state-ok", "Benchmarking", "Running the 20-minute sustained benchmark."];
  if (d.state === "run") return ["state-ok", "Ready", "Waiting for work. Earnings depend on demand; there may be quiet periods."];
  const why = {
    user_active: ["state-idle", "Waiting for idle", `Starts after ${s.settings.idle_minutes} minutes without keyboard or mouse use.`],
    fullscreen: ["state-idle", "Paused for your game or presentation", "Resumes when you leave fullscreen."],
    on_battery: ["state-warn", "Paused on battery", "Vouch Compute only works while plugged in."],
    battery_low: ["state-warn", "Battery low", "Vouch Compute never runs on battery below 30%."],
    thermal: ["state-warn", "Cooling down", `Paused until the temperature drops below your ${s.settings.temp_cap_c} °C limit.`],
    paused_by_user: ["state-idle", "Paused", s.settings.paused_until_ms ? `Until ${time(s.settings.paused_until_ms)}.` : ""],
    outside_schedule: ["state-idle", "Outside your schedule", "Vouch Compute works only in the hours you chose."],
    daily_cap_reached: ["state-idle", "Daily limit reached", "Resumes tomorrow."],
  };
  return why[d.reason] || ["state-idle", "Paused", ""];
}

// ------------------------------------------------------------------ onboarding
function steps(current) {
  const i = STEPS.indexOf(current);
  return `<ol class="steps" aria-label="Setup progress, step ${i + 1} of ${STEPS.length}">${STEPS.map(
    (s, j) => `<li class="${j < i ? "done" : j === i ? "current" : ""}"></li>`
  ).join("")}</ol>`;
}
function goStep(s) {
  onboardStep = s;
  if (s) store.set("vouch.step", s);
  else store.set("vouch.onboarded", true);
  render(true);
  $main.focus();
}

function renderOnboarding() {
  const s = snap && !snap.error ? snap : null;
  const st = onboardStep;
  let body = "";
  if (st === "welcome") {
    body = `
      <h1>Welcome to Vouch Compute</h1>
      <p class="muted">Vouch Compute uses your computer's spare time for small, verified AI jobs and pays you for the work that checks out. Please read this first.</p>
      <div class="disclosure card" tabindex="0" id="disclosure" aria-label="What you are agreeing to">
        <ul>
          <li><strong>What runs.</strong> Speech-to-text and text embeddings of non-sensitive data, inside a sandbox that has no network access and cannot see your files.</li>
          <li><strong>Your computer can technically see job inputs</strong> while it processes them. Inputs are kept in memory only and are never saved to disk.</li>
          <li><strong>Electricity.</strong> Work uses power. Your estimate subtracts an electricity cost so you can judge whether it is worth it.</li>
          <li><strong>Your internet provider</strong> may restrict commercial use of a home connection. Check your contract.</li>
          <li><strong>Taxes</strong> on what you earn are your responsibility.</li>
          <li><strong>This is not mining.</strong> No cryptocurrency is mined on your computer. Earnings are paid in USDC.</li>
          <li><strong>New devices start on probation.</strong> Earnings are held in escrow for 21 days while work is verified. Unverified work is not paid.</li>
          <li><strong>Defaults are conservative:</strong> work starts only when you've been away for 10 minutes, stops the moment you're back, pauses for games and on battery, and respects a temperature limit.</li>
        </ul>
      </div>
      <div class="row"><span class="muted small" id="scroll-hint">Scroll to the end to continue.</span><span class="spacer"></span>
      <button class="btn btn-primary btn-lg" id="agree" disabled>I understand</button></div>`;
  } else if (st === "consent") {
    body = consentHtml(consentCache, s && s.hw_consent);
    if (!consentCache) loadConsent();
  } else if (st === "signin") {
    const si = s && s.signin;
    if (s && s.signed_in && si && si.state !== "pending") {
      body = `<h1>You're signed in</h1><p class="muted">Next, this computer gets its own key.</p>
        <button class="btn btn-primary btn-lg" data-go="device">Continue</button>`;
    } else if (si && si.state === "pending") {
      body = `
        <h1>Confirm in your browser</h1>
        <p>Open the sign-in page, sign in with your username, password and second factor, then check that this code matches:</p>
        <p><span class="code" aria-label="Device code">${esc(si.user_code)}</span></p>
        <div class="row"><button class="btn btn-primary" data-link="signin">Open sign-in page</button>
        <span class="row muted small"><span class="spinner" aria-hidden="true"></span> Waiting for you to approve…</span></div>
        <p class="muted small">The app only gets read access to your earnings and devices. Wallet changes always happen on the web.</p>`;
    } else if (si && si.state === "consent_required") {
      body = `<h1>One more permission</h1><p class="muted">You're signed in. Before this computer can be registered, Vouch Compute needs your answer about hardware identifiers.</p>
        <button class="btn btn-primary btn-lg" data-go="consent">Review</button>`;
    } else if (si && si.state === "choose_replace") {
      body = `<h1>Is this a computer you used before?</h1>
        <p class="muted">Your account already has ${si.candidates.length === 1 ? "a device" : "devices"} like this one. If you reinstalled Windows or the app, replace the old entry. Its tier is not carried over: the replacement starts as a new device.</p>
        <div class="stack">${si.candidates.map((c) => `<button class="btn" data-replace="${esc(c.device_id)}">Replace “${esc(c.name || "Unnamed device")}”${c.last_seen_day ? ` <span class="muted small">(last seen ${day(c.last_seen_day)})</span>` : ""}</button>`).join("")}
        <button class="btn btn-primary" data-replace="">No, this is a new computer</button></div>`;
    } else if (si && si.state === "blocked") {
      const fix = si.code === "hardware_in_use" ? `<button class="btn" data-link="devices">Open Devices on the web</button>`
        : si.code === "device_limit" ? `<button class="btn" data-link="verify">Verify on the web</button><button class="btn" data-link="devices">Manage devices</button>`
        : si.code === "consent_refused" || si.code === "consent_required" || si.code === "hw_ids_required" ? `<button class="btn" data-go="consent">Review the hardware permission</button>`
        : si.code === "replace_not_confirmed" ? `<button class="btn btn-primary" data-replace="">Register as a new device</button>` : "";
      body = `<h1>This computer can't be registered yet</h1><div class="note note-warn" role="alert">${esc(si.message)}</div><div class="row">${fix}</div>`;
    } else if (si && si.state === "enrolling") {
      body = `<h1>Registering this device…</h1><div class="row"><div class="spinner"></div><span>Creating this computer's key</span></div>`;
    } else if (si && si.state === "done") {
      body = `<h1>You're signed in</h1><p class="muted">This computer is registered.</p>
        <button class="btn btn-primary btn-lg" data-go="device">Continue</button>`;
    } else {
      const err = si && si.state === "error" ? `<div class="note note-danger" role="alert">${esc(si.message)}</div>` : "";
      const down = snap && snap.error ? `<div class="note note-warn">${esc(snap.error)}</div>` : "";
      body = `
        <h1>Sign in</h1>
        <p class="muted">Use your Vouch Compute account. Sign-in happens in your browser with your username, password and second factor, so this window never sees your password or codes.</p>
        ${err}${down}
        <button class="btn btn-primary btn-lg" id="signin-start">Sign in with the browser</button>`;
    }
  } else if (st === "device") {
    const ks = s && s.key_storage;
    const hw = (s && s.hardware) || {};
    body = `
      <h1>This device</h1>
      <div class="card stack">
        <dl class="kv">
          <dt>Processor</dt><dd>${esc(hw.cpu || "—")}</dd>
          <dt>Memory</dt><dd>${hw.ram_mb ? (hw.ram_mb / 1024).toFixed(0) + " GB" : "—"}</dd>
          <dt>Graphics</dt><dd>${esc(hw.gpu || "Not detected")}${hw.vram_mb ? `, ${(hw.vram_mb / 1024).toFixed(0)} GB` : ""}</dd>
          <dt>Device key</dt><dd>${ks === "tpm" ? `<span class="badge badge-ok">TPM 2.0</span>` : `<span class="badge badge-warn">Software key (dev)</span>`}</dd>
        </dl>
        <p class="muted small">This list is for your information only. What you can earn is decided by a benchmark, never by what the app reports.</p>
        ${ks === "tpm" ? "" : `<div class="note note-warn small">Without a hardware security chip this device stays in the Probation tier, with capped earnings.</div>`}
      </div>
      <div class="row" style="margin-top:16px"><button class="btn" data-go="signin">Back</button><span class="spacer"></span>
      <button class="btn btn-primary btn-lg" data-go="benchmark">Continue</button></div>`;
  } else if (st === "benchmark") {
    const b = s && s.status && s.status.benchmark;
    const pct = b ? Math.min(100, Math.round(((Date.now() - b.started_ms) / 1000 / Math.max(1, b.duration_s)) * 100)) : 0;
    const state = !b ? `<p class="muted">Waiting for the network to send your benchmark. Keep Vouch Compute open and plugged in.</p>`
      : b.state === "running" ? `<div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Benchmark progress"><div style="width:${pct}%"></div></div><p class="muted small">${pct}% · ${b.segments} rounds done. You can keep using your computer lightly; moving the mouse doesn't cancel it if you chose "Run now".</p>`
      : b.state === "sent" || b.state === "received" ? `<div class="note note-info">Benchmark finished. Results are checked by the server.</div>`
      : `<div class="note note-warn">The benchmark stopped before it finished. It will start again later.</div>`;
    const now = s && s.settings && s.settings.benchmark_now;
    body = `
      <h1>Benchmark</h1>
      <p class="muted">A signed, 20-minute sustained test measures what this computer can really do. It is never paid, and you can stop it at any time.</p>
      <div class="card stack">${state}
        <div class="row"><button class="btn ${now ? "" : "btn-primary"}" id="bench-now" aria-pressed="${now ? "true" : "false"}">${now ? "Run at first idle instead" : "Run now"}</button></div>
      </div>
      <div class="row" style="margin-top:16px"><button class="btn" data-go="device">Back</button><span class="spacer"></span>
      <button class="btn btn-primary btn-lg" data-go="estimate">Continue</button></div>`;
  } else if (st === "estimate") {
    body = `<h1>What you could earn</h1><div id="estimate-slot">${estimateHtml(estimateCache)}</div>
      <div class="row" style="margin-top:16px"><button class="btn" data-go="benchmark">Back</button><span class="spacer"></span>
      <button class="btn btn-primary btn-lg" data-go="controls">Continue</button></div>`;
    if (!estimateCache) loadEstimate();
  } else if (st === "controls") {
    body = `<h1>How Vouch Compute should run</h1><p class="muted">You can change this any time.</p>${controlsHtml(s ? s.settings : null)}
      <div class="row" style="margin-top:16px"><button class="btn" data-go="estimate">Back</button><span class="spacer"></span>
      <button class="btn btn-primary btn-lg" data-go="">Finish</button></div>`;
    queueMicrotask(() => wireControls());
  }
  return `<section class="onboard" aria-labelledby="ob-title">${steps(st)}<div id="ob-title" class="stack">${body}</div></section>`;
}

// ------------------------------------------------------------------ hardware-identifier consent (2.1.0)
// The text, version and hash come from the agent (the same signed-off text as the web's consent registry); the app
// shows it word for word and sends its hash back, so the consent record names exactly what the user read.
let consentCache = null;
async function loadConsent() {
  try { consentCache = await core("hw_consent.get"); } catch (e) { consentCache = { error: String(e) }; }
  if (onboardStep === "consent") render(true);
}
function consentHtml(c, decision) {
  if (!c) return `<div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div>`;
  if (c.error) return `<div class="note">${esc(c.error)}</div>`;
  const refused = decision === "refused";
  return `
    <h1>${esc("Hardware identifiers")}</h1>
    <div class="card stack">
      <p>${esc(c.text)}</p>
      <p class="muted small">Sent only to Vouch Compute's account service, never to the job network. Version ${esc(c.version)}.</p>
    </div>
    ${refused ? `<div class="note note-warn" role="alert" style="margin-top:12px">${esc(c.refused_message)}</div>` : ""}
    <div class="row" style="margin-top:16px"><button class="btn" data-go="welcome">Back</button><span class="spacer"></span>
      <button class="btn" id="consent-refuse">Don't allow</button>
      <button class="btn btn-primary btn-lg" id="consent-accept">Allow and continue</button></div>`;
}

// ------------------------------------------------------------------ account notices (node protocol 1.2.0)
// Banners only. They carry no reason; offers are not affected (a paused device simply receives none).
function noticesHtml(n) {
  if (!n) return "";
  const out = [];
  if (n.paused_by === "user") out.push(`<div class="note note-info row" role="status"><span>Paused from the web or this app. This device gets no work until you resume it.</span><span class="spacer"></span><button class="btn" data-control="resume">Resume</button></div>`);
  if (n.paused_by === "tally") out.push(`<div class="note note-warn" role="status">Paused by Vouch Compute. Contact support.</div>`);
  if (n.recovery_in_progress) out.push(`<div class="note note-warn row" role="alert"><span>Account recovery requested. If this wasn't you, cancel it on the web now.</span><span class="spacer"></span><button class="btn" data-link="recover">Open the web</button></div>`);
  if (n.reverify_required) out.push(`<div class="note note-warn row" role="status"><span>Please verify your identity again on the web.</span><span class="spacer"></span><button class="btn" data-link="verify">Verify</button></div>`);
  return out.length ? `<div class="stack" style="margin-bottom:16px">${out.join("")}</div>` : "";
}

// The runtime of the last job, in plain words (the agent reports what really ran, never what was hoped for).
function backendLabel(b) {
  if (!b) return "No job yet";
  if (b === "onnxruntime-directml") return "Graphics card (DirectML)";
  if (b === "candle-cuda") return "Graphics card (CUDA)";
  if (b.endsWith("-cpu") || b === "onnxruntime") return "Processor (CPU)";
  return b;
}

// The agent signs with the server's clock anyway; this only tells the user their clock is off.
function clockHtml(off) {
  if (typeof off !== "number" || Math.abs(off) < 5) return "";
  const n = Math.abs(off), unit = n >= 120 ? `${Math.round(n / 60)} minutes` : `${n} seconds`;
  return `<div class="note note-info" role="status">Your computer's clock is ${unit} ${off > 0 ? "behind" : "ahead"}. Vouch Compute corrects for it, but setting the time automatically in your system settings is best.</div>`;
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
    <div class="row"><span class="badge badge-ok">${esc(TIER_LABELS[r.tier])}</span>${r.since_day ? `<span class="muted small">since ${day(r.since_day)}</span>` : ""}</div>
    <dl class="kv"><dt>Queue</dt><dd>${esc(PRIORITY_WORDS[b.queue_priority] || PRIORITY_WORDS.standard)}</dd><dt>Bonus</dt><dd>${esc(bonus)}</dd></dl>
    ${hints ? `<p class="small"><strong>How to improve</strong></p><ul class="small">${hints}</ul>` : `<p class="muted small">Nothing to improve right now.</p>`}
    <p class="muted small">Tiers are decided by the server from how reliably the device is available and finishes work, and change at most once a day.</p>`;
}
// ---- reliability (end)

// ------------------------------------------------------------------ estimate (server-computed; VT: never over-promise)
let estimateCache = null;
async function loadEstimate() {
  try {
    estimateCache = { ok: await core("estimate") };
  } catch (e) {
    estimateCache = { err: String(e) };
  }
  const slot = document.getElementById("estimate-slot");
  if (slot) slot.innerHTML = estimateHtml(estimateCache);
}
function estimateHtml(c) {
  if (!c) return `<div class="row"><div class="spinner"></div><span class="muted">Asking the server for an estimate…</span></div>`;
  if (c.err)
    return `<div class="note">An estimate needs a finished benchmark and a connection to the server. (${esc(c.err)})</div>`;
  const e = c.ok;
  const a = e.assumptions || {};
  const mult = Number(e.multiplier || 1);
  return `
    <div class="card stack">
      <div class="stat"><span class="label">Estimated range per month, after electricity</span>
        <span class="range-big">${usd(e.low_usd)} – ${usd(e.high_usd)}</span></div>
      <div class="grid">
        <div class="stat"><span class="label">Base pay</span><span class="value">${usd(e.base && e.base.low_usd)} – ${usd(e.base && e.base.high_usd)}</span>
          <span class="muted small">What the work earns on its own.</span></div>
        <div class="stat"><span class="label">Launch bonus</span><span class="value">${mult > 1 ? `×${mult.toFixed(2)}` : "None"}</span>
          <span class="muted small">${mult > 1 ? `A temporary launch bonus${e.multiplier_end ? `, ends ${day(e.multiplier_end)}` : ""}. It tapers as paid demand grows.` : "No launch bonus right now."}</span></div>
        <div class="stat"><span class="label">Electricity</span><span class="value">−${usd(a.electricity_cost_usd)}</span>
          <span class="muted small">${esc(a.avg_watts ?? "?")} W at $${esc(a.electricity_usd_per_kwh ?? "?")}/kWh, already subtracted.</span></div>
      </div>
      <p class="muted small">Assumes ${esc(a.hours_per_day ?? "?")} h/day available and ${Math.round((a.utilization ?? 0) * 100)}% of that time with work. This is a range, not a promise: earnings depend on demand, and only verified work is paid.</p>
    </div>`;
}

// ------------------------------------------------------------------ main views
function renderAgentDown() {
  return `<div class="card stack"><h1>The Vouch Compute agent isn't running</h1>
    <p class="muted">${esc(snap.error)}</p><button class="btn btn-primary" id="start-core">Start it</button></div>`;
}

function renderStatus() {
  const [cls, title, sub] = describe(snap);
  const st = snap.status;
  const s = snap.settings;
  const paused = s.paused_until_ms && s.paused_until_ms > Date.now();
  const needSignIn = ["not_signed_in", "auth_failed"].includes(st.connection);
  return `${noticesHtml(st.notices)}${clockHtml(st.clock_offset_s)}
    <section class="card hero" aria-labelledby="state-title">
      <div class="pulse ${cls}" aria-hidden="true"></div>
      <div class="stack" style="flex:1">
        <div><h1 id="state-title">${esc(title)}</h1><p class="muted">${sub}</p></div>
        <div class="row">
          ${needSignIn ? `<button class="btn btn-primary" data-go-onboard="signin">Sign in</button>` : paused
            ? `<button class="btn btn-primary" id="resume">Resume now</button>`
            : `<button class="btn" id="pause">Pause for 1 hour</button>`}
          <span class="muted small">Mode: <strong>${{ idle_only: "When idle", scheduled: "On a schedule", always_on: "Always on" }[s.mode]}</strong></span>
        </div>
      </div>
    </section>
    <div class="grid" style="margin-top:16px">
      <section class="card stat"><span class="label">Jobs this session</span><span class="value">${st.jobs_completed}</span>
        <span class="muted small">${st.jobs_abandoned ? `${st.jobs_abandoned} stopped early (not paid)` : "Verified on the server before they count."}</span></section>
      <section class="card stat"><span class="label">Worked today</span><span class="value">${(snap.worked_today_s / 3600).toFixed(1)} h</span>
        <span class="muted small">${s.daily_cap_hours ? `Limit ${s.daily_cap_hours} h` : "No daily limit"}</span></section>
      <section class="card stat"><span class="label">Temperature limit</span><span class="value">${s.temp_cap_c} °C</span>
        <span class="muted small">${s.never_on_battery ? "Never on battery" : "Allowed on battery above 30%"}</span></section>
    </div>
    ${st.last_error && st.connection !== "connected" ? `<div class="note small" style="margin-top:16px">Last problem: ${esc(st.last_error)}</div>` : ""}`;
}

function controlsHtml(s) {
  if (!s) return `<p class="muted">Controls appear once the agent is running.</p>`;
  const dayNames = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const hhmm = (m) => `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
  const windows = (s.schedule || []).map((w, i) => `
    <div class="window-row" data-win="${i}">
      <div class="days" role="group" aria-label="Days for window ${i + 1}">${dayNames.map((n, d) =>
        `<label><input type="checkbox" data-day="${d}" ${w.days & (1 << d) ? "checked" : ""}/><span>${n}</span></label>`).join("")}</div>
      <label class="row small">From <input type="time" data-k="start" value="${hhmm(w.start_min)}"/></label>
      <label class="row small">to <input type="time" data-k="end" value="${hhmm(w.end_min)}"/></label>
      <button type="button" class="btn btn-ghost small" data-remove="${i}" aria-label="Remove window ${i + 1}">Remove</button>
    </div>`).join("");
  return `
  <form id="controls" class="stack" novalidate>
    <section class="card"><fieldset>
      <legend>When should Vouch Compute work?</legend>
      <label class="choice"><input type="radio" name="mode" value="idle_only" ${s.mode === "idle_only" ? "checked" : ""}/>
        <span><strong>When I'm away (recommended)</strong><span class="muted small">Starts after you've been idle, stops within seconds when you're back.</span></span></label>
      <label class="choice"><input type="radio" name="mode" value="scheduled" ${s.mode === "scheduled" ? "checked" : ""}/>
        <span><strong>On a schedule</strong><span class="muted small">Only in the hours you pick below.</span></span></label>
      <label class="choice"><input type="radio" name="mode" value="always_on" ${s.mode === "always_on" ? "checked" : ""}/>
        <span><strong>Always on</strong><span class="muted small">Desktops only. Your computer will feel slower while it works.</span></span></label>
      <div class="field" style="margin-top:12px"><label for="idle">Start after being idle for <output id="idle-out">${s.idle_minutes}</output> minutes</label>
        <input id="idle" type="range" min="1" max="60" value="${s.idle_minutes}" name="idle_minutes"/></div>
    </fieldset></section>
    <section class="card"><fieldset>
      <legend>Schedule</legend>
      <p class="muted small">Used in "On a schedule" mode. Times are local; a window can run past midnight.</p>
      <div id="windows">${windows || `<p class="muted small">No windows yet.</p>`}</div>
      <button type="button" class="btn" id="add-window">Add a time window</button>
      <div class="field" style="margin-top:12px"><label for="cap">Daily limit (hours, empty for none)</label>
        <input id="cap" type="number" min="0.5" max="24" step="0.5" value="${s.daily_cap_hours ?? ""}" name="daily_cap_hours" style="max-width:140px"/></div>
    </fieldset></section>
    <section class="card"><fieldset>
      <legend>Limits</legend>
      <div class="field"><label for="temp">Pause above <output id="temp-out">${s.temp_cap_c}</output> °C</label>
        <input id="temp" type="range" min="65" max="85" value="${s.temp_cap_c}" name="temp_cap_c"/>
        <span class="muted small">Vouch Compute never exceeds 90 °C, whatever this is set to.</span></div>
      <div class="field" style="margin-top:12px"><label for="power">Power use: <output id="power-out">${s.power_pct}</output>%</label>
        <input id="power" type="range" min="10" max="100" step="10" value="${s.power_pct}" name="power_pct"/></div>
      <div class="switch"><label for="batt"><strong>Never run on battery</strong><br/><span class="muted small">Below 30% battery it never runs, regardless.</span></label>
        <input id="batt" class="toggle" type="checkbox" name="never_on_battery" ${s.never_on_battery ? "checked" : ""}/></div>
      <div class="switch"><label for="fs"><strong>Pause during games and fullscreen</strong></label>
        <input id="fs" class="toggle" type="checkbox" name="pause_in_fullscreen" ${s.pause_in_fullscreen ? "checked" : ""}/></div>
    </fieldset></section>
    <p class="row"><span class="saved" id="saved" role="status">Saved</span></p>
  </form>`;
}

function renderControls() {
  return `<h1>Controls</h1>${controlsHtml(snap.settings)}`;
}

function readControls(form, base) {
  const s = structuredClone(base);
  const fd = new FormData(form);
  s.mode = fd.get("mode") || s.mode;
  s.idle_minutes = Number(form.idle_minutes.value);
  s.temp_cap_c = Number(form.temp_cap_c.value);
  s.power_pct = Number(form.power_pct.value);
  s.never_on_battery = form.never_on_battery.checked;
  s.pause_in_fullscreen = form.pause_in_fullscreen.checked;
  const cap = form.daily_cap_hours.value.trim();
  s.daily_cap_hours = cap === "" ? null : Number(cap);
  const toMin = (v) => { const [h, m] = (v || "0:0").split(":").map(Number); return h * 60 + m; };
  s.schedule = [...form.querySelectorAll("[data-win]")].map((row) => ({
    days: [...row.querySelectorAll("[data-day]")].reduce((acc, c) => acc | (c.checked ? 1 << Number(c.dataset.day) : 0), 0),
    start_min: toMin(row.querySelector('[data-k="start"]').value),
    end_min: toMin(row.querySelector('[data-k="end"]').value),
  }));
  return s;
}

let saveTimer = null;
function wireControls() {
  const form = document.getElementById("controls");
  if (!form || form.dataset.wired) return;
  form.dataset.wired = "1";
  const outs = { idle_minutes: "idle-out", temp_cap_c: "temp-out", power_pct: "power-out" };
  const save = (immediate) => {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      try {
        const s = await core("settings.set", readControls(form, snap.settings));
        snap.settings = s;
        const el = document.getElementById("saved");
        if (el) { el.classList.add("show"); setTimeout(() => el.classList.remove("show"), 1200); }
        announce("Settings saved");
      } catch (e) { announce(`Could not save: ${e}`); }
    }, immediate ? 0 : 350);
  };
  form.addEventListener("input", (e) => {
    const o = outs[e.target.name];
    if (o) document.getElementById(o).textContent = e.target.value;
    save(false);
  });
  form.addEventListener("change", () => save(true));
  form.addEventListener("click", async (e) => {
    if (e.target.id === "add-window") {
      snap.settings = await core("settings.set", { ...readControls(form, snap.settings), schedule: [...readControls(form, snap.settings).schedule, { days: 0b0011111, start_min: 22 * 60, end_min: 7 * 60 }] });
      render(true);
    } else if (e.target.dataset.remove != null) {
      const s = readControls(form, snap.settings);
      s.schedule.splice(Number(e.target.dataset.remove), 1);
      snap.settings = await core("settings.set", s);
      render(true);
    }
  });
}

function renderEarnings() {
  return `<h1>Earnings</h1>
    <p class="muted">Figures come from the server once a day and cover work from at least 24 hours ago.</p>
    <div id="earn-slot"><div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div></div>
    <section class="card stack" style="margin-top:16px" aria-labelledby="wallet-h">
      <h2 id="wallet-h">Payout wallet</h2>
      <div id="wallet-slot" class="muted">Loading…</div>
      <div class="row"><button class="btn" data-link="wallet">Link or change wallet on the web</button></div>
      <p class="muted small">For your safety, wallets are linked only on the web, with a signed message from the wallet and your second factor. Any change pauses payouts for 72 hours.</p>
      <p class="small">Verify your identity on the web to get paid. <button class="linklike" data-link="verify">Verify on the web</button></p>
    </section>
    <section class="card stack" style="margin-top:16px"><h2>Your estimate</h2><div id="estimate-slot">${estimateHtml(estimateCache)}</div></section>`;
}

const LABELS = [["pending", "Pending", "Held 72 h before release"], ["in_escrow", "In escrow", "Probation: held 21 days"],
  ["in_review", "In review", "Being checked, not forfeited"], ["releasable", "Releasable", "Goes out with the next weekly payout"],
  ["sent", "Sent", "Paid to your wallet"], ["clawed_back", "Clawed back", "Reversed after review"]];

async function wireAsync(v) {
  if (v === "controls") return wireControls();
  const es = document.getElementById("earn-slot");
  if (!es || es.dataset.loaded) return;
  es.dataset.loaded = "1";
  try {
    const e = await core("earnings");
    const t = e.totals || {};
    es.innerHTML = `<div class="grid">${LABELS.map(([k, l, hint]) =>
      `<section class="card stat"><span class="label">${l}</span><span class="value">${usd(t[k])}</span><span class="muted small">${hint}</span></section>`).join("")}</div>
      ${e.probation && e.probation.active ? `<div class="note note-info" style="margin-top:16px">New device: earnings are held for ${e.probation.escrow_days} days while work is verified${e.probation.ends_on ? ` (until ${day(e.probation.ends_on)})` : ""}.</div>` : ""}
      ${(e.alerts || []).map((a) => `<div class="note note-warn" style="margin-top:12px">${esc(a.message)}</div>`).join("")}
      <p class="muted small" style="margin-top:12px">Verified this week: ${usd(e.this_week_verified_usd)}. As of ${day(e.as_of)}. Detailed history is on the <button class="linklike" data-link="dashboard">web dashboard</button>.</p>`;
  } catch (err) {
    es.innerHTML = `<div class="note">Earnings are available once you're signed in and online. (${esc(err)})</div>`;
  }
  const ws = document.getElementById("wallet-slot");
  try {
    const w = await core("wallets");
    const list = (w && w.data) || (Array.isArray(w) ? w : []);
    ws.innerHTML = list.length ? list.map((x) => {
      const frozen = x.payout_freeze_until && new Date(x.payout_freeze_until) > new Date();
      return `<div class="row"><span class="badge">${esc(x.chain)}</span><span class="mono" title="${esc(x.address)}">${esc(x.address.slice(0, 6))}…${esc(x.address.slice(-6))}</span>
        <span class="badge ${x.status === "active" ? "badge-ok" : "badge-warn"}">${esc(x.status)}</span>
        ${frozen ? `<span class="muted small">Payouts resume ${day(x.payout_freeze_until)}</span>` : ""}</div>`;
    }).join("") : `<p>No wallet linked yet. Earnings keep accruing; link one on the web before your first payout.</p>`;
  } catch (err) {
    ws.textContent = "Wallet details are available once you're signed in.";
  }
  if (!estimateCache || estimateCache.err) loadEstimate();
}

function renderDevice() {
  const st = snap.status;
  const hw = snap.hardware || {};
  return `<h1>Device</h1>
    <section class="card stack">
      <dl class="kv">
        <dt>Device ID</dt><dd class="mono small">${esc(snap.device_id || "Not registered")}</dd>
        <dt>Device key</dt><dd>${snap.key_storage === "tpm" ? "TPM 2.0 (hardware, non-exportable)" : "Software key (dev tier: capped at Probation)"}</dd>
        <dt>Trust ceiling</dt><dd>${esc(snap.trust_ceiling || "—")}</dd>
        <dt>Sandbox</dt><dd>${esc(st.sandbox || "Not used yet")}</dd>
        <dt>Last job ran on</dt><dd>${esc(backendLabel(st.backend))}</dd>
        <dt>Processor</dt><dd>${esc(hw.cpu || "—")}</dd>
        <dt>Graphics</dt><dd>${esc(hw.gpu || "Not detected")}</dd>
        <dt>Agent version</dt><dd>${esc(snap.version)}</dd>
      </dl>
      <p class="muted small">Jobs run in a separate sandboxed process with no network access and no access to your files. Inputs stay in memory and are never written to disk.</p>
    </section>
    <section class="card stack" style="margin-top:16px" aria-labelledby="rel-h">
      <h2 id="rel-h">Reliability</h2>
      <div id="device-slot"><div class="row"><div class="spinner"></div><span class="muted">Loading…</span></div></div>
    </section>
    <section class="card stack" style="margin-top:16px" aria-labelledby="act-h">
      <h2 id="act-h">This device on your account</h2>
      <div id="device-state" class="muted small"></div>
      <div class="row">
        <button class="btn" data-control="pause">Pause on the server</button>
        <button class="btn" data-control="resume">Resume</button>
        <button class="btn" data-link="devices">Manage on the web</button>
      </div>
      <p class="muted small">Pausing here works like pausing on the web: no new work arrives until you resume. A running job finishes and is paid if it verifies.</p>
      <details><summary>Remove this device</summary>
        <p class="small">Removes this computer from your account and deletes its key. Earnings stay with your account. This can't be undone; registering again makes it a new device.</p>
        <label class="row small">Type REMOVE to confirm <input id="remove-confirm" autocomplete="off" style="max-width:120px"/></label>
        <button class="btn btn-danger" id="remove-device">Remove this device</button>
      </details>
    </section>
    <section class="card stack" style="margin-top:16px" aria-labelledby="rec-h">
      <h2 id="rec-h">Recover my account</h2>
      <p class="muted small">Only if you started an account recovery on the web and it asks for a code from this app.</p>
      <div id="recover-slot"><button class="btn" id="recover-start">I have a recovery code</button></div>
    </section>
    <section class="card stack" style="margin-top:16px">
      <h2>Updates</h2>
      <p class="muted small">Updates are signed; Vouch Compute refuses any update whose signature doesn't verify.</p>
      <div class="row"><button class="btn" id="check-update">Check for updates</button><span id="update-result" class="muted small" role="status"></span></div>
    </section>
    <section class="card stack" style="margin-top:16px">
      <h2>Account</h2>
      <div class="row"><button class="btn" data-link="dashboard">Open web dashboard</button><button class="btn" data-link="trust">How verification works</button>
      <span class="spacer"></span><button class="btn btn-ghost" id="signout">Sign out</button></div>
      <details><summary class="small">Advanced: repair device identity</summary>
        <p class="small">Creates a new key for this computer, vouched for by the current one, and keeps its tier. Use it only if support asks you to.</p>
        <button class="btn" id="repair-identity">Repair device identity</button></details>
    </section>`;
}

const ACTIVITY = { idle: "idle", working: "working", paused: "paused" };
async function loadDevice() {
  const slot = document.getElementById("device-slot");
  if (!slot || slot.dataset.loaded) return;
  slot.dataset.loaded = "1";
  try {
    const d = await core("device");
    slot.innerHTML = reliabilityHtml(d.reliability);
    const st = document.getElementById("device-state");
    if (st) st.textContent = `${d.connection === "online" ? "Online" : "Offline"}${d.activity ? `, ${ACTIVITY[d.activity] || ""}` : ""}${d.paused_by === "user" ? ". Paused by you." : d.paused_by === "tally" ? ". Paused by Vouch Compute." : ""}`;
  } catch (e) {
    slot.innerHTML = `<p class="muted small">Available once this device is registered and online.</p>`;
  }
}

// ------------------------------------------------------------------ events
document.addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  try {
    if (t.dataset.go !== undefined) return goStep(t.dataset.go || null);
    if (t.dataset.goOnboard) return goStep(t.dataset.goOnboard);
    if (t.dataset.link) return await invoke("open_link", { kind: t.dataset.link });
    if (t.dataset.control) {
      await core("device.control", { action: t.dataset.control });
      announce(t.dataset.control === "pause" ? "Paused on the server" : "Resumed");
      return refresh();
    }
    if (t.dataset.replace !== undefined) {
      await core("enroll", { replaces_device_id: t.dataset.replace || null });
      return refresh();
    }
    switch (t.id) {
      case "agree": return goStep("consent");
      case "consent-accept":
        await core("hw_consent.set", { accept: true, text_sha256: consentCache.text_sha256 });
        await refresh();
        return goStep("signin");
      case "consent-refuse":
        await core("hw_consent.set", { accept: false, text_sha256: consentCache.text_sha256 });
        return refresh().then(() => render(true));
      case "remove-device": {
        const v = (document.getElementById("remove-confirm") || {}).value || "";
        if (v.trim() !== "REMOVE") { announce("Type REMOVE to confirm"); return; }
        await core("device.control", { action: "self_revoke", confirm: "remove" });
        announce("This device was removed");
        return refresh();
      }
      case "recover-start":
        document.getElementById("recover-slot").innerHTML = `<label class="field">Code from the web<input id="recover-code" autocomplete="off" spellcheck="false"/></label>
          <div class="row"><button class="btn btn-primary" id="recover-send">Sign with this device</button></div>`;
        return;
      case "recover-send": {
        const code = document.getElementById("recover-code").value;
        const r = await core("recovery.prove", { code });
        document.getElementById("recover-slot").innerHTML = `<div class="note note-info">${esc(r.message)}</div>`;
        return;
      }
      case "repair-identity": await core("identity.repair"); announce("Device identity repaired"); return refresh();
      case "signin-start":
        t.disabled = true;
        await core("signin.start");
        await refresh();
        await invoke("open_link", { kind: "signin" }).catch(() => {});
        return;
      case "bench-now": await core("benchmark.now", { enabled: t.getAttribute("aria-pressed") !== "true" }); return refresh();
      case "pause": await core("pause", { minutes: 60 }); announce("Paused for one hour"); return refresh();
      case "resume": await core("resume"); announce("Resumed"); return refresh();
      case "start-core": await invoke("ensure_core"); return refresh();
      case "signout": await core("signout"); return refresh();
      case "check-update": {
        const out = document.getElementById("update-result");
        out.textContent = "Checking…";
        try {
          const u = await invoke("check_update");
          out.innerHTML = u.available ? `Version ${esc(u.version)} is available. <button class="btn btn-primary" id="install-update">Install and restart</button>` : "You're up to date.";
        } catch (err) { out.textContent = String(err); }
        return;
      }
      case "install-update": return await invoke("install_update");
    }
  } catch (err) {
    announce(String(err));
    alert(String(err));
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
  if (d && b && b.disabled && d.scrollHeight <= d.clientHeight + 8) b.disabled = false;
}).observe($main, { childList: true });

// ------------------------------------------------------------------ boot
// Browser preview only: #view=<name> skips onboarding, #step=<name> opens a setup step.
if (!TAURI && location.hash) {
  const p = new URLSearchParams(location.hash.slice(1));
  if (p.get("view")) { onboardStep = null; view = p.get("view"); }
  if (p.get("step")) onboardStep = p.get("step");
  if (p.get("theme")) document.documentElement.dataset.theme = p.get("theme");
}
setView(view);
(async () => {
  if (TAURI) { try { await invoke("ensure_core"); } catch (e) { /* shown by refresh */ } }
  await refresh();
  // "DEV BUILD" stays unless both the app and its agent are release builds
  try {
    const b = await invoke("build_info");
    const agentDev = !snap || snap.error || !snap.build || snap.build.dev_build !== false;
    const badge = document.getElementById("dev-badge");
    if (badge && b && b.dev_build === false && !agentDev) badge.remove();
  } catch (e) { /* keep the marker */ }
  setInterval(refresh, 1500);
})();

// ------------------------------------------------------------------ demo backend (browser preview only)
function demoInvoke(cmd, args) {
  const now = Date.now();
  const settings = demoInvoke.settings || (demoInvoke.settings = { mode: "idle_only", idle_minutes: 10, temp_cap_c: 80, power_pct: 100, never_on_battery: true, pause_in_fullscreen: true, schedule: [], daily_cap_hours: null, paused_until_ms: null, benchmark_now: false });
  const m = args && args.method;
  const R = (v) => Promise.resolve(v);
  if (cmd === "ensure_core") return R(null);
  if (cmd === "open_link") return R(null);
  if (cmd === "check_update") return R({ available: false });
  if (cmd === "build_info") return R({ channel: "dev", dev_build: true });
  if (m === "hw_consent.get") return R({ kind: "hw_identifiers", version: "2026-11-19.draft-2", text: "The desktop app sends identifiers of this computer's hardware (security chip, graphics card, board, disk, network adapters) to Vouch Compute so that one physical machine counts as one device. We keep only keyed fingerprints of them, never the raw values such as MAC addresses or serial numbers. Withdrawing this stops further reports, and a device without it cannot be enrolled for paid work.", text_sha256: "0".repeat(64), decision: null, refused_message: "Vouch Compute can't register this computer for paid work without the hardware check." });
  if (m === "device") return R({ device_id: "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f", name: "Gaming PC", connection: "online", activity: "working", paused_by: null, reliability: { tier: "stable", since_day: "2026-11-12", benefits: { queue_priority: "higher", bonus_pct: 5 }, improve: ["keep_regular_hours", "avoid_disconnects"] } });
  if (m === "status") return R({ version: "0.1.0", signed_in: true, device_id: "7d0c3c9e-1b2a-4f5e-9c8d-0a1b2c3d4e5f", trust_ceiling: "capped", key_storage: "tpm",
    settings, worked_today_s: 5400, signin: { state: "done" }, hw_consent: "accepted", build: { dev_build: true }, links: {}, hardware: { cpu: "AMD Ryzen 7 7700", ram_mb: 32768, gpu: "NVIDIA GeForce RTX 4070", vram_mb: 12282 },
    status: { connection: "connected", decision: { state: "run" }, job: { model_id: "whisper-small", since_ms: now - 20000 }, jobs_completed: 37, jobs_abandoned: 1, benchmark: { benchmark_id: "b", state: "sent", started_ms: now - 1300000, duration_s: 1200, segments: 120 }, sandbox: "WindowsLpac", last_error: null, notices: { paused_by: null, recovery_in_progress: false, reverify_required: false } } });
  if (m === "settings.set") { Object.assign(settings, args.params); return R(settings); }
  if (m === "estimate") return R({ low_usd: "9.000000000", high_usd: "24.000000000", period: "month", base: { low_usd: "3.500000000", high_usd: "9.000000000" }, multiplier: 3, multiplier_end: "2027-03-01T00:00:00Z", assumptions: { utilization: 0.35, hours_per_day: 14, electricity_usd_per_kwh: 0.15, avg_watts: 180, electricity_cost_usd: "4.100000000" }, rate_card_version: 1 });
  if (m === "earnings") return R({ as_of: "2026-11-17", totals: { pending: "2.310000000", in_escrow: "6.870000000", in_review: "0.120000000", releasable: "0.000000000", sent: "0.000000000", clawed_back: "0.000000000" }, this_week_verified_usd: "3.100000000", probation: { active: true, escrow_days: 21, ends_on: "2026-12-05" }, alerts: [] });
  if (m === "wallets") return R({ data: [{ wallet_id: "w", chain: "solana", address: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", status: "active", linked_at: "2026-11-01T00:00:00Z", payout_freeze_until: "2026-11-04T00:00:00Z" }] });
  return R({});
}
