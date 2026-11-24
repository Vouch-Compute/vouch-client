// Homebrew cask checks: scripts/update-cask.sh writes the version, sha256 and URL of a release into the cask from a
// SHA256SUMS file and leaves valid Ruby behind, and the cask describes the app the Tauri config builds (app name,
// minimum macOS, bundle id). Run: node pool-app/tests/homebrew-cask.test.js
//
// `brew audit` and `brew style` need a Mac; they run in the tap repository's workflow. `ruby -c` runs here only when
// ruby is on PATH (it is on every Mac, not on the Windows CI box).
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const tests = path.resolve(__dirname);
const repo = path.resolve(tests, "..", "..", "..");
const fixture = path.join(tests, "fixtures", "vouch-compute.rb");
// in vouch-client the script is scripts/update-cask.sh; in the monorepo it waits in the vouch-client template
const script = [path.join(repo, "scripts", "update-cask.sh"), path.join(repo, "scripts", "m10", "templates", "vouch-client", "scripts", "update-cask.sh")]
  .find((p) => fs.existsSync(p));
const tauriConf = JSON.parse(fs.readFileSync(path.join(repo, "client", "pool-app", "src-tauri", "tauri.conf.json"), "utf8"));
const releaseConf = JSON.parse(fs.readFileSync(path.join(repo, "client", "pool-app", "src-tauri", "tauri.release.conf.json"), "utf8"));

let bad = 0;
const fail = (m) => { bad++; console.log("FAIL", m); };
const ok = (c, m) => { if (!c) fail(m); };

// ---- the cask against the Tauri config
const cask = fs.readFileSync(fixture, "utf8");
ok(cask.includes(`  app "${tauriConf.productName}.app"`), `app name is not "${tauriConf.productName}.app"`);
const minOs = { 13: "ventura", 14: "sonoma", 15: "sequoia", 26: "tahoe" }[tauriConf.bundle.macOS.minimumSystemVersion.split(".")[0]];
ok(minOs, `no Homebrew symbol for minimumSystemVersion ${tauriConf.bundle.macOS.minimumSystemVersion}`);
ok(cask.includes(`  depends_on macos: ">= :${minOs}"`), `depends_on macos does not say ">= :${minOs}"`);
ok(cask.includes("  depends_on arch: :arm64"), "depends_on arch: :arm64 missing (the release is aarch64 only)");
ok(cask.includes(`quit:      "${releaseConf.identifier}"`), `uninstall quit: is not the release bundle id ${releaseConf.identifier}`);
ok(!cask.includes(tauriConf.identifier + '"'), `the dev bundle id ${tauriConf.identifier} must not appear in the cask`);
for (const p of ["~/Library/Application Support/", "~/Library/Caches/", "~/Library/Preferences/", "~/Library/WebKit/"]) {
  ok(cask.includes(`"${p}${releaseConf.identifier}`), `zap is missing ${p}${releaseConf.identifier}`);
}
ok(cask.includes(`launchctl: "${tauriConf.productName}"`), "uninstall launchctl: must be the LaunchAgent label (the product name, set by tauri-plugin-autostart)");
ok(!/no.quarantine/i.test(cask), "the cask must not mention --no-quarantine");
ok(cask.includes(`url "${releaseConf.plugins.updater.endpoints[0]}"`), "livecheck must read the release updater manifest");

// the monorepo keeps the template the tap repository is created from; the fixture must be that file
const template = path.join(repo, "scripts", "m10", "templates", "homebrew-tap", "Casks", "vouch-compute.rb");
if (fs.existsSync(template)) ok(fs.readFileSync(template, "utf8") === cask, "tests/fixtures/vouch-compute.rb differs from the tap template");

// ---- structure: a cask is one `cask "token" do ... end` block with balanced blocks and closed strings
function checkRuby(text, label) {
  const lines = text.split("\n");
  ok(lines[0] === 'cask "vouch-compute" do', `${label}: first line is not the cask header`);
  ok(lines.filter((l) => l.trim() !== "").at(-1) === "end", `${label}: last line is not end`);
  let depth = 0;
  for (const l of lines) {
    const code = l.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/#.*$/, "");
    ok(((l.match(/"/g) || []).length % 2) === 0, `${label}: odd number of quotes: ${l}`);
    if (/\bdo\b(\s*\|[^|]*\|)?\s*$/.test(code)) depth++;
    if (/^\s*end\s*$/.test(code)) depth--;
    ok(depth >= 0, `${label}: end without do: ${l}`);
  }
  ok(depth === 0, `${label}: ${depth} unclosed do block(s)`);
  for (const stanza of ["version", "sha256", "url", "name", "desc", "homepage", "app", "uninstall", "zap"]) {
    ok(new RegExp(`^  ${stanza} `, "m").test(text), `${label}: no ${stanza} stanza`);
  }
  const ruby = spawnSync("ruby", ["-c", "-e", text], { encoding: "utf8" });
  if (ruby.error) console.log(`note: ruby not on PATH, syntax check skipped for ${label} (runs on the Mac)`);
  else ok(ruby.status === 0, `${label}: ruby -c failed: ${ruby.stderr}`);
}
checkRuby(cask, "template");

// ---- the updater on a fake SHA256SUMS
const bash = process.platform === "win32" && fs.existsSync("C:\\Program Files\\Git\\bin\\bash.exe") ? "C:\\Program Files\\Git\\bin\\bash.exe" : "bash";
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cask-test-"));
const sha = "a".repeat(40) + "0123456789abcdef0123456f";
const sums = [
  `${"b".repeat(64)}  VouchCompute-0.4.2-macos-arm64.app.tar.gz`,
  `${sha}  VouchCompute-0.4.2-macos-arm64.dmg`,
  `${"c".repeat(64)}  VouchCompute-0.4.2-macos-arm64.app.tar.gz.sig`,
  `${"d".repeat(64)}  latest.json`,
].join("\n") + "\n";
fs.writeFileSync(path.join(tmp, "SHA256SUMS"), sums);

function run(base, sumsFile = "SHA256SUMS") {
  const out = path.join(tmp, "Casks");
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out);
  fs.copyFileSync(fixture, path.join(out, "vouch-compute.rb"));
  const env = { ...process.env, VOUCH_TAURI_CONF: path.join(repo, "client", "pool-app", "src-tauri", "tauri.conf.json") };
  if (base === undefined) delete env.VOUCH_DOWNLOAD_BASE; else env.VOUCH_DOWNLOAD_BASE = base;
  const toPosix = (p) => (process.platform === "win32" ? p.replace(/^([A-Za-z]):\\/, (_, d) => `/${d.toLowerCase()}/`).replace(/\\/g, "/") : p);
  env.VOUCH_TAURI_CONF = toPosix(env.VOUCH_TAURI_CONF);
  const r = spawnSync(bash, [toPosix(script), toPosix(path.join(tmp, sumsFile)), toPosix(path.join(out, "vouch-compute.rb"))], { encoding: "utf8", env });
  return { ...r, cask: fs.readFileSync(path.join(out, "vouch-compute.rb"), "utf8") };
}

const cases = [
  ["https://downloads.vouchcompute.com/macos/#{version}",
    'url "https://downloads.vouchcompute.com/macos/#{version}/VouchCompute-#{version}-macos-arm64.dmg",', 'verified: "downloads.vouchcompute.com/macos/"'],
  ["https://github.com/MetehanAydemir/vouch-client/releases/download/client-macos-v#{version}/",
    'url "https://github.com/MetehanAydemir/vouch-client/releases/download/client-macos-v#{version}/VouchCompute-#{version}-macos-arm64.dmg",',
    'verified: "github.com/MetehanAydemir/vouch-client/"'],
];
for (const [base, urlLine, verifiedLine] of cases) {
  const r = run(base);
  ok(r.status === 0, `updater failed for ${base}: ${r.stderr}`);
  ok(r.cask.includes('\n  version "0.4.2"\n'), `version not written for ${base}`);
  ok(r.cask.includes(`\n  sha256 "${sha}"\n`), `sha256 of the .dmg line not written for ${base}`);
  ok(!r.cask.includes("b".repeat(64)) && !r.cask.includes("0".repeat(64)), `wrong checksum picked for ${base}`);
  ok(r.cask.includes(`\n  ${urlLine}\n`), `url line wrong for ${base}:\n${r.cask}`);
  ok(r.cask.includes(`\n      ${verifiedLine}\n`), `verified line wrong for ${base}:\n${r.cask}`);
  ok(/git tag v0\.4\.2/.test(r.stdout) && /git push origin HEAD v0\.4\.2/.test(r.stdout) && /git commit -m/.test(r.stdout), `git commands not printed for ${base}`);
  ok(!/git (commit|push|tag)/.test(r.stderr), "the updater must only print git commands, never run them");
  checkRuby(r.cask, `updated (${base})`);
  // everything but the four lines is unchanged
  const strip = (t) => t.split("\n").filter((l) => !/^  (version|sha256|url) "|^      verified: "/.test(l)).join("\n");
  ok(strip(r.cask) === strip(cask), `lines other than version, sha256, url and verified changed for ${base}`);
}

// refusals
ok(run(undefined).status !== 0, "must refuse without VOUCH_DOWNLOAD_BASE");
ok(run("http://downloads.vouchcompute.com/macos/#{version}").status !== 0, "must refuse a non-https base");
ok(run("https://downloads.vouchcompute.com/macos/latest").status !== 0, "must refuse a base without the #{version} placeholder");
fs.writeFileSync(path.join(tmp, "NODMG"), sums.split("\n").filter((l) => !l.endsWith(".dmg")).join("\n") + "\n");
ok(run("https://downloads.vouchcompute.com/macos/#{version}", "NODMG").status !== 0, "must refuse a SHA256SUMS without the .dmg line");
fs.writeFileSync(path.join(tmp, "TWODMG"), sums + `${"e".repeat(64)}  VouchCompute-0.4.3-macos-arm64.dmg\n`);
ok(run("https://downloads.vouchcompute.com/macos/#{version}", "TWODMG").status !== 0, "must refuse a SHA256SUMS with two .dmg lines");
const unchanged = run("https://downloads.vouchcompute.com/macos/latest");
ok(unchanged.cask === cask, "a refused run must leave the cask untouched");

fs.rmSync(tmp, { recursive: true, force: true });
if (bad) { console.log(`${bad} failure(s)`); process.exit(1); }
console.log("homebrew-cask.test.js OK");
