// Self-test of the release bundle check (client/ci/release-pack-check.sh): it passes a bundle whose packaged pack
// bytes match the pins and fails closed on anything else, in every macOS form it opens (the .app and the updater
// archive; the .dmg needs hdiutil, so macOS runners only) and in the Linux .deb (where dpkg-deb exists).
// Run: node pool-app/tests/release-pack-check.test.js
// Fixtures only: a stand-in pin table (PACKS_JSON) and fake library bytes; the unsigned fixtures skip the signature
// check (PACK_CHECK_NO_CODESIGN).
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const client = path.resolve(__dirname, "..", "..");
const script = path.join(client, "ci", "release-pack-check.sh");
const product = JSON.parse(fs.readFileSync(path.join(client, "pool-app", "src-tauri", "tauri.conf.json"), "utf8")).productName;
// Git for Windows' bash (not WSL's System32\bash.exe) on Windows, the system bash elsewhere
const bash = process.platform === "win32" ? ["C:\\Program Files\\Git\\bin\\bash.exe", "C:\\Program Files\\Git\\usr\\bin\\bash.exe"].find((p) => fs.existsSync(p)) : "bash";
const has = (cmd) => spawnSync(bash, ["-c", `command -v ${cmd}`]).status === 0;

let bad = 0;
const ok = (c, m) => { if (!c) { bad++; console.log("FAIL", m); } };
if (!bash) { console.log("release pack check self-test: skipped (no Git Bash)"); process.exit(0); }

const root = fs.mkdtempSync(path.join(os.tmpdir(), "pack-check-"));
const good = Buffer.from("pinned runtime library bytes\n");
const sha = crypto.createHash("sha256").update(good).digest("hex");
const pins = path.join(root, "packs.json");
fs.writeFileSync(pins, JSON.stringify({ packs: [
  { runtime: "onnxruntime", target: "macos-aarch64", dir: "ort-cpu", library: "libonnxruntime.dylib", files: [{ name: "libonnxruntime.dylib", sha256: sha }] },
  { runtime: "onnxruntime", target: "linux-x86_64", dir: "ort-cpu", library: "libonnxruntime.so", files: [{ name: "libonnxruntime.so", sha256: sha }] },
] }));
const toPosix = (p) => (process.platform === "win32" ? p.replace(/\\/g, "/") : p);
const run = (target, bundle, env) => {
  const r = spawnSync(bash, [toPosix(script), target, toPosix(bundle)], { env: { ...process.env, PACKS_JSON: toPosix(pins), PACK_CHECK_NO_CODESIGN: "1", ...env }, encoding: "utf8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const tar = (args, cwd) => spawnSync(bash, ["-c", `tar ${args}`], { cwd, encoding: "utf8" });

// a macOS bundle: the .app and its updater archive
function macBundle(name, appBytes, tgzBytes) {
  const b = path.join(root, name);
  const app = path.join(b, "macos", `${product}.app`);
  const res = path.join(app, "Contents", "Resources", "backends", "ort-cpu");
  fs.mkdirSync(res, { recursive: true });
  if (appBytes) fs.writeFileSync(path.join(res, "libonnxruntime.dylib"), appBytes);
  if (tgzBytes !== undefined) {
    const stage = path.join(root, `${name}-stage`);
    const sres = path.join(stage, `${product}.app`, "Contents", "Resources", "backends", "ort-cpu");
    fs.mkdirSync(sres, { recursive: true });
    if (tgzBytes) fs.writeFileSync(path.join(sres, "libonnxruntime.dylib"), tgzBytes);
    // to stdout: GNU tar would read "C:/..." as a remote host name
    const r = tar(`-czf - "${product}.app" > "${toPosix(path.join(b, "macos", `${product}.app.tar.gz`))}"`, stage);
    ok(r.status === 0, `tar: ${r.stderr}`);
  }
  return b;
}

let r = run("macos-aarch64", macBundle("ok", good, good));
ok(r.code === 0 && /2 pinned file\(s\) present and matching/.test(r.out) && /app,updater/.test(r.out), `matching app + updater archive pass: ${r.out}`);
r = run("macos-aarch64", macBundle("signed-changed", Buffer.concat([good, Buffer.from("signature appended")]), good));
ok(r.code !== 0 && /MISMATCH: .*\.app backends\/ort-cpu\/libonnxruntime\.dylib/.test(r.out), `changed bytes in the .app fail: ${r.out}`);
r = run("macos-aarch64", macBundle("tgz-changed", good, Buffer.from("other")));
ok(r.code !== 0 && /MISMATCH: .*\.app\.tar\.gz/.test(r.out), `changed bytes in the updater archive fail: ${r.out}`);
r = run("macos-aarch64", macBundle("missing", null, good));
ok(r.code !== 0 && /MISSING: /.test(r.out), `a missing pack file fails: ${r.out}`);
r = run("macos-aarch64", macBundle("ok2", good, good), { RELEASE_PACK_REQUIRE: "app,dmg,updater" });
ok(r.code !== 0 && /MISSING FORM: no dmg/.test(r.out), `a required form that is absent fails: ${r.out}`);
r = run("macos-aarch64", macBundle("ok3", good, good), { RELEASE_PACK_REQUIRE: "app,updater" });
ok(r.code === 0, `required forms present pass: ${r.out}`);
const empty = path.join(root, "empty");
fs.mkdirSync(path.join(empty, "macos"), { recursive: true });
r = run("macos-aarch64", empty);
ok(r.code !== 0 && /no \.app/.test(r.out), `an empty bundle fails: ${r.out}`);
r = run("windows-x86_64", empty);
ok(r.code === 0 && /no runtime pack pinned|not unpacked here/.test(r.out), `targets without unpacked forms pass: ${r.out}`);

// Linux .deb (needs dpkg-deb)
if (has("dpkg-deb")) {
  for (const [name, bytes, pass] of [["deb-ok", good, true], ["deb-bad", Buffer.from("x"), false]]) {
    const pkg = path.join(root, `${name}-pkg`);
    const lib = path.join(pkg, "usr", "lib", product, "backends", "ort-cpu");
    fs.mkdirSync(lib, { recursive: true });
    fs.mkdirSync(path.join(pkg, "DEBIAN"), { recursive: true });
    fs.writeFileSync(path.join(pkg, "DEBIAN", "control"), "Package: vouch-test\nVersion: 0.2.0\nArchitecture: amd64\nMaintainer: t <t@example.com>\nDescription: t\n");
    fs.writeFileSync(path.join(lib, "libonnxruntime.so"), bytes);
    const b = path.join(root, name);
    fs.mkdirSync(path.join(b, "deb"), { recursive: true });
    const d = spawnSync(bash, ["-c", `dpkg-deb --build "${toPosix(pkg)}" "${toPosix(path.join(b, "deb", "t.deb"))}"`], { encoding: "utf8" });
    ok(d.status === 0, `dpkg-deb: ${d.stderr}`);
    r = run("linux-x86_64", b);
    ok((r.code === 0) === pass, `${name}: ${r.out}`);
  }
} else {
  console.log("(no dpkg-deb here: the .deb cases run on Linux)");
}

fs.rmSync(root, { recursive: true, force: true });
console.log(bad ? `${bad} failures` : "release pack check: self-test passes");
process.exit(bad ? 1 : 0);
