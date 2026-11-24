// Runtime packs: what each desktop bundle ships matches the pin table (crates/pool-runner/packs.json), and the agent
// looks for it where the bundler puts it. Run: node pool-app/tests/runtime-packs.test.js
// * tauri.<os>.conf.json bundles exactly the pinned files of that OS's target, at backends/<dir>/<name>;
// * the Linux resource dir is named after `productName`, which pool-core's PRODUCT_NAME must equal;
// * sidecars.mjs and runtime-packs.mjs agree on the target keys.
const fs = require("node:fs");
const path = require("node:path");

const client = path.resolve(__dirname, "..", "..");
const tauri = path.join(client, "pool-app", "src-tauri");
const table = JSON.parse(fs.readFileSync(path.join(client, "crates", "pool-runner", "packs.json"), "utf8"));
const conf = JSON.parse(fs.readFileSync(path.join(tauri, "tauri.conf.json"), "utf8"));

let bad = 0;
const ok = (c, m) => { if (!c) { bad++; console.log("FAIL", m); } };

const desktop = { windows: "windows-x86_64", macos: "macos-aarch64", linux: "linux-x86_64" };
for (const [os, target] of Object.entries(desktop)) {
  const file = path.join(tauri, `tauri.${os}.conf.json`);
  const want = table.packs.filter((p) => p.target === target).flatMap((p) => p.files.map((f) => `backends/${p.dir}/${f.name}`)).sort();
  ok(want.length > 0, `${target}: no runtime pack pinned`);
  ok(fs.existsSync(file), `${file} missing`);
  if (!fs.existsSync(file)) continue;
  const res = JSON.parse(fs.readFileSync(file, "utf8")).bundle?.resources || {};
  const got = Object.keys(res).sort();
  ok(JSON.stringify(got) === JSON.stringify(want), `${os}: bundled ${JSON.stringify(got)}, pinned ${JSON.stringify(want)}`);
  for (const [src, dst] of Object.entries(res)) ok(src === dst, `${os}: ${src} is bundled as ${dst}`);
}
// no pack file for one OS leaks into another OS's bundle (e.g. the .so in the macOS app)
ok(!Object.keys(conf.bundle.resources || {}).some((k) => k.startsWith("backends/")), "tauri.conf.json bundles pack files for every OS");

const configRs = fs.readFileSync(path.join(client, "crates", "pool-core", "src", "config.rs"), "utf8");
const m = configRs.match(/pub const PRODUCT_NAME: &str = "([^"]+)";/);
ok(m && m[1] === conf.productName, `pool-core PRODUCT_NAME ${m && m[1]} differs from productName ${conf.productName}`);

// pins are lower-case hex SHA-256 and every file has exactly one source
for (const p of table.packs) {
  ok(p.files.some((f) => f.name === p.library), `${p.target}: library ${p.library} not among the files`);
  for (const f of p.files) {
    ok(/^[0-9a-f]{64}$/.test(f.sha256), `${p.target}/${f.name}: bad pin`);
    ok(!!f.nuget !== !!f.vendored, `${p.target}/${f.name}: needs exactly one source (nuget or vendored)`);
    if (f.nuget) ok(/^[a-z0-9.]+$/.test(f.nuget.id) && /^\d+\.\d+\.\d+$/.test(f.nuget.version), `${p.target}/${f.name}: bad nuget source`);
  }
}

import(require("node:url").pathToFileURL(path.join(client, "pool-app", "scripts", "runtime-packs.mjs")).href).then((m) => {
  ok(m.targetKey("x86_64-pc-windows-msvc") === "windows-x86_64", "windows triple");
  ok(m.targetKey("aarch64-apple-darwin") === "macos-aarch64", "macOS triple");
  ok(m.targetKey("x86_64-unknown-linux-gnu") === "linux-x86_64", "Linux triple");
  if (bad) { console.log(`${bad} failure(s)`); process.exit(1); }
  console.log("runtime packs: bundle configs, pins and paths agree");
});
