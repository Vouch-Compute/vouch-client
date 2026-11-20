// Assemble a release set for the download host from the bundles the release workflow produced.
//
//   node ci/release-manifest.mjs <bundles dir> <out dir> <version> <base url>
//
// <bundles dir> holds the per-platform artifacts (searched recursively). The script copies the installers under
// stable, space-free names into <out dir>, and writes:
//   latest.json  the updater manifest (Tauri static format): per platform the download URL and the minisign
//                signature (the bundler's .sig file), checked by the app against the release public keys;
//   SHA256SUMS   SHA-256 of every published file (sign it afterwards; see the release workflow).
// <base url> is the folder the files are served from, e.g. https://downloads.vouchcompute.com/desktop/0.2.0
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const [dir, out, version, base] = process.argv.slice(2);
if (!dir || !out || !version || !base) {
  console.error("usage: release-manifest.mjs <bundles dir> <out dir> <version> <base url>");
  process.exit(2);
}
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`version must be x.y.z: ${version}`);
if (!base.startsWith("https://")) throw new Error("base url must be https");

const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    statSync(p).isDirectory() ? walk(p) : files.push(p);
  }
})(dir);
const find = (re) => {
  const hits = files.filter((f) => re.test(basename(f)));
  if (hits.length > 1) throw new Error(`more than one file matches ${re}: ${hits.join(", ")}`);
  return hits[0];
};

// [published name, source pattern, updater platform key (or null: download only)]
const v = version.replace(/\./g, "\\.");
const PLAN = [
  [`VouchCompute-${version}-windows-x64-setup.exe`, new RegExp(`_${v}_x64-setup\\.exe$`), "windows-x86_64"],
  [`VouchCompute-${version}-macos-arm64.dmg`, new RegExp(`_${v}_aarch64\\.dmg$`), null],
  [`VouchCompute-${version}-macos-arm64.app.tar.gz`, /\.app\.tar\.gz$/, "darwin-aarch64"],
  [`VouchCompute-${version}-linux-x86_64.AppImage`, new RegExp(`_${v}_amd64\\.AppImage$`), "linux-x86_64"],
  [`VouchCompute-${version}-linux-amd64.deb`, new RegExp(`_${v}_amd64\\.deb$`), null],
];

mkdirSync(out, { recursive: true });
const platforms = {};
const sums = [];
for (const [name, re, platform] of PLAN) {
  const src = find(re);
  if (!src) {
    console.warn(`[release-manifest] no file for ${name} (platform not built in this run)`);
    continue;
  }
  copyFileSync(src, join(out, name));
  sums.push(`${createHash("sha256").update(readFileSync(src)).digest("hex")}  ${name}`);
  if (platform) {
    const sig = files.find((f) => f === `${src}.sig`);
    if (!sig) throw new Error(`no updater signature for ${src}`);
    platforms[platform] = { signature: readFileSync(sig, "utf8").trim(), url: `${base}/${name}` };
  }
  console.log(`[release-manifest] ${name}`);
}
if (Object.keys(platforms).length === 0) throw new Error("no updater platform found");
const manifest = { version, notes: `Vouch Compute ${version}`, pub_date: new Date().toISOString(), platforms };
writeFileSync(join(out, "latest.json"), JSON.stringify(manifest, null, 2) + "\n");
sums.push(`${createHash("sha256").update(readFileSync(join(out, "latest.json"))).digest("hex")}  latest.json`);
writeFileSync(join(out, "SHA256SUMS"), sums.join("\n") + "\n");
console.log(`[release-manifest] latest.json (${Object.keys(platforms).join(", ")}), SHA256SUMS`);
