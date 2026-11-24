// Builds pool-core and pool-runner and places them where Tauri's `externalBin` expects them:
// src-tauri/binaries/<name>-<target-triple>[.exe]. Run by `tauri build` (beforeBuildCommand, --release)
// and `tauri dev` (beforeDevCommand). Release builds drop dev trust:
//   POOL_RELEASE=1 (the release-signing configuration; also POOL_RELEASE_FEATURES=prod)
//     ->  --no-default-features (+ candle / nvml) --features release
// With POOL_RELEASE=1 a dev-trust build fails to compile (pool-proto release guard).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { table, targetKey } from "./runtime-packs.mjs";

const release = process.argv.includes("--release");
const here = dirname(fileURLToPath(import.meta.url));
const clientDir = join(here, "..", "..");
const binDir = join(here, "..", "src-tauri", "binaries");

const triple =
  process.env.TAURI_ENV_TARGET_TRIPLE ||
  execFileSync("rustc", ["-vV"], { encoding: "utf8" }).match(/host: (\S+)/)[1];
const exe = triple.includes("windows") ? ".exe" : "";
const targetDir =
  process.env.CARGO_TARGET_DIR ||
  JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: clientDir, encoding: "utf8" }))
    .target_directory;

const prod = process.env.POOL_RELEASE_FEATURES === "prod" || process.env.POOL_RELEASE === "1";
if (prod) process.env.POOL_RELEASE = "1";
// Runners include the ONNX Runtime backend on every target with a pinned runtime pack (crates/pool-runner/packs.json:
// Windows x64 with DirectML, macOS arm64 and Linux x64 CPU-only). scripts/runtime-packs.mjs fetches the pack and checks
// every file against its pin; tauri.<os>.conf.json bundles it as resources.
const packs = table.packs.filter((p) => p.target === targetKey(triple));
const onnx = packs.some((p) => p.runtime === "onnxruntime");
const runnerFeats = prod
  ? ["--no-default-features", "--features", onnx ? "candle,onnx" : "candle"]
  : onnx ? ["--features", "onnx"] : [];
const builds = [
  ["pool-core", prod ? ["--no-default-features", "--features", "nvml,release"] : []],
  ["pool-runner", runnerFeats],
];
if (packs.length) execFileSync(process.execPath, [join(here, "runtime-packs.mjs"), "--target", targetKey(triple)], { stdio: "inherit" });
for (const [pkg, feats] of builds) {
  const args = ["build", "-p", pkg, "--bin", pkg, ...(release ? ["--release"] : []), ...feats];
  if (process.env.TAURI_ENV_TARGET_TRIPLE) args.push("--target", triple);
  console.log(`[sidecars] cargo ${args.join(" ")}`);
  execFileSync("cargo", args, { cwd: clientDir, stdio: "inherit" });
}
mkdirSync(binDir, { recursive: true });
const profile = release ? "release" : "debug";
for (const [pkg] of builds) {
  const candidates = [join(targetDir, triple, profile, pkg + exe), join(targetDir, profile, pkg + exe)];
  const src = candidates.find((p) => existsSync(p));
  if (!src) throw new Error(`built ${pkg} not found in ${candidates.join(", ")}`);
  const dst = join(binDir, `${pkg}-${triple}${exe}`);
  copyFileSync(src, dst);
  console.log(`[sidecars] ${src} -> ${dst}`);
}
