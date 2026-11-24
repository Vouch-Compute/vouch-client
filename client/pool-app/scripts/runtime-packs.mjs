// Fetch the pinned native runtime packs for one target into src-tauri/backends/<dir>/ (bundled as resources by
// tauri.<os>.conf.json). The packs, their files, SHA-256 pins and sources come from crates/pool-runner/packs.json,
// the single source of truth that the agent and the runner also check at every job start.
//   node scripts/runtime-packs.mjs [--target <os>-<arch>] [--check]
// Target: `windows-x86_64`, `macos-aarch64`, `linux-x86_64`, ... (Rust's std::env::consts spelling); default: the
// target of TAURI_ENV_TARGET_TRIPLE when set, else this machine. A target without packs is not an error.
// Sources: `nuget` = the official nuget.org package (id, version, path inside it); `vendored` = a file in this repo.
// Anything that does not match its pin fails the build. Files already present and matching are kept; any other file
// (including the empty placeholders a plain `cargo build` writes) is replaced.
// `--check`: only verify, never fetch; exits non-zero if any pinned file is missing, a placeholder or mismatched.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, copyFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const clientDir = join(here, "..", "..");
export const table = JSON.parse(readFileSync(join(clientDir, "crates", "pool-runner", "packs.json"), "utf8"));

/** `<os>-<arch>` for a Rust target triple, or for this machine. */
export function targetKey(triple) {
  if (triple) {
    const arch = triple.split("-")[0];
    const os = triple.includes("windows") ? "windows" : triple.includes("apple-darwin") ? "macos" : triple.includes("linux") ? "linux" : "unknown";
    return `${os}-${arch}`;
  }
  const os = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform] || process.platform;
  const arch = { x64: "x86_64", arm64: "aarch64" }[process.arch] || process.arch;
  return `${os}-${arch}`;
}

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const packDir = (pack) => join(here, "..", "src-tauri", "backends", pack.dir);

function unzip(pkg, work, path) {
  // bsdtar reads zip archives (Windows 10+ tar.exe, macOS tar); on Windows the system one explicitly, because a GNU
  // tar earlier on PATH (Git Bash) reads "C:" as a remote host. GNU tar (Linux) cannot read zip: unzip there.
  if (process.platform === "linux") {
    execFileSync("unzip", ["-q", "-o", pkg, path, "-d", work], { stdio: "inherit" });
    return;
  }
  const tar = process.platform === "win32" ? join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-xf", pkg, "-C", work, path], { stdio: "inherit" });
}

async function fetchNuget(src, work) {
  const pkg = join(work, `${src.id}.${src.version}.zip`);
  if (!existsSync(pkg)) {
    const url = `https://api.nuget.org/v3-flatcontainer/${src.id}/${src.version}/${src.id}.${src.version}.nupkg`;
    console.log(`[runtime-packs] downloading ${url}`);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    writeFileSync(pkg, Buffer.from(await res.arrayBuffer()));
  }
  unzip(pkg, work, src.path);
  return join(work, ...src.path.split("/"));
}

async function main() {
  const args = process.argv.slice(2);
  const ti = args.indexOf("--target");
  const target = ti >= 0 ? args[ti + 1] : targetKey(process.env.TAURI_ENV_TARGET_TRIPLE);
  const packs = table.packs.filter((p) => p.target === target);
  if (packs.length === 0) {
    console.log(`[runtime-packs] no runtime pack is pinned for ${target}`);
    return;
  }
  if (args.includes("--check")) {
    let bad = 0;
    for (const pack of packs) {
      for (const f of pack.files) {
        const p = join(packDir(pack), f.name);
        if (!existsSync(p) || sha(p) !== f.sha256) {
          console.error(`[runtime-packs] ${pack.dir}/${f.name}: missing, placeholder or not matching its pin`);
          bad++;
        }
      }
    }
    if (bad) process.exit(1);
    console.log(`[runtime-packs] check: every file of ${packs.map((p) => `${p.runtime} (${p.dir})`).join(", ")} for ${target} matches its pin`);
    return;
  }
  // one work dir for the run: a package shared by several files is downloaded once
  const work = mkdtempSync(join(tmpdir(), "runtime-packs-"));
  try {
    for (const pack of packs) {
      const out = packDir(pack);
      mkdirSync(out, { recursive: true });
      for (const f of pack.files) {
        const dst = join(out, f.name);
        if (existsSync(dst) && sha(dst) === f.sha256) {
          console.log(`[runtime-packs] ${pack.dir}/${f.name} ok (pinned)`);
          continue;
        }
        let got;
        if (f.vendored) {
          got = join(clientDir, ...f.vendored.split("/"));
          if (!existsSync(got)) throw new Error(`[runtime-packs] vendored ${f.vendored} is missing: refused`);
        } else if (f.nuget) {
          got = await fetchNuget(f.nuget, work);
        } else {
          throw new Error(`[runtime-packs] no source for pinned file ${pack.dir}/${f.name}`);
        }
        const h = sha(got);
        if (h !== f.sha256) throw new Error(`[runtime-packs] ${pack.dir}/${f.name} has SHA-256 ${h}, pinned ${f.sha256}: refused`);
        copyFileSync(got, dst);
        console.log(`[runtime-packs] ${pack.dir}/${f.name} ok (${f.vendored ? "vendored" : "downloaded"}, pinned)`);
      }
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
