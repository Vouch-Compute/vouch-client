// Fetch the pinned GPU backend pack for the Windows installer into src-tauri/backends/ort-directml/.
// The files and their SHA-256 come from crates/pool-runner/src/accel.rs (`PINNED`), the single source of truth that
// the agent and the runner also check at every job start. Sources:
//   Microsoft.ML.OnnxRuntime.DirectML 1.22.0  runtimes/win-x64/native/onnxruntime.dll   (nuget.org)
//   Microsoft.AI.DirectML 1.15.4              bin/x64-win/DirectML.dll                  (nuget.org)
//   Visual C++ runtime 14.51.36247.0          vcruntime140.dll, vcruntime140_1.dll, msvcp140.dll
//                                             (Microsoft's redistributable files, vendored in pool-app/vendor/vcruntime/)
// Anything that does not match its pin fails the build. Files already present and matching are kept; any other file
// (including the empty placeholders a plain `cargo build` writes) is replaced.
// `--check`: only verify, never fetch; exits non-zero if any pinned file is missing, a placeholder or mismatched.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, copyFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const accel = readFileSync(join(here, "..", "..", "crates", "pool-runner", "src", "accel.rs"), "utf8");
// line-ending agnostic: a CRLF checkout must find the same pins
const lf = accel.replace(/\r\n/g, "\n");
const block = lf.slice(lf.indexOf("#[cfg(windows)]\npub const PINNED"), lf.indexOf("];", lf.indexOf("pub const PINNED")));
const pins = [...block.matchAll(/\("([^"]+)", "([0-9a-f]{64})"\)/g)].map((m) => ({ name: m[1], sha256: m[2] }));
if (pins.length === 0) throw new Error("no pins found in accel.rs");

const VENDORED = new Set(["vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"]);
const SOURCES = {
  "DirectML.dll": { id: "microsoft.ai.directml", version: "1.15.4", path: "bin/x64-win/DirectML.dll" },
  "onnxruntime.dll": { id: "microsoft.ml.onnxruntime.directml", version: "1.22.0", path: "runtimes/win-x64/native/onnxruntime.dll" },
};

const out = join(here, "..", "src-tauri", "backends", "ort-directml");
mkdirSync(out, { recursive: true });
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

if (process.argv.includes("--check")) {
  const bad = pins.filter(({ name, sha256 }) => !existsSync(join(out, name)) || sha(join(out, name)) !== sha256);
  for (const { name } of bad) console.error(`[gpu-pack] ${name}: missing, placeholder or not matching its pin`);
  if (bad.length) process.exit(1);
  console.log(`[gpu-pack] check: all ${pins.length} files match their pins`);
  process.exit(0);
}

for (const { name, sha256 } of pins) {
  const dst = join(out, name);
  if (existsSync(dst) && sha(dst) === sha256) {
    console.log(`[gpu-pack] ${name} ok (pinned)`);
    continue;
  }
  if (VENDORED.has(name)) {
    const v = join(here, "..", "vendor", "vcruntime", name);
    if (!existsSync(v) || sha(v) !== sha256) throw new Error(`[gpu-pack] vendored ${name} is missing or does not match its pin: refused`);
    copyFileSync(v, dst);
    console.log(`[gpu-pack] ${name} ok (vendored, pinned)`);
    continue;
  }
  const src = SOURCES[name];
  if (!src) throw new Error(`no download source for pinned file ${name}`);
  const work = mkdtempSync(join(tmpdir(), "gpu-pack-"));
  const pkg = join(work, "pkg.zip");
  const url = `https://api.nuget.org/v3-flatcontainer/${src.id}/${src.version}/${src.id}.${src.version}.nupkg`;
  console.log(`[gpu-pack] downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  writeFileSync(pkg, Buffer.from(await res.arrayBuffer()));
  // bsdtar (Windows 10+ tar.exe, libarchive elsewhere) reads zip archives
  // on Windows the system bsdtar explicitly: a GNU tar earlier on PATH (Git Bash) reads "C:" as a remote host
  const tar = process.platform === "win32" ? join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-xf", pkg, "-C", work, src.path], { stdio: "inherit" });
  const got = join(work, ...src.path.split("/"));
  const h = sha(got);
  if (h !== sha256) {
    rmSync(work, { recursive: true, force: true });
    throw new Error(`[gpu-pack] ${name} from ${url} has SHA-256 ${h}, pinned ${sha256}: refused`);
  }
  copyFileSync(got, dst);
  rmSync(work, { recursive: true, force: true });
  console.log(`[gpu-pack] ${name} ok (downloaded, pinned)`);
}
