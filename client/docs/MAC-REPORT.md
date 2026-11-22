# Vouch Compute on macOS: build, test and benchmark report

Machine: MacBook Pro, Apple M3 Pro (5 performance + 6 efficiency cores), 18 GB, macOS 27.0 (26A428).
Date: 2026-11-20. Branches: `mac-support` in `vouch-client` and `vouch-backend` (draft PRs, not merged).
`vouch-web` and `vouch-admin` needed no changes.

**All benchmark figures were measured on battery with Low Power Mode on.** That throttles the CPU and GPU, so
treat absolute numbers as a floor and repeat them on AC power with Low Power Mode off before they count. The
ratios (CPU vs GPU) are more reliable than the absolute values.

## Toolchain

| Tool | Version |
|---|---|
| macOS / Xcode / clang | 27.0 (26A428) / Xcode 27.2 / Apple clang 21.0.0 |
| Homebrew | 7.0.15 |
| rustup / rustc (pinned in `client/rust-toolchain.toml`) | 1.29.3 / 1.98.1, target `aarch64-apple-darwin` |
| Node / npm | 22.23.5 / 10.9.9 (Homebrew `node@22`; the system default is Node 25) |
| Python | 3.10.22 (Homebrew `python@3.10`, as CI); 3.12 only for two benchmark extras, see §3 |
| protoc / cmake | libprotoc 36.2 / 4.5.1 |
| Docker / Compose | 29.9.3 / 5.7.1 (Docker Desktop updated itself from 29.4.0 during the run, see §7) |
| Tauri CLI / Playwright | 2.12.5 / 1.65.1 |
| Benchmark venv | torch 2.14.1, faster-whisper 1.2.1, CTranslate2 4.9.0, onnxruntime 1.23.2, mlx 0.32.4, mlx-whisper 0.4.3, sentence-transformers 6.3.0 |

## 1. Results by step

| Step | Result | Counts / duration |
|---|---|---|
| `cargo build --workspace` | pass | 1 m 16 s (cold) |
| `cargo test --workspace` | **failed at first, passes after fixes** | first run: 6 test binaries failed (2 bugs, §5); after the fixes and the rebase onto current `main`: **169 passed, 0 failed, 1 ignored** (the soak), 159 s |
| `cargo clippy --workspace --all-targets -D warnings` | pass | also with `-p pool-runner --features metal` |
| `cargo test -p pool-proto --no-default-features` | pass | 50 passed (39 + 11 fuzz-decoding), 33 s |
| macOS sandbox tests (new `tests/sandbox_macos.rs`) | pass | 3 tests (4 with `--features metal`), §4 |
| Bundle: `npx tauri build --target aarch64-apple-darwin` | pass (unsigned) | `.app` 16 MB, `.dmg` 6.9 MB, updater `.app.tar.gz` + `.sig`. DMG layout needs `CI=true`, see §7 |
| Launch `.app` | partly verified | shell + agent start, data dir `~/Library/Application Support/com.vouchcompute.app.dev` (0700; token, key, socket 0600), governor pauses on battery; pause/resume/benchmark work through the real control socket and a wrong token is refused. **Window, tray and benchmark screen not checked visually** (no Screen Recording permission for the terminal), see §6 |
| App JS tests (`node --test`) | pass | 2/2 |
| Metal acceleration | implemented behind `metal` (off by default) | §2 |
| Soak (`POOL_SOAK_SECS=600`) | pass | 600 s: **4,350 jobs**, 58 pre-empted, 55 reconnections; footprint 6.0 → 5.7 MB (peak 6.2), descriptors 16 → 12, no runner left behind |
| Trusted-node benchmark | done | §3 |
| engine `pytest` | **failed at first, passes after fix** | first run: 55 failed, 248 errors (greenlet, §5); after the fix **574 passed, 18 skipped**, 8 m 28 s |
| vault `pytest` | pass | **754 passed, 2 skipped**, 10 m 18 s (one earlier run had 40 errors when Docker Desktop restarted Postgres mid-run, §7) |
| `ruff check .` engine / vault | pass / pass | |
| web: `npm ci`, `gen:api`, `typecheck`, `lint` | pass | `gen:api` reproduces the committed files exactly |
| web: `npm test` (vitest) | pass | 166/166 in 14 files |
| web: `npm run build:mock` | pass | 21 s |
| web: Playwright `npm run test:e2e` | pass | **151 passed, 7 skipped**, 3.4 min. The config defines Chromium projects only (desktop + 360 px), so WebKit was not run |
| Live e2e (`scripts/dev.sh e2e`) | **blocked** | stack comes up (vault, engine, admins, 4 signed manifests); stops at the first device enrolment, §6 |

The soak's environment variable is `POOL_SOAK_SECS` (`TALLY_SOAK_SECS` in the brief is an old name and is ignored:
the first run silently used the 120 s default).

## 2. Apple GPU (Metal)

**Choice: candle with its `metal` feature**, over ONNX Runtime + CoreML and whisper.cpp + Metal:
- it is the same code path as the existing `cuda` feature (same models, bundles and backends);
- it uses only Apple's system Metal framework, inside the signed, sealed system volume. No third-party
  dylib is shipped or loaded, so there is nothing to pin by SHA-256;
- ONNX Runtime + CoreML would need a `libonnxruntime.dylib` pack pinned like the Windows DirectML pack, and in the
  trusted-node runs CoreML brought no speed-up for bge-small and fell back to the CPU for bge-m3 (§3);
- whisper.cpp needs a C++ build and covers transcription only.

Implementation (`vouch-client`, `mac-support`). **Apple silicon only**: on Intel Macs the `metal` build never uses
the GPU and every job runs on the CPU.
- `pool-runner --features metal`: Metal when a device is visible **and** a self-test matmul is correct, CPU
  otherwise; the backend actually used is reported (`candle-metal` / `candle-cpu`; the app shows `candle-metal` as
  "Graphics card (Metal)"). `candle-metal` is a new backend label for the change-request log. A pre-check through
  `MTLCreateSystemDefaultDevice` avoids a candle panic (an abort in release builds) when no device is visible.
- `SandboxConfig::gpu` adds exactly two rules; see "for security review" below.
- The agent grants it only to **candle embedding jobs**, only with "Use the GPU" on, and only when the runner
  itself reports a Metal build: at start the agent asks `pool-runner capabilities` inside the sandbox (5 s limit;
  any failure means no grant). pool-runner's `metal` feature is the one switch. Every other job runs with
  `POOL_ORT_FORCE_CPU=1` and without the rules.
- **Thermal guard:** macOS gives unprivileged processes no CPU/GPU temperature, so the governor's °C cap never
  applied on a Mac. The agent now reads `NSProcessInfo.thermalState` and pauses jobs at Serious or Critical
  pressure, resuming at Fair or below (a reading that vanishes while hot keeps the pause).
- **Not enabled in the bundle** (`scripts/sidecars.mjs` unchanged) because of the mixed results below.

Measured with the real runner **inside the sandbox**, median of 3 jobs after a warm-up, 2,048 texts / 60 s of speech
(`cargo test --release -p pool-runner --features metal --test gpu_metal -- --ignored`):

| Model | CPU | Metal | Speed-up | Output check |
|---|---|---|---|---|
| bge-base-en-v1.5 (2,048 texts, 85,173 tokens) | 61.2 s (1,392 tok/s) | 28.2 s (3,023 tok/s) | **2.2×** | min cosine 1.000000 |
| all-MiniLM-L6-v2 (same texts) | 9.1 s (9,326 tok/s) | 17.9 s (4,749 tok/s) | **0.5×** | min cosine 1.000000 |
| whisper-base (60 s of speech) | 8.2 s (7.4× real time) | 18.9 s (3.2× real time) | **0.4×** | transcripts identical |

Metal wins for the larger embedding model and loses for the small model and for Whisper. The likely cause is a
fixed per-job cost: every job is a fresh runner process, which sets up Metal and its kernels again, and Whisper's
decoder runs many tiny sequential kernels. So transcription always stays on the CPU, even in `metal` builds.
Before turning Metal on, measure on AC power without Low Power Mode, and consider a model-size threshold or keeping
the Metal kernels warm across jobs.

**For security review (do not merge without it): the GPU sandbox rules.** Measured one rule at a time; each is
required and nothing else is:
- `(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient"))`: the Apple GPU kernel driver.
  **This is the real added attack surface**: a driver bug reachable from it could be a sandbox escape. Safari's web
  content processes get the same client.
- `(allow mach-lookup (global-name "com.apple.MTLCompilerService"))`: Apple's shader compiler, an XPC service in its
  own sandbox; candle sends it only its own kernel source.
- `IOSurfaceRootUserClient` was tested and is **not** needed, so it stays denied.
- A test (`metal_gpu_jobs_keep_every_other_rule`) checks that with the GPU rules every other escape probe still fails,
  and that without them Metal is unreachable and the job falls back cleanly.

## 3. Trusted-node benchmark (this Mac as an owner node)

`vouch-backend/engine/tools/mac_bench.py` (new; `gpu_bench.py` needs nvidia-smi and CUDA). Conservative figures
(long texts, batch-1 Whisper on 120 s of audio):

| Model | Worker path today | Best other runtime on this Mac | Peak memory |
|---|---|---|---|
| whisper-large-v3-turbo | CTranslate2 int8, CPU: **2.89 audio-s/s** (3.04 in a repeat) | mlx-whisper (Metal): **21.4 audio-s/s** (7.4×), same transcript | CT2 RSS 1.4 GB; MLX RSS 0.9 GB + 2.4 GB GPU |
| bge-small-en-v1.5 (catalog int8 ONNX) | ONNX CPU: **5,137 tok/s** (5,776 short texts) | sentence-transformers on MPS: **33,201 tok/s** (6.5×) | ONNX RSS 2.4 GB; MPS RSS 0.6 GB + 2.2 GB GPU |
| bge-m3 (catalog fp32 ONNX) | ONNX CPU: **480 tok/s** (535 short) | MPS: **3,664 tok/s** (7.6×) | ONNX RSS 2.4 GB; MPS RSS 1.7 GB + 3.1 GB GPU |
| (ONNX Runtime CoreML provider) | | no gain for bge-small; bge-m3 fell back to the CPU provider | |

Power was not measured: `powermetrics` needs sudo.

`ENGINE_OPENROUTER_TRUSTED_UPS` takes the **raw measured throughput**; engine applies the ×0.5 safety factor
(`openrouter_capacity_safety`) and the split over the models served:

```
# what the reference worker can run today (CT2 int8 CPU + ONNX CPU)
ENGINE_OPENROUTER_TRUSTED_UPS="whisper-large-v3-turbo=2.89,bge-small-en-v1.5=5137,bge-m3=480"
#   declared per minute (0.5 x / 3 models x 60): 28 audio-s, 51,000 and 4,800 tokens
# if the worker gained MLX (whisper) and MPS (embeddings) backends
ENGINE_OPENROUTER_TRUSTED_UPS="whisper-large-v3-turbo=21.4,bge-small-en-v1.5=33201,bge-m3=3664"
#   declared per minute: 210 audio-s, 330,000 and 36,000 tokens
```

The M11 table estimated ~4 audio-s/s, ~8k and ~700 tokens/s for this Mac. The measured worker path is somewhat
lower (in Low Power Mode). Notes:
- **The reference worker cannot serve these models on a Mac today.** `--device cpu` uses the small CPU models
  (whisper-tiny, bge-small); only `--device cuda` uses `GpuBackend` with the catalog weights. Serving
  whisper-large-v3-turbo / bge-m3 from a Mac needs a worker option for `GpuBackend("cpu")`, or, better, MLX/MPS
  backends (about 7× faster here).
- Every download in `mac_bench.py` is pinned to the commit that was measured, and no pickle weights are fetched or
  loaded (PyTorch models load with `use_safetensors=True`). MLX/MPS figures use safetensors weights, not the catalog
  ONNX/CT2 files; adopting them means adding those formats to the catalog and reviewing them.
- **bge-m3 has no publisher safetensors.** BAAI publishes its PyTorch weights only as a pickle (`pytorch_model.bin`);
  the MPS figure uses the safetensors conversion in `refs/pr/130` (Hugging Face's conversion bot, not merged by
  BAAI). An earlier bge-m3 MPS run in this report had loaded the pickle; it was re-measured with safetensors only.
- The worker's own `fetch_weights` (`refworker/gpu.py`) downloads the catalog repos without a pinned revision.
  That is outside this PR, but worth pinning in the catalog.
- scipy's Python 3.10 wheel (1.15.3, the last release for 3.10) **does not load on macOS 27** (dyld rejects its
  `__thread_bss` section). sentence-transformers and mlx-whisper import it, so those two extras ran from a Python
  3.12 venv. The worker path does not use scipy.

## 4. Sandbox findings (macOS `sandbox-exec` runner)

Verified by tests, each probe against an unsandboxed control run (`crates/pool-runner/tests/sandbox_macos.rs`, plus
the existing `sandbox.rs` and pool-core `sandbox_isolation.rs`, which now run on macOS):

| A job cannot… | Result |
|---|---|
| read or list home, `~/Documents`, `~/Desktop`, `~/Downloads`, `~/Library/{Keychains,Mail,Messages}`, `/Users/Shared`, `/Volumes`, a secret file in home | blocked |
| write to home, `/tmp`, `$TMPDIR`, **its own model dir**, its temp dir | blocked |
| reach the network: loopback TCP, public internet, DNS; a Unix socket | blocked |
| connect to the agent's control socket, read its token, device key or state | blocked |
| start a child process; signal another process | blocked |
| look up 15 sensitive Mach services (pasteboard, keychain/securityd, window server, TCC, Launch Services, audio, camera, mDNSResponder, nsurlsessiond, …) | blocked |
| `stat` user files (existence, size, times) | **was possible, fixed** |
| exceed the memory cap | **had no cap, now a soft cap** (watchdog) |

Gaps, rated:

| Gap | Rating | Status |
|---|---|---|
| **A job can read the arguments and environment variables of every process of the same user** (`KERN_PROCARGS2`). `sandbox-exec` does not mediate it: denying `sysctl-read` by name or `process-info*` changes nothing. Environment variables often hold tokens and API keys. The job cannot send them over the network, but a compromised runner could hide them in a job result, which the buyer receives. Windows (LPAC) and Linux (Landlock blocks `/proc/<pid>/environ`) do not have this gap. | **High** | **Open.** Asserted as a known gap (`known_gap_same_user_process_environment_is_readable`), so the test flips the day it is fixed. Needs the runner under a different user (a privileged helper) or the signed App Sandbox helper. Whether App Sandbox blocks it could not be verified locally: App Sandbox will not start for an ad-hoc-signed bare executable. |
| No separately signed App Sandbox runner helper; `sandbox-exec` is a deprecated API (still works on macOS 27) | Medium | Open, needs the Apple Developer account |
| Device key is a software key on macOS (no Secure Enclave until the helper is signed) | Medium | Open, as documented in `identity/mod.rs` |
| No hard CPU cap (only `nice 10`); same as Linux | Medium | Open. Mitigated by the idle-only governor and pre-emption. A `PRIO_DARWIN_BG` policy would hard-throttle but confines the job to the efficiency cores |
| Memory cap is a 50 ms footprint watchdog: a job can overshoot by what it allocates within one period, and it is killed instead of failing an allocation | Low | **New** (there was no cap at all before) |
| GPU rules (§2), when enabled | Medium (driver attack surface) | Off by default; needs security review |
| The profile now allows reading the listing of `/` (top-level names only), required by dyld on macOS 27 | Low | New, documented |
| `file-read-metadata` and `sysctl-read` were global | Low–Medium | **Fixed**: allow-listed (metadata: the runner's paths and their parents; sysctl: the `hw.` and `machdep.cpu.` prefixes and the exact names `kern.osversion`, `kern.osrelease`, `kern.ostype`, `kern.osproductversion`, `kern.version`, `kern.argmax`, `kern.maxfilesperproc`, `kern.secure_kernel`, `sysctl.proc_cputype`, `sysctl.proc_native`, `vm.pagesize`) |

## 5. Bugs found and fixed

| Bug | Where | Branch |
|---|---|---|
| **Plain `cargo build/test --workspace` replaced `target/*/pool-runner` and `pool-core` with empty sidecar placeholders** (tauri-build copies `externalBin` sidecars into the target dir). Depending on build order, every sandboxed test then started a 0-byte runner. Affects every OS; CI only avoided it because clippy ran the build script first. | `pool-app/src-tauri/build.rs` | client `mac-support` |
| **Every sandboxed job aborted in dyld on macOS 27** (dyld reads `/` while locating the shared cache) | `pool-sandbox/src/unix.rs` | client |
| Global `file-read-metadata` / `sysctl-read`; no memory cap on macOS | `pool-sandbox` | client |
| Review follow-ups: the app shows `candle-metal` as "Graphics card (Metal)" (with a render test); the Metal benchmark asserts identical transcripts; the memory watchdog survives a poisoned lock; Metal is Apple silicon only | `pool-app/ui`, `pool-runner`, `pool-sandbox` | client |
| Soak measured 0 MB / 0 descriptors on macOS (it read `/proc`), so its leak checks passed without measuring | `pool-core/tests/soak.rs` | client |
| Metal backend + tests + benchmark (new feature, off by default) | `pool-runner`, `pool-core`, `pool-sandbox` | client |
| **engine had no `greenlet` on macOS arm64** (SQLAlchemy's marker lists `aarch64`, not `arm64`); every async DB connection failed (248 errors) | `engine/pyproject.toml` → `sqlalchemy[asyncio]` | backend `mac-support` |
| **SSRF guard: hosts were checked in their Unicode form** (review): a non-ASCII host is now mapped with IDNA/UTS-46 and punycode before every check, so `０１７７．0．0．1`, `0177.0.0.1。`, `metadata.google。internal` and `ｌｏｃａｌｈｏｓｔ` are refused like their ASCII forms; a malformed redirect target is a clean denial instead of a 500 (timeouts keep their type so webhooks still retry) | `engine/src/engine/egress.py` | backend |
| **SSRF guard depended on the OS's address parser**: `0177.0.0.1` is 127.0.0.1 on glibc but 177.0.0.1 on macOS. Not exploitable (the connection is pinned to the vetted address), but non-canonical IPv4 hosts are now refused before resolution on every OS | `engine/src/engine/egress.py` | backend |
| Trusted-node benchmark for Apple silicon | `engine/tools/mac_bench.py` | backend |
| e2e harness: simulated devices bind random `127.0.x.y` source addresses, which macOS does not have | `tests/e2e` (fixed loopback pool on macOS + preflight message) | backend |

## 6. Live e2e and the app UI: what is blocked

- **Live e2e:** the stack comes up on macOS: Postgres/Redis, vault (3 listeners + worker), engine, 3 owner admins,
  4 manifests signed and listed. The first device enrolment then fails because macOS has only `127.0.0.1` on
  `lo0` (`Errno 49`). The harness now uses a fixed pool on macOS and stops early with the command to add it.
  To finish step 5, run once per boot, in Terminal:

  ```
  for i in $(seq 2 33); do sudo ifconfig lo0 alias 127.0.1.$i up; done
  ./scripts/dev.sh e2e        # in the integration workspace (README "Integration workspace")
  ```

  The e2e ports (engine :8000-8002, vault :8100-8102, web :3000, web-admin :3201) must be free.
- **App UI:** check by hand in about 2 minutes: open
  `client/target/aarch64-apple-darwin/release/bundle/macos/Vouch Compute.app` (unsigned: right-click → Open the first
  time). Confirm the window renders, the menu-bar tray icon and its menu work, Pause/Resume change the status, and
  the benchmark screen starts (on battery the governor holds jobs; plug in to see it run).

## 7. Environment notes

- Docker Desktop updated itself (29.4.0 → 29.9.3) during the first vault run and restarted the containers. That
  run had 40 connection errors; the rerun was clean. Consider turning off automatic updates on a test machine.
- DMG bundling drives Finder through AppleScript to lay out the window. It timed out waiting on the Automation
  permission prompt ("… wants to control Finder"). `CI=true npx tauri build` skips that step.
- Permission prompts seen: Finder Automation (DMG layout). Screen Recording was not granted, so there were no
  screenshots. The unsigned app needs right-click → Open (Gatekeeper).
- Low Power Mode was on and the Mac was on battery during all benchmarks.

## 7b. Follow-ups done in the second PR (`mac-metal-followups`)

- macOS thermal guard (above), with a governor property test that it never runs under Serious/Critical pressure.
- The two `metal` switches are now one (the runner's), tied at run time through `pool-runner capabilities`.
- CI: on manual runs the macOS job also runs clippy and the macOS sandbox tests with the runner's `metal` feature
  (the GPU half skips itself on a runner VM without a usable Metal device), and every run now executes the app's
  `render.test.js` (it was not run in CI before).
- Still open before Metal is enabled in release builds: backend-aware fraud benchmarks, closing the
  `KERN_PROCARGS2` gap (signed App Sandbox helper), and an owner-approved GPU re-benchmark.

## 8. What the owner needs to do

1. **Apple Developer account**: Developer ID signing and notarization of the app, and the separately signed App
   Sandbox runner helper (also the path to closing the `KERN_PROCARGS2` gap and to a Secure Enclave device key).
2. **Security review** of the sandbox changes: the allow-listed metadata/sysctl reads, the `/` listing rule,
   the memory watchdog, and **especially the Metal GPU rules** before `metal` is ever enabled.
3. Decide on the **High** `KERN_PROCARGS2` gap (privileged helper with a separate user, or App Sandbox once
   signing exists).
4. Add the `lo0` aliases and run the live e2e (§6).
5. Re-run the GPU and trusted-node benchmarks on AC power with Low Power Mode off; decide whether Metal ships.
6. Check the app UI by hand (§6).
7. Review and merge the two draft PRs.
