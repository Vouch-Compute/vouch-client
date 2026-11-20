# Vouch Compute desktop app

Vouch Compute lets you share your computer's idle time for small AI jobs (speech-to-text and text embeddings) and
get paid in USDC for the work. This repository is the desktop app for Windows, macOS and Linux.

- **Runs only when you're away.** Jobs start when the computer is idle and stop as soon as you come back. You set
  limits for CPU, GPU, temperature and battery.
- **Sandboxed.** Every job runs in a separate, locked-down process with no network access and no access to your
  files.
- **Verified work.** The server checks and meters every job. You are paid for verified work only, and earnings are
  always shown as estimates.
- **Signed updates.** The app installs only updates signed with the project's release keys, and never an older
  version.

## How it is built

| Path | What |
|---|---|
| `client/crates/pool-core` | the background agent: device identity, connection to the server, job scheduling, idle and thermal governor |
| `client/crates/pool-runner` | the per-job worker that runs inside the sandbox (speech-to-text, embeddings; CPU and GPU backends) |
| `client/crates/pool-sandbox` | OS sandboxes: AppContainer (Windows), namespaces + Landlock + seccomp (Linux), a deny-by-default sandbox profile (macOS) |
| `client/crates/pool-proto` | the wire protocol and the signed objects the app verifies |
| `client/pool-app` | the Tauri 2 desktop shell and its UI |
| `client/fuzz` | fuzz targets for the decoders and the update-signature check |
| `proto/node.proto` | the protocol definition the app is generated from |

## Build from source

Requirements:
- Rust 1.98.1 (pinned in `client/rust-toolchain.toml`; `rustup` installs it automatically);
- Node.js 22 (for the Tauri CLI);
- the Tauri 2 system prerequisites for your OS (https://tauri.app/start/prerequisites/):
  - Windows: Visual Studio 2022 Build Tools ("Desktop development with C++") and WebView2 (preinstalled on Windows 11);
  - Linux: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libgtk-3-dev libssl-dev patchelf cmake clang libclang-dev`;
  - macOS: Xcode Command Line Tools.

Test and lint:

```bash
cd client
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the app in development mode:

```bash
cd client/pool-app
npm ci
npx tauri dev
```

Build an installer (unsigned development build):

```bash
cd client/pool-app
npm ci
npx tauri signer generate -w ../dev-keys/updater-1.key       # once; your own development update key
# set TAURI_SIGNING_PRIVATE_KEY to the contents of that file (empty password), then:
npx tauri build                                              # bundles in client/target/release/bundle/
```

On Windows, the installer bundles the GPU backend pack (ONNX Runtime with DirectML from Microsoft's NuGet packages,
plus the Visual C++ runtime vendored in `client/pool-app/vendor/vcruntime/`). Fetch it before building an installer:

```bash
cd client/pool-app
node scripts/gpu-pack.mjs          # downloads/copies the pack, checks every file against its SHA-256 pin
node scripts/gpu-pack.mjs --check  # verify only
```

The pins live in `client/crates/pool-runner/src/accel.rs`; a mismatch fails the script. A plain `cargo build`,
`cargo test` or `cargo clippy` on a fresh checkout writes empty placeholder files instead, so it works without the
pack (GPU jobs are then refused at job start, because a placeholder never matches its pin). A release build
(`POOL_RELEASE=1`) refuses to compile unless every pack file matches its pin.

Development builds use a separate update channel and separate keys. They cannot install release updates, and release
builds refuse development keys: a release build with development trust enabled fails to compile, and CI checks the
release binaries for development markers before anything is signed.

## Contributing

Pull requests are welcome once the repository is public. Please run `cargo clippy` and `cargo test` before opening one.
Changes to the protocol, the sandbox, the device key or the updater get an extra security review.

## Security

Please report vulnerabilities privately to **security@vouchcompute.com**, not in a public issue. See `SECURITY.md`.

## License

To be decided before the repository is made public.
