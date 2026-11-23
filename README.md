<p align="center">
  <img src=".github/assets/logo-light.svg#gh-light-mode-only" height="64" alt="Vouch Compute">
  <img src=".github/assets/logo-dark.svg#gh-dark-mode-only" height="64" alt="Vouch Compute">
</p>

<h3 align="center">Earn US dollars by lending your idle PC to verified AI jobs</h3>

<p align="center">
  <a href="https://github.com/MetehanAydemir/vouch-client/actions/workflows/client.yml"><img src="https://github.com/MetehanAydemir/vouch-client/actions/workflows/client.yml/badge.svg" alt="CI"></a>
  <a href="https://www.vouchcompute.com"><img src="https://img.shields.io/badge/website-vouchcompute.com-2b55c9" alt="Website"></a>
  <a href="https://www.vouchcompute.com/download"><img src="https://img.shields.io/badge/download-first%20release%20soon-0e7353" alt="Download"></a>
  <img src="https://img.shields.io/badge/macOS-coming%20soon-55607a" alt="macOS coming soon">
  <img src="https://img.shields.io/badge/license-not%20yet%20released-55607a" alt="License: not yet released">
</p>

Vouch Compute is a desktop app that runs small AI jobs (speech-to-text and text embeddings) on your computer while
you're away, and pays you in US dollars for every job that passes verification. It runs only when the machine is idle,
inside a locked-down sandbox, and it shows earnings as honest estimates, never as promises.

<p align="center">
  <img src=".github/assets/dashboard-light.png#gh-light-mode-only" width="860" alt="The contributor dashboard on vouchcompute.com">
  <img src=".github/assets/dashboard-dark.png#gh-dark-mode-only" width="860" alt="The contributor dashboard on vouchcompute.com">
  <br><sub>The contributor dashboard at vouchcompute.com/app, which the app pairs with (development build, sample data).</sub>
</p>

## Table of contents

- [Download](#-download)
- [First launch on macOS](#-first-launch-on-macos)
- [Features](#-features)
- [What the sandbox protects](#-what-the-sandbox-protects)
- [System requirements](#-system-requirements)
- [Build from source](#-build-from-source)
- [Important links](#-important-links)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)

## 📦 Download

Installers are published only on **[vouchcompute.com/download](https://www.vouchcompute.com/download)**. The first
signed release is in preparation: Windows and Linux first, macOS (Apple Silicon) soon after. Until it is out, the
download page shows placeholders, and any "Vouch Compute" installer found elsewhere is not ours.

Release files will be signed, and the download page will list each file's SHA-256 checksum, so you can check that the
file you downloaded is the one we published. The app installs only updates signed with the project's release keys, and
never an older version.

## 🍎 First launch on macOS

The macOS app is **not signed with an Apple Developer ID and not notarized**. We have no Apple Developer account yet,
and we'd rather say so than hide it. Trust comes from the published source, the checksums below and our own update
signatures, not from Apple.

Because of that, macOS blocks the app the first time you open it. You allow it once:

1. Open the downloaded `.dmg` and drag **Vouch Compute** to **Applications**.
2. Open Vouch Compute from Applications. macOS says it can't verify the developer. Click **Done** (not "Move to Trash").
3. Open **System Settings → Privacy & Security** and scroll down to the note about Vouch Compute.
   Click **Open Anyway**, then confirm with your password or Touch ID.
4. Open the app again and choose **Open**. From now on it opens normally.

On older macOS versions, right-click (or Control-click) the app in Applications and choose **Open** instead.

**Check the download before you open it.** Each release lists SHA-256 checksums in a `SHA256SUMS` file. In Terminal, in
the folder that holds both files:

```bash
grep '\.dmg$' SHA256SUMS | shasum -a 256 -c -
# or compare by eye:
shasum -a 256 VouchCompute-<version>-macos-arm64.dmg
```

The line for the `.dmg` must say `OK` (or the two hashes must be equal). If not, delete the file and don't open it.

**What the update signature protects.** The app installs an update only if it is signed with the project's release
update key (the `.sig` file next to each update), whose public half is built into the app. It also refuses older
versions. So a changed or swapped update file is rejected, even though Apple doesn't sign the app. What it does not
cover: the first download itself (that's what the checksum is for), and a compromise of our release key.

This section applies once the first macOS build is published; until then the download page shows macOS as coming soon.

**What being unsigned changes for you.** Nothing in how jobs run: every job still runs in the macOS sandbox described
below. Without Apple's signing, the app can't use a Secure Enclave key or Apple's device attestation yet, so Macs start
with the lower, capped earning limits that apply to every device without hardware attestation.

**Homebrew.** Once the first macOS build is published, the app can also be installed from the project's own tap:
`brew install --cask metehanaydemir/tap/vouch-compute`. The "Open Anyway" step above still applies once. The cask pins
the release's SHA-256, and the tap's README ([MetehanAydemir/homebrew-tap](https://github.com/MetehanAydemir/homebrew-tap))
explains how to verify, update and uninstall. The official Homebrew repository only lists signed and notarized apps,
which is why it is a separate tap.

Maintainers: `scripts/release-macos.sh` builds the unsigned release on an Apple silicon Mac, writes `SHA256SUMS` and the
updater files, prints the `gh release create` command to run by hand, and (with `VOUCH_TAP_DIR` set) runs
`scripts/update-cask.sh`, which writes the version and checksum into the tap's cask and prints the git commands for it.

## ✨ Features

- **Runs only when you're away.** Jobs start when the computer is idle and stop as soon as you come back. You set
  limits for CPU, GPU, temperature and battery.
- **Paid for verified work only.** The server meters and checks every job, and pays in US dollars for work that passes.
  Earnings are shown as estimated ranges, never as guaranteed income.
- **No token, no points, no mining.** Just small AI jobs and US dollar payouts. We don't pay or accept cryptocurrency.
- **Signed, tamper-evident updates.** Release builds trust only release keys, and refuse to downgrade.

## 🛡️ What the sandbox protects

Every job runs in a separate, locked-down worker process:

- **No network access.** A job can't reach the internet or your local network.
- **No access to your files.** It sees only the job's own input and a private scratch folder, which is deleted
  afterwards.
- **Least privilege.**
  - Windows: AppContainer.
  - Linux: namespaces, Landlock and seccomp.
  - macOS: a deny-by-default sandbox profile.
- **Your limits win.** The app pauses work when you use the computer, or when it gets too hot or the battery is low.

Jobs are for public and non-sensitive data only. The buyer-facing data policy says so on every page of the website.

## 💻 System requirements

| OS | Requirements |
|---|---|
| Windows | Windows 10 or 11, x64. NVIDIA GPUs with 8 GB or more are paid; other devices join an unpaid beta. |
| Linux | x86_64, AppImage or `.deb`. Devices without a TPM start with lower limits. |
| macOS | Coming soon: macOS 13 or newer, Apple Silicon (M1 or later). |

## 🛠️ Build from source

Requirements:
- **Rust 1.98.1**, pinned in `client/rust-toolchain.toml`; `rustup` installs it automatically.
- **Node.js 22**, for the Tauri CLI.
- **The [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/)** for your OS:
  - Windows: Visual Studio 2022 Build Tools ("Desktop development with C++") and WebView2.
  - Linux: `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libgtk-3-dev libssl-dev patchelf cmake clang libclang-dev`.
  - macOS: Xcode Command Line Tools.

```bash
# test and lint
cd client
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# run the app in development mode
cd pool-app
npm ci
npx tauri dev
```

Build an unsigned development installer:

```bash
cd client/pool-app
npm ci
npx tauri signer generate -w ../dev-keys/updater-1.key   # once: your own development update key
# set TAURI_SIGNING_PRIVATE_KEY to that file's contents (empty password), then:
npx tauri build                                          # bundles in client/target/release/bundle/
```

On Windows, the installer bundles the GPU backend pack: ONNX Runtime with DirectML, plus the Visual C++ runtime in
`client/pool-app/vendor/vcruntime/`. Fetch it before building an installer:

```bash
cd client/pool-app
node scripts/gpu-pack.mjs          # fetches the pack and checks every file against its SHA-256 pin
node scripts/gpu-pack.mjs --check  # verify only
```

A plain `cargo build` or `cargo test` works without the pack: GPU jobs are then refused at job start. Development
builds use their own update channel and keys. They can't install release updates, and release builds refuse
development keys.

<details>
<summary>Repository layout</summary>

| Path | What |
|---|---|
| `client/crates/pool-core` | the background agent: device identity, connection, job scheduling, idle and thermal governor |
| `client/crates/pool-runner` | the per-job worker inside the sandbox (speech-to-text, embeddings; CPU and GPU backends) |
| `client/crates/pool-sandbox` | the OS sandboxes for Windows, Linux and macOS |
| `client/crates/pool-proto` | the wire protocol and the signed objects the app verifies |
| `client/pool-app` | the Tauri 2 desktop shell and its UI |
| `client/fuzz` | fuzz targets for the decoders and the update-signature check |
| `proto/node.proto` | the protocol definition |

</details>

## 🔗 Important links

- Website: [vouchcompute.com](https://www.vouchcompute.com)
- Download: [vouchcompute.com/download](https://www.vouchcompute.com/download)
- How earnings work (realistic ranges): [vouchcompute.com/earn](https://www.vouchcompute.com/earn)
- Trust and security: [vouchcompute.com/trust](https://www.vouchcompute.com/trust)

## 🤝 Contributing

Pull requests are welcome once the repository is public. Please run `cargo clippy` and `cargo test` before opening
one. Changes to the protocol, the sandbox, the device key or the updater get an extra security review.

## 🔒 Security

Please report vulnerabilities privately to **security@vouchcompute.com**, not in a public issue. See
[SECURITY.md](SECURITY.md).

## 📄 License

Not yet released under an open-source license. A license will be chosen before the repository is made public. Until
then, all rights are reserved.
