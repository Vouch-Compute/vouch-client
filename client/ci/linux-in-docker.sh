#!/usr/bin/env bash
# Linux build + tests inside a Debian container (used by `scripts/dev.ps1 client-linux-docker` and
# `scripts/dev.sh client-linux-docker`). The repo is mounted read-only at /src; work happens in /work.
# Produces /out/{*.deb, *.AppImage, test logs} (Vouch Compute bundles).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libgtk-3-dev libssl-dev \
  patchelf cmake clang libclang-dev build-essential pkg-config curl file xdg-utils ca-certificates \
  nodejs npm >/dev/null
rustup component add clippy >/dev/null 2>&1 || true

mkdir -p /work /out
tar -C /src -cf - --exclude=client/pool-app/node_modules --exclude=client/pool-app/src-tauri/binaries \
  --exclude=client/dist-linux --exclude=client/dev-keys client proto \
  | tar -C /work -xf -
cd /work/client
export CARGO_TARGET_DIR=/work/target
export RUSTUP_TOOLCHAIN=1.98.1

echo "== clippy" ; cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -n 20
echo "== test"   ; cargo test --workspace 2>&1 | tee /out/linux-test.log | grep -E "^test result|FAILED|panicked|WARNING" || true
grep -q "FAILED" /out/linux-test.log && { echo "tests failed"; exit 1; }
echo "== release decoding rules (pool-proto without dev-trust)"
cargo test -p pool-proto --no-default-features 2>&1 | grep -E "^test result|FAILED|panicked"
echo "== native runtimes (whisper.cpp + onnxruntime features, clippy -D warnings)"
cargo clippy -p pool-runner --features whisper,onnx -- -D warnings 2>&1 | tail -n 5
echo "== app money display + reliability card + rendering + languages"
node pool-app/tests/usd.test.js
node pool-app/tests/reliability.test.js
node pool-app/tests/render.test.js
node pool-app/tests/i18n.test.js
node pool-app/tests/i18n-render.test.js
echo "== release hygiene: guard + marker check"
bash ci/release-guard.sh
POOL_RELEASE=1 cargo build -p pool-core --bin pool-core --no-default-features --features nvml,release 2>&1 | tail -n 2
POOL_RELEASE=1 cargo build -p pool-runner --bin pool-runner --no-default-features --features candle 2>&1 | tail -n 2
mkdir -p /tmp/relbins && cp "$CARGO_TARGET_DIR"/debug/pool-core "$CARGO_TARGET_DIR"/debug/pool-runner /tmp/relbins/
bash ci/release-marker-check.sh /tmp/relbins
cargo build -p pool-runner --bin pool-runner 2>&1 | tail -n 1
if bash ci/release-marker-check.sh "$CARGO_TARGET_DIR"/debug/pool-runner; then echo "marker check passed a dev-trust binary"; exit 1; fi

echo "== tauri bundle (AppImage + deb)"
cd pool-app
npm ci --no-audit --no-fund >/dev/null
npx tauri signer generate --ci -w /tmp/updater.key -f >/dev/null
export TAURI_SIGNING_PRIVATE_KEY="$(cat /tmp/updater.key)" TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
export APPIMAGE_EXTRACT_AND_RUN=1 NO_STRIP=true
npx tauri build --bundles deb,appimage 2>&1 | tail -n 15
cp -v "$CARGO_TARGET_DIR"/release/bundle/deb/*.deb "$CARGO_TARGET_DIR"/release/bundle/appimage/*.AppImage /out/ 2>/dev/null || true
ls -la /out
