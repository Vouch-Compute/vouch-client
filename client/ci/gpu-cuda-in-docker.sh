#!/usr/bin/env bash
# Build the runner with candle CUDA in an nvidia/cuda devel image and run the CUDA-vs-CPU benchmark
# inside the Linux sandbox. Needs `docker run --gpus all` and models mounted at /models (see crates/pool-runner/tests/
# gpu_cuda.rs):
#   docker run --rm --gpus all -v <repo>:/src:ro -v <models>:/models:ro -v pool-cargo-registry:/usr/local/cargo/registry \
#     nvidia/cuda:12.4.1-devel-ubuntu22.04 bash /src/client/ci/gpu-cuda-in-docker.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates build-essential pkg-config >/dev/null
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1 >/dev/null
fi
. "$HOME/.cargo/env"
mkdir -p /work
tar -C /src -cf - --exclude=client/pool-app/node_modules --exclude=client/dist-linux --exclude=client/dev-keys \
  --exclude=client/target --exclude=client/pool-app/src-tauri/backends client proto | tar -C /work -xf -
cd /work/client
export CARGO_TARGET_DIR=/work/target CUDA_COMPUTE_CAP="${CUDA_COMPUTE_CAP:-89}"
nvidia-smi --query-gpu=name,driver_version --format=csv,noheader || true
echo "== build (candle cuda)"
cargo build --release -p pool-runner --features cuda 2>&1 | tail -n 3
echo "== benchmark"
POOL_BENCH_MODEL=/models/bge-base POOL_WHISPER_MODEL=/models/whisper-base POOL_SPEECH_WAV=/models/jfk.wav \
  cargo test --release -p pool-runner --features cuda --test gpu_cuda -- --ignored --nocapture 2>&1 \
  | grep -vE "^\s+(Compiling|Finished|Running)"
