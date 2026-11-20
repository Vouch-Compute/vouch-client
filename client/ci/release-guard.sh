#!/usr/bin/env bash
# Release hygiene: a release-signing build with `dev-trust` must not compile.
#   client/ci/release-guard.sh        (run from anywhere; uses the client workspace)
# 1. POOL_RELEASE=1 with the default (dev-trust) features   -> must FAIL with the release guard's compile_error!
# 2. the `release` feature together with dev-trust          -> must FAIL the same way
# 3. POOL_RELEASE=1 with the release feature set             -> must compile
set -uo pipefail
cd "$(dirname "$0")/.."
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
fail() { echo "release guard: $*"; exit 1; }

echo "== 1. POOL_RELEASE=1 cargo check -p pool-core (default features include dev-trust): must fail"
if POOL_RELEASE=1 cargo check -p pool-core >"$log" 2>&1; then fail "a release-signing build with dev-trust compiled"; fi
grep -q "dev-trust is enabled in a release-signing build" "$log" || { tail -n 30 "$log"; fail "failed, but not on the release guard"; }

echo "== 2. cargo check -p pool-proto --features dev-trust,release: must fail"
if cargo check -p pool-proto --features dev-trust,release >"$log" 2>&1; then fail "the release feature with dev-trust compiled"; fi
grep -q "dev-trust is enabled in a release-signing build" "$log" || { tail -n 30 "$log"; fail "failed, but not on the release guard"; }

echo "== 3. POOL_RELEASE=1 release feature set: must compile"
POOL_RELEASE=1 cargo check -p pool-core --no-default-features --features nvml,release >"$log" 2>&1 || { tail -n 30 "$log"; fail "the release build does not compile"; }
POOL_RELEASE=1 cargo check -p pool-runner --no-default-features --features candle >"$log" 2>&1 || { tail -n 30 "$log"; fail "the release runner does not compile"; }
echo "release guard: ok"
