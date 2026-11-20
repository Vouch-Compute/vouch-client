#!/usr/bin/env bash
# Coverage-guided fuzzing with cargo-fuzz (libFuzzer) inside a Debian container, nightly toolchain.
#   docker run --rm -v "<repo>:/src:ro" -v "<out>:/out" -e FUZZ_SECS=300 rust:1.98.1-bookworm bash /src/client/ci/fuzz-in-docker.sh
# Each target runs FUZZ_SECS seconds (default 300) with a seed corpus of valid signed objects; any crash, panic,
# timeout or OOM fails the run and its reproducer is copied to /out/fuzz-artifacts.
set -euo pipefail
FUZZ_SECS="${FUZZ_SECS:-300}"
mkdir -p /work /out
tar -C /src -cf - --exclude=client/pool-app/node_modules --exclude=client/dist-linux --exclude=client/dev-keys \
  --exclude=client/target client proto | tar -C /work -xf -
rustup toolchain install nightly --profile minimal >/dev/null 2>&1
cargo +nightly install cargo-fuzz --locked >/dev/null 2>&1 || cargo +nightly install cargo-fuzz >/dev/null 2>&1
cd /work/client/fuzz
export CARGO_TARGET_DIR=/work/fuzz-target
cargo +nightly fuzz build -O 2>&1 | tail -n 3
status=0
: > /out/fuzz-summary.txt
for t in frame cbor_cose manifest tamper update_sig; do
  mkdir -p "corpus/$t"
  echo "== $t ($FUZZ_SECS s)"
  if cargo +nightly fuzz run "$t" "corpus/$t" -O -- -max_total_time="$FUZZ_SECS" -rss_limit_mb=2048 -timeout=10 \
      -print_final_stats=1 > "/out/fuzz-$t.log" 2>&1; then
    echo "$t: ok $(grep -E 'stat::number_of_executed_units' "/out/fuzz-$t.log" | awk '{print $2}') execs, corpus $(ls "corpus/$t" | wc -l)" | tee -a /out/fuzz-summary.txt
  else
    echo "$t: FAILED (see fuzz-$t.log)" | tee -a /out/fuzz-summary.txt
    status=1
  fi
  tail -n 4 "/out/fuzz-$t.log"
done
mkdir -p /out/fuzz-artifacts && cp -r artifacts/* /out/fuzz-artifacts/ 2>/dev/null || true
exit $status
