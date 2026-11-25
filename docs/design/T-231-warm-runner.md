# T-231: warm runner per model (candidate for the next round)

Status: **proposal, no code.** Needs vault review before any implementation (it changes the job isolation model).

## Problem

Every benchmark run and every job starts a fresh sandboxed `pool-runner`, which re-reads and re-verifies the whole
model bundle before it computes anything. For bge-m3 that is 2.27 GB per run.

Measured on the owner's MacBook Pro (M3 Pro, 18 GB, macOS 27, test build `0.2.1-test.e5a9265`, 25 Nov):

| | Value |
|---|---|
| Benchmark result (20 segments, 161 runs, received by the server) | **11.0 tokens/s** |
| Time per run | about 7.5 s for about 80–110 tokens |
| SHA-256 of `model.onnx_data` (2.27 GB, `shasum`) | about 5.1 s |
| ONNX Runtime session load and optimisation | 0.66 s |
| One bge-m3 inference, 107 tokens, CPU | 0.15 s |
| Same model kept loaded (warm) | **about 718 tokens/s** |

The runner reads every bundle file into memory and hashes it each run (`pool-runner` `bundle::load`). Then it
builds the session, runs one input and exits. Over 90 % of each run is setup. The measured rate (and the server's
rate derived from the signed timing) is about 65 times below what the machine delivers warm. Jobs pay for the same
overhead, so tiers and earnings understate every device. Large models are affected most.

## Proposal

Keep one runner process alive per (model hash, runtime, runtime version) and send it inputs over the existing pipe
protocol.

1. **Verify once per process.** The runner verifies the manifest, file hashes and the runtime pack once at start, as
   today. Later inputs reuse the verified, in-memory session.
2. **Same sandbox, same limits.** The warm runner runs under exactly the sandbox and caps of today's per-job runner,
   with read access to that model only. One model per process; never two models or two runtimes in one process.
3. **Recycle.** End the process after N inputs, T minutes, idle time, a pause or pre-emption, a KeySet change or any
   error. Pre-emption still kills the whole sandbox at once (the 5 s SLA is unchanged).
4. **No state between inputs.** Inputs and outputs stay memory-only. The runner keeps no per-job data: no caches keyed
   by input, no files. A test asserts that the outputs for an input are identical warm and cold.
5. **Benchmark and jobs on the same path.** The benchmark uses the warm runner exactly as jobs do, so the
   benchmarked rate stays comparable with delivered work. The first run's start-up is included in the window, as
   now.
6. **Re-verify on reuse when files may have changed.** Before each input, check the model directory's file sizes
   and modification times against the verified set. Any change ends the process.

## Questions for vault

- Is one process per model across jobs from different buyers acceptable, given points 2, 4 and 6? The alternative
  is one warm process per job, which only helps jobs with many inputs.
- How should N and T be set, and should the server be able to set them (signed in the KeySet)?
- Does the benchmark rate need a new protocol version, since rates will jump about 60 times for large models?
  Old benchmarks would no longer compare with new ones.

## Smaller step, independent of the above

Hash the model once when it is downloaded, then use a cheaper check per run: the size and modification time of each
file, recorded at download. A full re-hash would happen only after a change. This alone cuts bge-m3 from about 7.5 s
to about 1 s per run (about 100 tokens/s). It needs vault's view, because it weakens "verify before every load".
