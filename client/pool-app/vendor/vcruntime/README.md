# Visual C++ runtime (app-local, Windows GPU pack)

ONNX Runtime and DirectML need the Microsoft Visual C++ 2015-2022 runtime. The app ships its own copy next to
`onnxruntime.dll` instead of relying on whatever version is installed system-wide, so every install loads the
same, known files.

| File | Version | SHA-256 |
|---|---|---|
| `vcruntime140.dll` | 14.51.36247.0 | `d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7` |
| `vcruntime140_1.dll` | 14.51.36247.0 | `a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e` |
| `msvcp140.dll` | 14.51.36247.0 | `7c26614e1d733892c2deac7e245ce115504b1d80592dd0a01b08e3e5a55f89ca` |

The files are Microsoft-signed redistributable binaries (Visual C++ Redistributable, app-local deployment).

How they are used:

* `scripts/gpu-pack.mjs` copies them into the GPU backend pack only after their SHA-256 matches the pin list in
  `crates/pool-runner/src/accel.rs` (`PINNED`); a mismatch stops the build.
* On every job start, the agent and the sandboxed runner both re-check every pinned file of the pack and load
  them by full path in a fixed order. There is no fallback to a system copy.

Updating: replace the files, update the hashes in `PINNED` (and this table), rebuild the pack. A new pin only
reaches users through a signed app update.
