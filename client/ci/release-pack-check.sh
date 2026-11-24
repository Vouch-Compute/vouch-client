#!/usr/bin/env bash
# Release hygiene: every packaged form of the app carries this target's pinned runtime packs
# (crates/pool-runner/packs.json) where the agent looks for them (pool-core config.rs `default_pack_dirs`), byte for
# byte, **after** the bundler has signed the app. On macOS this is the check vault asked for before the first release
# with the CPU pack (CR-T215-01 follow-up): code signing must leave the pinned libonnxruntime.dylib unchanged, or the
# release fails closed (the agent would refuse the pack, so the app could run no embedding job).
#
#   client/ci/release-pack-check.sh <target> <bundle dir>      e.g. macos-aarch64 target/release/bundle
#
# Checked:
# * macOS: each `<App>.app/Contents/Resources/backends/<dir>/`, the same inside every `.dmg` (mounted read-only) and
#   inside every updater archive `<App>.app.tar.gz` (what auto-update installs); where `codesign` exists, each `.app`
#   must also pass `codesign --verify --strict` (a valid seal over the bytes that were checked).
# * Linux: `.deb` and AppImage `usr/lib/<productName>/backends/<dir>/`.
# * Windows: the NSIS installer is not unpacked here; its resources are the files build.rs already checked against the
#   pins (POOL_RELEASE=1). A target without packs passes.
#
# RELEASE_PACK_REQUIRE (optional, comma-separated: app,dmg,updater,deb,appimage): forms that must be present.
# PACKS_JSON, PACK_CHECK_NO_CODESIGN (self-test only, pool-app/tests/release-pack-check.test.js): another pin table
# instead of crates/pool-runner/packs.json; skip the signature check of the unsigned test fixtures.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <target> <bundle dir>" >&2; exit 2; }
target="$1"; bundle="$(cd "$2" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
client="$(cd "$here/.." && pwd)"
packs_json="${PACKS_JSON:-$client/crates/pool-runner/packs.json}"
work="$(mktemp -d)"
mounts=()
cleanup() {
  for m in "${mounts[@]:-}"; do [ -n "$m" ] && { hdiutil detach -quiet "$m" >/dev/null 2>&1 || true; }; done
  rm -rf "$work"
}
trap cleanup EXIT

# "<dir>/<name> <sha256>" per pinned file of the target
pins="$(node -e '
  const t = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  for (const p of t.packs.filter((p) => p.target === process.argv[2])) for (const f of p.files) console.log(`${p.dir}/${f.name} ${f.sha256}`);
' "$packs_json" "$target")"
product="$(node -p 'require(process.argv[1]).productName' "$client/pool-app/src-tauri/tauri.conf.json")"
[ -n "$pins" ] || { echo "release pack check: no runtime pack pinned for $target"; exit 0; }

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bad=0; checked=0; seen=""
check_root() { # <resource root> <label>
  local root="$1" label="$2" rel want got
  while read -r rel want; do
    if [ ! -f "$root/backends/$rel" ]; then echo "MISSING: $label backends/$rel"; bad=1; continue; fi
    got="$(sha "$root/backends/$rel")"
    if [ "$got" != "$want" ]; then echo "MISMATCH: $label backends/$rel is $got, pinned $want"; bad=1; continue; fi
    checked=$((checked + 1))
  done <<< "$pins"
}
check_app() { # <App.app> <label>
  local app="$1" label="$2"
  check_root "$app/Contents/Resources" "$label"
  if [ -z "${PACK_CHECK_NO_CODESIGN:-}" ] && command -v codesign >/dev/null; then
    if codesign --verify --strict "$app" 2>"$work/codesign.err"; then
      echo "signature ok: $label ($(codesign -dv "$app" 2>&1 | grep -E '^(Signature|CodeDirectory)' | tr '\n' ' '))"
    else
      echo "SIGNATURE: $label does not verify: $(cat "$work/codesign.err")"; bad=1
    fi
  fi
}
saw() { seen="$seen,$1"; }

case "$target" in
  macos-*)
    for app in "$bundle"/macos/*.app; do
      [ -d "$app" ] || continue; saw app
      check_app "$app" "$(basename "$app")"
    done
    for tgz in "$bundle"/macos/*.app.tar.gz; do
      [ -f "$tgz" ] || continue; saw updater
      d="$work/updater$RANDOM"; mkdir -p "$d"; tar -xzf "$tgz" -C "$d"
      found=0
      for app in "$d"/*.app; do [ -d "$app" ] && { found=1; check_app "$app" "$(basename "$tgz")"; }; done
      [ "$found" -eq 1 ] || { echo "MISSING: no .app inside $(basename "$tgz")"; bad=1; }
    done
    for dmg in "$bundle"/dmg/*.dmg; do
      [ -f "$dmg" ] || continue; saw dmg
      if ! command -v hdiutil >/dev/null; then echo "cannot open $(basename "$dmg") here (no hdiutil)"; bad=1; continue; fi
      m="$work/dmg$RANDOM"; mkdir -p "$m"
      hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$m" "$dmg" >/dev/null; mounts+=("$m")
      found=0
      for app in "$m"/*.app; do [ -d "$app" ] && { found=1; check_app "$app" "$(basename "$dmg")"; }; done
      [ "$found" -eq 1 ] || { echo "MISSING: no .app inside $(basename "$dmg")"; bad=1; }
    done
    case "$seen" in *app*|*updater*|*dmg*) ;; *) echo "no .app, .app.tar.gz or .dmg in $bundle"; exit 1 ;; esac
    ;;
  linux-*)
    for deb in "$bundle"/deb/*.deb; do
      [ -f "$deb" ] || continue; saw deb
      d="$work/deb$RANDOM"; mkdir -p "$d"; dpkg-deb -x "$deb" "$d"
      check_root "$d/usr/lib/$product" "$(basename "$deb")"
    done
    for img in "$bundle"/appimage/*.AppImage; do
      [ -f "$img" ] || continue; saw appimage
      d="$work/appimage$RANDOM"; mkdir -p "$d"; cp "$img" "$d/a.AppImage"; chmod +x "$d/a.AppImage"
      (cd "$d" && APPIMAGE_EXTRACT_AND_RUN=1 ./a.AppImage --appimage-extract >/dev/null)
      check_root "$d/squashfs-root/usr/lib/$product" "$(basename "$img")"
    done
    case "$seen" in *deb*|*appimage*) ;; *) echo "no .deb or .AppImage in $bundle"; exit 1 ;; esac
    ;;
  *) echo "release pack check: $target bundles are not unpacked here (build.rs checked the pins)"; exit 0 ;;
esac
for need in $(echo "${RELEASE_PACK_REQUIRE:-}" | tr ',' ' '); do
  case "$seen," in *",$need,"*) ;; *) echo "MISSING FORM: no $need in $bundle (RELEASE_PACK_REQUIRE)"; bad=1 ;; esac
done
[ "$bad" -eq 0 ] || exit 1
echo "release pack check: $checked pinned file(s) present and matching in the $target bundle(s) ($(echo "${seen#,}" | tr ',' '\n' | sort -u | paste -sd, -))"
