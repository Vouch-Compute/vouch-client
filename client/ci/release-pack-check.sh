#!/usr/bin/env bash
# Release hygiene: the packaged app carries this target's pinned runtime packs (crates/pool-runner/packs.json) where the
# agent looks for them (pool-core config.rs `default_pack_dirs`), byte for byte.
#
#   client/ci/release-pack-check.sh <target> <bundle dir>      e.g. macos-aarch64 target/release/bundle
#
# Checked: macOS `<App>.app/Contents/Resources/backends/<dir>/`, Linux `.deb` and AppImage `usr/lib/<productName>/
# backends/<dir>/`. Windows: the NSIS installer is not unpacked here; its resources are the files build.rs already
# checked against the pins (POOL_RELEASE=1). A target without packs passes.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <target> <bundle dir>" >&2; exit 2; }
target="$1"; bundle="$(cd "$2" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
client="$(cd "$here/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# "<dir>/<name> <sha256>" per pinned file of the target
pins="$(node -e '
  const t = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  for (const p of t.packs.filter((p) => p.target === process.argv[2])) for (const f of p.files) console.log(`${p.dir}/${f.name} ${f.sha256}`);
' "$client/crates/pool-runner/packs.json" "$target")"
product="$(node -p 'require(process.argv[1]).productName' "$client/pool-app/src-tauri/tauri.conf.json")"
[ -n "$pins" ] || { echo "release pack check: no runtime pack pinned for $target"; exit 0; }

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
bad=0; checked=0
check_root() { # <resource root> <label>
  local root="$1" label="$2" rel want got
  while read -r rel want; do
    if [ ! -f "$root/backends/$rel" ]; then echo "MISSING: $label backends/$rel"; bad=1; continue; fi
    got="$(sha "$root/backends/$rel")"
    if [ "$got" != "$want" ]; then echo "MISMATCH: $label backends/$rel is $got, pinned $want"; bad=1; continue; fi
    checked=$((checked + 1))
  done <<< "$pins"
}

case "$target" in
  macos-*)
    found=0
    for app in "$bundle"/macos/*.app; do
      [ -d "$app" ] || continue; found=1
      check_root "$app/Contents/Resources" "$(basename "$app")"
    done
    [ "$found" -eq 1 ] || { echo "no .app in $bundle/macos"; exit 1; }
    ;;
  linux-*)
    found=0
    for deb in "$bundle"/deb/*.deb; do
      [ -f "$deb" ] || continue; found=1
      d="$work/deb$RANDOM"; mkdir -p "$d"; dpkg-deb -x "$deb" "$d"
      check_root "$d/usr/lib/$product" "$(basename "$deb")"
    done
    for img in "$bundle"/appimage/*.AppImage; do
      [ -f "$img" ] || continue; found=1
      d="$work/appimage$RANDOM"; mkdir -p "$d"; cp "$img" "$d/a.AppImage"; chmod +x "$d/a.AppImage"
      (cd "$d" && APPIMAGE_EXTRACT_AND_RUN=1 ./a.AppImage --appimage-extract >/dev/null)
      check_root "$d/squashfs-root/usr/lib/$product" "$(basename "$img")"
    done
    [ "$found" -eq 1 ] || { echo "no .deb or .AppImage in $bundle"; exit 1; }
    ;;
  *) echo "release pack check: $target bundles are not unpacked here (build.rs checked the pins)"; exit 0 ;;
esac
[ "$bad" -eq 0 ] || exit 1
echo "release pack check: $checked pinned file(s) present and matching in the $target bundle(s)"
