#!/usr/bin/env bash
# Release hygiene: refuse to ship or sign any binary that is a dev-trust build.
#
#   client/ci/release-marker-check.sh <file-or-dir>...      exit 0 = clean release binaries, 1 = refused
#
# A binary is refused when it contains any of:
#   * POOL_DEV_TRUST_ROOTS               the dev trust-root override (exists only in dev-trust builds)
#   * VOUCH-DEV-REFERENCE-BACKEND        the dev reference model backend marker (pool-runner, dev-trust only)
#   * VOUCH-BUILD-INFO dev-trust=yes     the embedded build info of a dev-trust build
# and the agent binaries (pool-core, pool-runner) must carry "VOUCH-BUILD-INFO dev-trust=no".
# Directories are searched for executables and shared libraries; .deb packages and AppImages are unpacked first.
# The release signing workflow runs this immediately before every signing step.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <file-or-dir>..." >&2; exit 2; }

FORBIDDEN=("POOL_DEV_TRUST_ROOTS" "VOUCH-DEV-REFERENCE-BACKEND" "VOUCH-BUILD-INFO dev-trust=yes")
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
files=()

add() {
  local f="$1"
  case "$f" in
    *.deb)
      local d="$work/deb$RANDOM"; mkdir -p "$d"
      (cd "$d" && ar x "$f" && tar -xf data.tar.* 2>/dev/null) || { echo "cannot unpack $f" >&2; exit 1; }
      while IFS= read -r -d '' x; do files+=("$x"); done < <(find "$d" -type f -perm -u+x -print0)
      ;;
    *.AppImage)
      local d="$work/appimage$RANDOM"; mkdir -p "$d"; cp "$f" "$d/a.AppImage"; chmod +x "$d/a.AppImage"
      (cd "$d" && APPIMAGE_EXTRACT_AND_RUN=1 ./a.AppImage --appimage-extract >/dev/null) || { echo "cannot unpack $f" >&2; exit 1; }
      while IFS= read -r -d '' x; do files+=("$x"); done < <(find "$d/squashfs-root" -type f -perm -u+x -print0)
      ;;
    *) files+=("$f") ;;
  esac
}

for a in "$@"; do
  if [ -d "$a" ]; then
    while IFS= read -r -d '' f; do add "$f"; done < <(find "$a" -type f \( -name '*.exe' -o -name '*.dll' -o -name '*.so' -o -name '*.dylib' \
      -o -name '*.deb' -o -name '*.AppImage' -o -name 'pool-core*' -o -name 'pool-runner*' -o -name 'VouchCompute' -o -name 'vouch-compute' -o -perm -u+x \) -print0)
  else
    add "$a"
  fi
done
[ ${#files[@]} -gt 0 ] || { echo "no binaries found in: $*" >&2; exit 1; }

bad=0; agents=0
for f in "${files[@]}"; do
  for m in "${FORBIDDEN[@]}"; do
    if grep -a -q -F "$m" "$f"; then echo "REFUSED: $f contains \"$m\" (dev-trust build)"; bad=1; fi
  done
  case "$(basename "$f")" in
    pool-core*|pool-runner*)
      agents=$((agents + 1))
      grep -a -q -F "VOUCH-BUILD-INFO dev-trust=no" "$f" || { echo "REFUSED: $f has no release build info"; bad=1; }
      ;;
  esac
done
[ "$bad" -eq 0 ] || exit 1
echo "release marker check: ${#files[@]} file(s) clean (${agents} agent binaries with release build info)"
