#!/usr/bin/env bash
# Write a release's version, sha256 and download URL into the Homebrew cask of the tap repository.
#
#   VOUCH_DOWNLOAD_BASE='https://downloads.vouchcompute.com/macos/#{version}' \
#     scripts/update-cask.sh <SHA256SUMS> <path to Casks/vouch-compute.rb>
#
# <SHA256SUMS> is the file release-macos.sh writes next to the release files. The version is read from the file name
# VouchCompute-<version>-macos-arm64.dmg in it, and the sha256 from the same line, so the cask always describes the
# file that was actually built.
#
# VOUCH_DOWNLOAD_BASE is the per-version folder the release files are served from, as an https URL with Homebrew's
# "#{version}" placeholder (two options, see the tap's README):
#   https://github.com/MetehanAydemir/vouch-client/releases/download/client-macos-v#{version}   public GitHub release
#   https://downloads.vouchcompute.com/macos/#{version}                                        our download address
#
# When the Tauri config is found (VOUCH_TAURI_CONF, or client/pool-app/src-tauri/tauri.conf.json in this checkout),
# the cask's `app` name and minimum macOS are checked against productName and minimumSystemVersion.
#
# Nothing is committed or pushed: the git commands for the tap repository are printed at the end.
set -euo pipefail

die() { echo "update-cask: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: scripts/update-cask.sh <SHA256SUMS> <Casks/vouch-compute.rb>"
sums="$1"
cask="$2"
[ -f "$sums" ] || die "not a file: $sums"
[ -f "$cask" ] || die "not a file: $cask"

base="${VOUCH_DOWNLOAD_BASE:-}"
[ -n "$base" ] || die "VOUCH_DOWNLOAD_BASE is not set (per-version download folder with the #{version} placeholder)"
case "$base" in
  https://*) ;;
  *) die "VOUCH_DOWNLOAD_BASE must be an https URL" ;;
esac
case "$base" in
  *'#{version}'*) ;;
  *) die 'VOUCH_DOWNLOAD_BASE must contain the #{version} placeholder, so the URL changes with every release' ;;
esac
base="${base%/}"

# ------------------------------------------------------------------------------------------- version and checksum
line="$(grep -E '^[0-9a-f]{64} [ *]VouchCompute-[0-9]+\.[0-9]+\.[0-9]+-macos-arm64\.dmg$' "$sums" || true)"
[ -n "$line" ] || die "no VouchCompute-<version>-macos-arm64.dmg line in $sums"
[ "$(printf '%s\n' "$line" | wc -l | tr -d ' ')" = "1" ] || die "more than one .dmg line in $sums"
sha="${line%% *}"
file="${line##* }"
version="${file#VouchCompute-}"
version="${version%-macos-arm64.dmg}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected version '$version'"

url="$base/VouchCompute-#{version}-macos-arm64.dmg"

# `verified:` is the part of the URL before the version, without the scheme, ending in a slash. For GitHub it is the
# repository, as Homebrew's casks write it.
host_path="${base#https://}"
verified="${host_path%%\#\{version\}*}"
verified="${verified%/*}/"
case "$verified" in
  github.com/*/*/*) verified="$(printf '%s' "$verified" | cut -d/ -f1-3)/" ;;
esac

# ------------------------------------------------------------------------------------------- consistency checks
conf="${VOUCH_TAURI_CONF:-}"
if [ -z "$conf" ]; then
  root="$(cd "$(dirname "$0")/.." && pwd)"
  [ -f "$root/client/pool-app/src-tauri/tauri.conf.json" ] && conf="$root/client/pool-app/src-tauri/tauri.conf.json"
fi
if [ -n "$conf" ]; then
  command -v node >/dev/null 2>&1 || die "node is needed to read $conf"
  product="$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).productName' "$conf")"
  min_os="$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).bundle.macOS.minimumSystemVersion' "$conf")"
  grep -qF "  app \"$product.app\"" "$cask" || die "the cask's app name does not match productName \"$product\" in $conf"
  case "${min_os%%.*}" in
    13) sym=ventura ;; 14) sym=sonoma ;; 15) sym=sequoia ;; 26) sym=tahoe ;;
    *) die "no Homebrew symbol known for minimumSystemVersion $min_os; extend the table in this script" ;;
  esac
  grep -qF "  depends_on macos: \">= :$sym\"" "$cask" || die "the cask's depends_on macos does not match minimumSystemVersion $min_os (:$sym) in $conf"
  version_conf="$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).version' "$conf")"
  [ "$version_conf" = "$version" ] || echo "update-cask: note: $sums is for $version, the checkout's tauri.conf.json says $version_conf" >&2
fi

# ------------------------------------------------------------------------------------------- rewrite the cask
# Only the four lines change; everything else is kept byte for byte. A temp file and rename, no sed -i (differs
# between macOS and GNU).
tmp="$cask.tmp.$$"
awk -v version="$version" -v sha="$sha" -v url="$url" -v verified="$verified" '
  BEGIN { seen_version = seen_sha = seen_url = seen_verified = 0 }
  /^  version "/   && !seen_version  { print "  version \"" version "\""; seen_version = 1; next }
  /^  sha256 "/    && !seen_sha      { print "  sha256 \"" sha "\""; seen_sha = 1; next }
  /^  url "/       && !seen_url      { print "  url \"" url "\","; seen_url = 1; next }
  /^      verified: "/ && !seen_verified { print "      verified: \"" verified "\""; seen_verified = 1; next }
  { print }
  END { if (!(seen_version && seen_sha && seen_url && seen_verified)) exit 3 }
' "$cask" > "$tmp" || { rm -f "$tmp"; die "the cask does not have the expected version, sha256, url and verified lines"; }
mv "$tmp" "$cask"

echo "update-cask: $cask"
echo "  version  $version"
echo "  sha256   $sha"
echo "  url      $url"
echo "  verified $verified"
echo
echo "Publish the release files first (the audit downloads $url), then in the tap repository:"
echo
tapdir="$(cd "$(dirname "$cask")/.." && pwd)"
printf '  cd %q\n' "$tapdir"
printf '  git add %q\n' "Casks/$(basename "$cask")"
printf '  git commit -m %q\n' "vouch-compute $version"
printf '  git tag %q\n' "v$version"
printf '  git push origin HEAD %q\n' "v$version"
echo
echo "The tag starts the tap's audit workflow (brew style, brew audit --cask --strict --online)."
