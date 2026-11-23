#!/usr/bin/env bash
# Build an UNSIGNED macOS release of Vouch Compute on an Apple silicon Mac and stage it for a GitHub Release.
#
# There is no Apple Developer ID yet (owner decision), so the app is ad-hoc signed and not notarized: on first
# launch macOS blocks it once, and the user allows it in System Settings > Privacy & Security > "Open Anyway"
# (README, "First launch on macOS"). Updates are still verified: the updater accepts only bundles signed with the
# project's release updater key, independent of Apple.
#
# This script mirrors the macOS leg of .github/workflows/client-release.yml. It builds, checks and collects files.
# It never publishes: it prints the `gh release create` command for you to review and run.
#
# Usage (repository root, clean checkout of the commit you want to release):
#   export VOUCH_RELEASE_UPDATER_PUBKEYS="<current release updater PUBLIC key>[,<next public key>]"
#   export VOUCH_RELEASE_UPDATE_URL="https://downloads.vouchcompute.com/desktop/stable/latest.json"
#   export TAURI_SIGNING_PRIVATE_KEY="$(cat /path/outside/the/repo/updater-release.key)"   # or the key file's path
#   export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="..."                                         # if the key has one
#   scripts/release-macos.sh
#
# Optional: RELEASE_BASE_URL (where the files will be downloadable; default: this repo's GitHub release download URL,
# which needs the repository to be public), RELEASE_REPO (default MetehanAydemir/vouch-client).
#
# Secrets: the updater PRIVATE key is read from the environment only. This script never prints it, never writes it to
# disk and refuses a key file inside the repository. It is removed from the environment for every step except the
# final `tauri build` (so `npm ci` install scripts and the guard builds never see it). Shell tracing is switched off.
set -euo pipefail
set +x

die() { echo "release-macos: $*" >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
[ -d client/pool-app/src-tauri ] || die "run from a vouch-client checkout (client/pool-app not found)"

# ------------------------------------------------------------------------------------------------ preconditions
[ "$(uname -s)" = "Darwin" ] || die "macOS only"
[ "$(uname -m)" = "arm64" ] || die "Apple silicon only (this builds aarch64-apple-darwin)"
for tool in cargo node npm shasum git; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found (see README, Build from source)"
done

[ -n "${VOUCH_RELEASE_UPDATER_PUBKEYS:-}" ] || die "VOUCH_RELEASE_UPDATER_PUBKEYS is not set (release updater PUBLIC keys)"
case "${VOUCH_RELEASE_UPDATE_URL:-}" in
  https://*) ;;
  *) die "VOUCH_RELEASE_UPDATE_URL must be an https URL" ;;
esac
[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ] || die "TAURI_SIGNING_PRIVATE_KEY is not set (the release updater key; environment only)"
# The variable holds either the key itself or a path to it. A path must not point into the repository.
if [ -f "$TAURI_SIGNING_PRIVATE_KEY" ]; then
  keydir="$(cd "$(dirname "$TAURI_SIGNING_PRIVATE_KEY")" && pwd)"
  case "$keydir/" in
    "$root"/*) die "the updater key file is inside the repository; keep it outside (for example in your keychain or ~/.vouch-keys)" ;;
  esac
fi
# every entry must decode to a minisign PUBLIC key (a private key pasted here would end up inside the app)
node -e '
  for (const k of process.env.VOUCH_RELEASE_UPDATER_PUBKEYS.split(",")) {
    const text = Buffer.from(k.trim(), "base64").toString("utf8");
    if (!/minisign public key/.test(text) || /secret key/i.test(text)) process.exit(1);
  }
' || die "VOUCH_RELEASE_UPDATER_PUBKEYS must hold minisign PUBLIC keys only (base64, comma-separated)"

# keep the key out of the environment until the bundler needs it
signing_key="$TAURI_SIGNING_PRIVATE_KEY"
signing_key_password="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD

if [ -n "$(git status --porcelain)" ]; then
  die "the working tree has changes; release from a clean checkout of the commit you mean to ship"
fi
version="$(node -p 'require("./client/pool-app/src-tauri/tauri.conf.json").version')"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected app version '$version'"
# Not "client-v<version>": pushing that tag starts the release workflow on GitHub Actions. This tag does not match it.
tag="client-macos-v$version"
commit="$(git rev-parse HEAD)"
repo="${RELEASE_REPO:-MetehanAydemir/vouch-client}"
base="${RELEASE_BASE_URL:-https://github.com/$repo/releases/download/$tag}"
case "$base" in https://*) ;; *) die "RELEASE_BASE_URL must be https" ;; esac

target=aarch64-apple-darwin
bundle_dir="client/target/$target/release/bundle"
out="client/target/release-macos/$version"

echo "release-macos: Vouch Compute $version ($tag) at ${commit:0:12}, target $target"

# Temporary config overlays live next to tauri.conf.json (relative paths resolve there) and are removed on exit.
src_tauri="client/pool-app/src-tauri"
release_conf="$src_tauri/tauri.release.local.conf.json"
signing_conf="$src_tauri/tauri.signing.local.conf.json"
cleanup() { rm -f "$root/$release_conf" "$root/$signing_conf"; }
trap cleanup EXIT

# ------------------------------------------------------------------------------------------------ build
(cd client && bash ci/release-guard.sh)

# the release overlay with the release updater PUBLIC key (updater.rs passes each release key explicitly; this is
# only the plugin's config default, so no placeholder ships)
node -e '
  const fs = require("fs");
  const c = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  c.plugins.updater.pubkey = process.env.VOUCH_RELEASE_UPDATER_PUBKEYS.split(",")[0].trim();
  fs.writeFileSync(process.argv[2], JSON.stringify(c, null, 2));
' "$src_tauri/tauri.release.conf.json" "$release_conf"
# no Developer ID: ad-hoc signature ("-"), as the release workflow does while MACOS_SIGNING is off
echo '{"bundle":{"macOS":{"signingIdentity":"-"}}}' > "$signing_conf"

rm -rf "$bundle_dir" "$out"
(
  cd client/pool-app
  npm ci --no-audit --no-fund
  # CI=true skips the Finder layout step of the DMG bundler (it waits on an Automation prompt otherwise)
  TAURI_SIGNING_PRIVATE_KEY="$signing_key" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$signing_key_password" \
    CI=true POOL_RELEASE=1 npx tauri build --target "$target" --bundles app,dmg \
    --config "src-tauri/$(basename "$release_conf")" --config "src-tauri/$(basename "$signing_conf")"
)

# ------------------------------------------------------------------------------------------------ checks
(cd client && bash ci/release-marker-check.sh "target/$target/release/bundle" pool-app/src-tauri/binaries)
if grep -r -a -l -F -e 'updates/vouchcompute-dev' -e 'com.vouchcompute.app.dev' "$bundle_dir"; then
  die "dev updater endpoint or dev bundle id found in the release bundle"
fi
app="$(ls -d "$bundle_dir"/macos/*.app 2>/dev/null | head -1 || true)"
[ -n "$app" ] || die "no .app in $bundle_dir/macos"
codesign --verify --deep --strict "$app" || die "the ad-hoc signature does not verify"
if [ -z "$(ls "$bundle_dir"/macos/*.app.tar.gz.sig 2>/dev/null)" ]; then
  die "no updater signature (.app.tar.gz.sig): was TAURI_SIGNING_PRIVATE_KEY accepted?"
fi
unset signing_key signing_key_password

# ------------------------------------------------------------------------------------------------ collect
# stable, space-free names + latest.json (updater manifest) via the same script the release workflow uses
node client/ci/release-manifest.mjs "$bundle_dir" "$out" "$version" "$base"
tarball="$out/VouchCompute-$version-macos-arm64.app.tar.gz"
cp "$bundle_dir"/macos/*.app.tar.gz.sig "$tarball.sig"
(
  cd "$out"
  rm -f SHA256SUMS
  shasum -a 256 VouchCompute-"$version"-macos-arm64.dmg VouchCompute-"$version"-macos-arm64.app.tar.gz \
    VouchCompute-"$version"-macos-arm64.app.tar.gz.sig latest.json > SHA256SUMS
  shasum -a 256 -c SHA256SUMS >/dev/null
)

notes="$out/RELEASE_NOTES.md"
{
  echo "Vouch Compute $version for macOS (Apple silicon), built from \`$commit\`."
  echo
  echo "**Unsigned build.** The app has no Apple Developer ID signature and is not notarized. On first launch macOS"
  echo "blocks it once: open System Settings > Privacy & Security, find the note about Vouch Compute and click"
  echo "\"Open Anyway\". See the README section \"First launch on macOS\"."
  echo
  echo "Check the download before opening it: \`grep '\.dmg\$' SHA256SUMS | shasum -a 256 -c -\`"
  echo
  echo '```'
  cat "$out/SHA256SUMS"
  echo '```'
  echo
  echo "Updates install only when signed with the project's release updater key (the \`.sig\` file)."
} > "$notes"

echo
echo "release-macos: staged in $out"
ls -l "$out"
echo
echo "Review the files, then publish by hand (a draft first; nothing has been uploaded):"
echo
printf '  gh release create %q --repo %q --draft --target %q --title %q --notes-file %q \\\n' \
  "$tag" "$repo" "$commit" "Vouch Compute $version (macOS, unsigned)" "$notes"
printf '    %q \\\n' "$out/VouchCompute-$version-macos-arm64.dmg" "$tarball" "$tarball.sig" "$out/latest.json"
printf '    %q\n' "$out/SHA256SUMS"
echo
if [[ "$base" == https://github.com/* ]]; then
  echo "Note: release assets of a PRIVATE repository need a GitHub login, so neither users nor the updater can fetch"
  echo "them. Until the repository is public, serve the files from RELEASE_BASE_URL (for example"
  echo "https://downloads.vouchcompute.com/desktop/$version) and rerun with that variable set."
fi
echo "The app's updater reads $VOUCH_RELEASE_UPDATE_URL: copy latest.json there only after the release is checked."
