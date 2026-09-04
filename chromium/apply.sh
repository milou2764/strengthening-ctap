#!/usr/bin/env bash
#
# Applies the CTAP client-authentication modifications to a Chromium checkout.
#
#   ./apply.sh /path/to/chromium/src
#
# Copies the new files into the tree and applies the patch to existing files.
# Base version: Chromium 154.0.8014.0.

set -euo pipefail

CHROMIUM_SRC="${1:-}"
if [[ -z "$CHROMIUM_SRC" || ! -d "$CHROMIUM_SRC" ]]; then
  echo "usage: $0 /path/to/chromium/src" >&2
  exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Copying new files into $CHROMIUM_SRC ..."
cp -Rv "$DIR/new-files/." "$CHROMIUM_SRC/"

echo "Applying patch ..."
if git -C "$CHROMIUM_SRC" apply --check "$DIR/patches/ctap-client-auth.patch" 2>/dev/null; then
  git -C "$CHROMIUM_SRC" apply "$DIR/patches/ctap-client-auth.patch"
else
  echo "  (git apply --check failed; trying a 3-way / patch fallback)"
  git -C "$CHROMIUM_SRC" apply --3way "$DIR/patches/ctap-client-auth.patch" || \
    patch -p1 -d "$CHROMIUM_SRC" < "$DIR/patches/ctap-client-auth.patch"
fi

echo
echo "Done. Next:"
echo "  cd $CHROMIUM_SRC"
echo "  gn gen out/Default"
echo "  autoninja -C out/Default chrome"
echo
echo "Run with:  --enable-features=WebAuthnCtapClientIdentity --user-data-dir=/tmp/ctap-profile"
