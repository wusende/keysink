#!/usr/bin/env bash
# Publish the staged package (npm/dist/keysink).
#
#   scripts/npm-publish.sh              # publish (needs npm login + 2FA code)
#   scripts/npm-publish.sh --dry-run    # show what would be uploaded
#   scripts/npm-publish.sh --otp 123456
#
# Re-running is safe: if the version is already on the registry it is skipped,
# so an expired 2FA code halfway through the upload costs nothing.
#
# In CI this runs with npm's trusted publishing (OIDC) instead of a token; see
# npm/README.md.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d npm/dist/keysink ]; then
  echo "npm/dist/keysink is missing — run scripts/npm-pack.sh first" >&2
  exit 1
fi

dry_run=false
for arg in "$@"; do
  [ "$arg" = "--dry-run" ] && dry_run=true
done

name=$(node -p "require('./npm/dist/keysink/package.json').name")
version=$(node -p "require('./npm/dist/keysink/package.json').version")

if [ "$dry_run" = false ] && npm view "$name@$version" version >/dev/null 2>&1; then
  echo "skip $name@$version (already published)"
  exit 0
fi

echo "publishing $name@$version"
if [ "$#" -gt 0 ]; then
  npm publish npm/dist/keysink --access public "$@"
else
  npm publish npm/dist/keysink --access public
fi
