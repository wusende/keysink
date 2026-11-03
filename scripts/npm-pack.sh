#!/usr/bin/env bash
# Stage the single npm package under npm/dist/keysink.
#
# Every platform's binary is bundled in vendor/<platform>-<arch>/, so installing
# needs only the npm registry (and its mirrors) — no GitHub, no postinstall, no
# network at install time. The trade-off is a ~16 MB tarball, paid by everyone,
# to avoid a download step that is unreachable behind the GFW.
#
#   scripts/npm-pack.sh                        # fetch assets from GitHub Releases
#   scripts/npm-pack.sh --from-target          # use target/<triple>/release (native only)
#   scripts/npm-pack.sh --from-artifacts DIR   # use the archives uploaded by CI
#   scripts/npm-pack.sh --check-version        # only assert the manifests agree (CI)
#
# Cargo.toml is the only place the version is written: staging stamps it into the
# built manifest and writes it back into the tracked one, and --check-version
# keeps that committed copy honest (CI's write-back never reaches the repo).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
  sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

mode=release
artifacts_dir=
check_version=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check-version) check_version=true ;;
    --from-target) mode=target ;;
    --from-release) mode=release ;;
    --from-artifacts)
      mode=artifacts
      artifacts_dir=${2:-}
      [ -n "$artifacts_dir" ] || { echo "--from-artifacts needs a directory" >&2; exit 2; }
      shift
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
[ -n "$version" ] || { echo "cannot read the package version from Cargo.toml" >&2; exit 1; }

if [ "$check_version" = true ]; then
  NPM_MANIFEST=npm/keysink/package.json NPM_VERSION=$version node -e '
    const fs = require("node:fs");
    const file = process.env.NPM_MANIFEST;
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    if (pkg.version !== process.env.NPM_VERSION) {
      console.error(`${file}: version ${pkg.version} != Cargo.toml ${process.env.NPM_VERSION}`);
      process.exit(1);
    }
  '
  echo "ok: npm/keysink/package.json is $version, matching Cargo.toml"
  exit 0
fi

# Local mode stages only what this machine has built, for testing the launcher;
# release and artifacts mode must cover every platform.
partial=false
[ "$mode" = target ] && partial=true

dist=npm/dist
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rm -rf "$dist"
mkdir -p "$dist/keysink/vendor"

# npm vendor dir | rust target | binary name
platforms=(
  "linux-x64|x86_64-unknown-linux-gnu|keysink"
  "linux-arm64|aarch64-unknown-linux-gnu|keysink"
  "darwin-x64|x86_64-apple-darwin|keysink"
  "darwin-arm64|aarch64-apple-darwin|keysink"
  "win32-x64|x86_64-pc-windows-msvc|keysink.exe"
)

extract() {
  local archive=$1 dest=$2
  mkdir -p "$dest"
  case "$archive" in
    *.zip)
      if command -v unzip >/dev/null; then unzip -q -o "$archive" -d "$dest"
      else tar -xf "$archive" -C "$dest"; fi
      ;;
    *.tar.gz) tar -xzf "$archive" -C "$dest" ;;
    *) echo "unsupported archive: $archive" >&2; return 1 ;;
  esac
}

checksum() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

host=
if [ "$mode" = target ]; then
  host=$(rustc -vV | sed -n 's/^host: //p')
  [ -n "$host" ] || { echo "cannot determine host triple (rustc -vV)" >&2; exit 1; }
fi

echo "staging keysink $version for npm (source: $mode)"

for entry in "${platforms[@]}"; do
  IFS='|' read -r slug target bin <<<"$entry"

  asset="keysink-$target"
  case "$bin" in
    *.exe) asset="$asset.zip" ;;
    *) asset="$asset.tar.gz" ;;
  esac

  dest="$dist/keysink/vendor/$slug"
  mkdir -p "$dest"

  case "$mode" in
    target)
      src="target/$target/release/$bin"
      if [ "$target" = "$host" ] && [ ! -f "$src" ]; then
        src="target/release/$bin"
      fi
      if [ ! -f "$src" ]; then
        if [ "$partial" = true ]; then
          echo "  skipping $slug (no $src)"
          rmdir "$dest" 2>/dev/null || true
          continue
        fi
        echo "missing $src — build that target first" >&2
        exit 1
      fi
      cp "$src" "$dest/$bin"
      ;;
    artifacts)
      archive="$artifacts_dir/$asset"
      [ -f "$archive" ] || { echo "missing $archive" >&2; exit 1; }
      extract "$archive" "$tmp/$slug"
      cp "$tmp/$slug/$bin" "$dest/$bin"
      ;;
    release)
      base="https://github.com/wusende/keysink/releases/download/v$version"
      curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$asset" "$base/$asset"
      curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$asset.sha256" "$base/$asset.sha256"

      expected=$(cut -d' ' -f1 "$tmp/$asset.sha256" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
      actual=$(checksum "$tmp/$asset")
      if [ "$expected" != "$actual" ]; then
        echo "checksum mismatch for $asset: expected $expected, got $actual" >&2
        exit 1
      fi

      extract "$tmp/$asset" "$tmp/$slug"
      cp "$tmp/$slug/$bin" "$dest/$bin"
      ;;
  esac

  [ "$bin" = "keysink.exe" ] || chmod 755 "$dest/$bin"
done

# The launcher package itself: manifest + bin from npm/keysink, README/LICENSE
# for the registry page.
cp -R npm/keysink/. "$dist/keysink/"
cp README.md LICENSE "$dist/keysink/"

sync_manifest() {
  NPM_MANIFEST=$1 NPM_VERSION=$version node -e '
    const fs = require("node:fs");
    const file = process.env.NPM_MANIFEST;
    const version = process.env.NPM_VERSION;
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    const before = pkg.version;
    pkg.version = version;
    fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
    if (before !== version) {
      console.error(`  ${file}: ${before} -> ${version}`);
    }
  '
}

sync_manifest "$dist/keysink/package.json"
sync_manifest npm/keysink/package.json

# Fail before publishing, not after.
NPM_DIST=$dist NPM_VERSION=$version NPM_ALLOW_PARTIAL=$([ "$partial" = true ] && echo 1 || echo 0) node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const dist = process.env.NPM_DIST;
  const version = process.env.NPM_VERSION;
  const allowPartial = process.env.NPM_ALLOW_PARTIAL === "1";
  const pkgDir = path.join(dist, "keysink");
  const problems = [];

  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
  if (pkg.name !== "keysink") problems.push(`package.json says ${pkg.name}`);
  if (pkg.version !== version) problems.push(`version ${pkg.version} != ${version}`);
  if (pkg.optionalDependencies) problems.push("optionalDependencies must be empty (binaries are bundled)");
  if (!fs.existsSync(path.join(pkgDir, "bin", "keysink.js"))) problems.push("bin/keysink.js is missing");

  const expected = [
    ["linux-x64", "keysink"],
    ["linux-arm64", "keysink"],
    ["darwin-x64", "keysink"],
    ["darwin-arm64", "keysink"],
    ["win32-x64", "keysink.exe"],
  ];
  const present = [];
  for (const [slug, bin] of expected) {
    const file = path.join(pkgDir, "vendor", slug, bin);
    if (!fs.existsSync(file)) {
      if (!allowPartial) problems.push(`vendor/${slug}/${bin} is missing`);
      continue;
    }
    const size = fs.statSync(file).size;
    if (size < 1_000_000) problems.push(`vendor/${slug}/${bin} is only ${size} bytes`);
    present.push(slug);
  }

  const total = present.reduce(
    (sum, slug) => sum + fs.statSync(path.join(pkgDir, "vendor", slug, slug === "win32-x64" ? "keysink.exe" : "keysink")).size,
    0,
  );
  if (problems.length) {
    console.error(problems.map((p) => `  - ${p}`).join("\n"));
    process.exit(1);
  }
  const kind = allowPartial ? "partial: local platform only" : "all platforms";
  console.log(`ok: keysink@${version}, ${present.length}/5 platforms, ${(total / 1048576).toFixed(1)} MB unpacked`);
'
