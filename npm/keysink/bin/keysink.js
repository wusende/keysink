#!/usr/bin/env node
// Launcher for the binary bundled under vendor/<platform>-<arch>/.
// Arguments, stdio, signals and the exit code pass straight through, so in a
// script `keysink status` behaves exactly like the native binary.
//
// Every platform ships inside the package (see scripts/npm-pack.sh): installing
// needs only the npm registry, never GitHub, and runs no install scripts.
//
// Dependency-free CommonJS on purpose: this runs before anything else is
// installed and must survive every npm/pnpm/yarn node version.

"use strict";

const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const HOMEPAGE = "https://github.com/wusende/keysink";
const KEY = `${process.platform}-${process.arch}`;
const SUPPORTED = new Set([
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
]);

function bail(reason) {
  process.stderr.write(
    `keysink: ${reason}\n\n` +
      `Install from source instead (needs a Rust toolchain):\n` +
      `  cargo install keysink\n\n` +
      `Prebuilt binaries: ${HOMEPAGE}/releases\n`,
  );
  process.exit(1);
}

// A glibc build started under musl fails with a bare "ENOENT" on exec, which
// reads like a broken install; name the real cause instead.
function isMusl() {
  if (process.platform !== "linux") return false;
  try {
    return process.report.getReport().header.glibcVersionRuntime === undefined;
  } catch {
    return false;
  }
}

if (!SUPPORTED.has(KEY)) {
  bail(`no prebuilt binary for ${KEY}`);
}
if (isMusl()) {
  bail(`${KEY} is a glibc build and this system uses musl (Alpine?)`);
}

const BIN = path.join(
  __dirname,
  "..",
  "vendor",
  KEY,
  process.platform === "win32" ? "keysink.exe" : "keysink",
);

if (!fs.existsSync(BIN)) {
  bail(`${BIN} is missing (corrupt install? try: npm rebuild keysink)`);
}

const child = spawn(BIN, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: false,
});

// The terminal already signals the whole process group on Ctrl-C, but npm's
// shim can run us detached; forwarding keeps one behaviour either way.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  try {
    process.on(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  } catch {
    // Windows has no SIGHUP; ignore.
  }
}

child.on("error", (error) => {
  bail(`failed to start ${BIN}: ${error.message}`);
});

child.on("exit", (code, signal) => {
  if (signal) {
    const number = os.constants.signals[signal];
    process.exit(number ? 128 + number : 1);
  }
  process.exit(code === null ? 1 : code);
});
