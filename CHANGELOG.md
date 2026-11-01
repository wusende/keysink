# Changelog

## v0.1.1

*Released 2026-11-01.*

Everything since the first tag. The v0.1.0 binaries predate the system-service
commands and the English surface — **this is the release to download**.

- `keysink deploy` / `keysink uninstall`: one-shot system install (system user, 0700 vault dir, systemd unit, `timestamp_timeout=0` sudoers rule) and symmetric removal
- Full English user-facing surface: CLI output, errors, prompts, tracing logs; `README.zh-CN.md` keeps the Chinese docs
- Seeded fuzzing suite — 22 targets over the pure helpers, a vault corruption matrix, and end-to-end fuzz over the real proxy stack — plus the two fixes it surfaced: static `accept-encoding` is no longer re-enabled on streaming requests (it blinded the SSE terminator scan), and oversized scrypt parameters are rejected before allocation (a tampered `password_hash` could force a multi-GB allocation)
- Dependencies on current majors: age 0.12, reqwest 0.13, rand 0.10, base64 0.23, scrypt 0.12, sha2 0.11
- MIT license file, `SECURITY.md` with the threat model and disclosure process, README badges
- Windows test/runtime fixes, arm64 release builds on native runners, CI green on Linux/macOS/Windows (perf budgets now scale for debug builds)
## v0.1.0

*Released 2026-11-01.*

First public release.

**keysink** — a tiny local gateway that keeps real API keys away from your agents: agents only hold revocable virtual keys (`ks_...`); real keys live encrypted in a local vault with no read channel, injected only when forwarding.

- Single static binary: Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64)
- Standalone mode (`keysink serve`); one-shot system install with `sudo keysink deploy` (systemd + sudoers) and symmetric `sudo keysink uninstall`
- age-encrypted vault, key zeroization, 0600/0700 + O_NOFOLLOW hardening (Unix)
- Per-route upstream proxy, SSE pass-through, retry/backoff, hot reload, async audit log

Download the archive for your platform, verify against the matching `.sha256`, put the binary on your `PATH`.

中文说明见 [README.zh-CN.md](https://github.com/wusende/keysink/blob/main/README.zh-CN.md)。
