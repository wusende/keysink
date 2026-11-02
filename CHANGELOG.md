# Changelog

## v0.1.2

*Released 2026-11-02.*

A stability and hardening pass: every request phase is now bounded and the hot
path is cheaper. Drop-in upgrade — no config changes, one new flag.

**Resilience**

- In-flight requests are capped (`--max-concurrent`, default 64); extra requests queue instead of growing memory, and SSE streams never hold a permit
- Connections are capped too, and excess is closed on accept; `EMFILE`/`ENFILE` now backs off a second and keeps serving instead of exiting, with `LimitNOFILE=16384` in the systemd unit
- Every phase has a timeout: 30s to finish request headers, 120s for a trickled body, and a silent upstream mid-body aborts instead of hanging the handler
- Hot-reload failures back off 1s → 30s instead of re-decrypting a corrupt store every second, and decryption runs off the async workers

**Performance**

- `stream` detection answers at the first `stream: true` without parsing the whole body (8MB request: ~100ms → 584ns)
- SSE terminator scanning is SIMD-accelerated (~67× less CPU on the scan path), proxy lookup is lock-free, and audit writes are batched

**Hardening**

- Route config is validated at save time: header values that would 500 every request, and `retry_on_status` outside 400–599 (which could replay POSTs), are rejected up front
- Upstream error logs no longer include the request URL, which could carry the upstream key with `--auth query`

**UX**

- `route add` no longer invents a gateway address when the gateway is down; 401s explain the hot-reload window; `route rm` says what it breaks; hints are platform-correct

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
