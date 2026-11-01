# Changelog

## Unreleased

Stability fixes from a performance/stability review:

- Non-streaming responses now abort when the upstream goes silent mid-body (per-chunk read idle, aligned with the response-header timeout): an upstream that sent headers and then stalled used to hang the handler forever — blocking the connection, its memory, and graceful shutdown with it. SSE streams keep their own 60s idle; the header wait keeps its 120s `header_timeout`
- Store hot-reload decryption (file I/O + age decrypt + JSON parse + validate) now runs on tokio's blocking pool instead of a worker thread: a slow disk or a large vault no longer stalls concurrent request forwarding for the duration of a reload
- Repeated hot-reload failures back off exponentially (1s → 30s cap) instead of re-reading and re-decrypting a corrupt store every second forever; any success restores the 1s poll
- Inbound reads are now time-bounded: a client that stalls mid-request-head (slowloris) is disconnected after 30s — the serve loop drives hyper-util's auto builder directly because `axum::serve` exposes no `header_read_timeout` — and a handler reading a trickled request body gives up with `408 request_timeout` after 120s. Both matter mainly with `--allow-remote`; streaming responses are unaffected
- SSE terminator scanning is memchr-accelerated: the case-insensitive fallback swept the whole scan window byte-by-byte on every chunk of every stream until the terminator showed up; it now SIMD-scans for the marker's first byte in either case and verifies only those candidates — same matching semantics, ~67x less CPU on the scan path (2MB chunk: 1.8ms → 27µs)
- Proxy client lookup for per-route upstream proxies is now lock-free (ArcSwap copy-on-write): no per-request mutex on proxied routes
- Audit lines batch in an 8KB buffer (flushed at capacity, when the queue goes idle for 50ms, before rotation, and on shutdown) instead of one write syscall per line; `tail -f` tail latency stays bounded
- Per-request retry policy override no longer allocates (retryable statuses are an Arc'd slice)

UX fixes from a scenario-based review (fresh install → route add → agent onboarding → key rotation → revocation → recovery):

- `route add` no longer prints a fabricated default address (`127.0.0.1:8787`) when the gateway is not running — it reports the address as unknown and points at `keysink serve`; the `TOKEN=` line (shown only once) is still printed (`current_gateway` now returns `Option`)
- The unknown-vkey 401 error body now mentions the hot-reload window: a vkey added/rotated a second ago is indistinguishable from an invalid one, and the old message blamed a rotation that never happened
- `--home` help text states the platform's real default (`~/.local/share/keysink` on macOS, `%LOCALAPPDATA%\keysink` on Windows) instead of the Linux-only `/var/lib/keysink`
- `route rm` output states the consequence (vkey stops working immediately) and how to re-create the route
- Port-in-use hint on `serve` is platform-appropriate (`lsof` on macOS, `systemctl`/`ss` on Linux) instead of always suggesting systemctl
- README "Everyday commands" lists `keysink init`, the first entry point in scripts / headless environments

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
