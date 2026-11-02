# Changelog

## Unreleased

**Stability**

- The serve loop now reaps finished connection tasks as they finish (a join
  branch in the accept select). tokio's JoinSet retains every finished task's
  entry until `join_next` consumes it, and it was only joined after the
  accept loop broke — so memory grew with the cumulative number of accepted
  connections over the process lifetime, a few KB per reconnect, even though
  concurrency stayed flat. A long-running gateway slowly ate its own RSS
- Request-head screening (missing/unknown vkey, disabled route, oversized
  declared Content-Length) now happens before the inbound permit is acquired.
  With the permit first, a credential-less flood could pin every permit for
  the body-read timeout each and starve legitimate traffic while it queued.
  Queueing for a permit is also bounded (`PERMIT_QUEUE_TIMEOUT`, 30s): a
  wedged upstream that accepts TCP but never sends response headers holds
  every permit for up to attempts × header_timeout + backoff, and the
  open-ended queue hung agents with no server-side error at all — past the
  bound requests are shed with 503 + `Retry-After: 1`
- Descriptor-pressure accept errors back off on Windows too
  (WSAEMFILE/WSAENOBUFS, previously Unix-only EMFILE/ENFILE — any other
  transient error aborted the whole serve loop there), the 1s backoff sleep
  is interruptible by shutdown, and accepted sockets get a 60s TCP keepalive
  as dead-peer insurance
- Graceful shutdown logs how many connections are still draining, and a
  second SIGINT/SIGTERM exits immediately with code 130: tokio's libc signal
  handler stays registered after the shutdown future resolves, so further
  signals were silently swallowed by a broadcast with no receivers and a
  long-lived SSE stream could pin the drain until SIGKILL
- The audit writer's reopen path no longer asserts an internal invariant
  with `unwrap`

**Security**

- Inbound h2c connections are now keep-alive-probed: the server PINGs after
  30s of silence and closes the connection when the PING is not ACKed within
  15s. The http1 slowloris bound (header_read_timeout) never reached h2
  connections, so an established-but-silent h2 connection held its connection
  slot forever — silently parking max_connections of them was a one-shot
  remote denial of service on an `--allow-remote` deployment. A peer that
  answers the PINGs is actively maintaining the connection and is unaffected
- Starting `serve` on the `.bak` backup (primary store undecryptable) now
  prints a prominent stderr banner with the recovery commands and, on a TTY,
  asks for confirmation — the backup lags one write behind, so vkeys rotated
  or removed since that write would silently work again. Non-interactive
  runs (systemd) keep starting for availability, banner and all;
  `--accept-degraded` skips the prompt
- The audit log now keeps 5 rotated generations (`.1` … `.5`, previously
  just `.1`), and rejected requests (401/403/408/413/…) pass an admission
  gate: one row per second per vkey fingerprint, 100 rows per second
  overall, suppressions counted in the log. Rejection rows are the one audit
  input an unauthenticated peer controls, and at loopback speeds a flood
  used to rotate a whole generation away in about a minute
- `export` output now states that the backup carries the working vkeys of
  every route (it always did; the reminder makes the storage requirement
  explicit), and `init --force` lists the leftover `vault.key.old.*` /
  `vault.age.old.*` pairs — each old key still decrypts its old store, so a
  rebuild done to flush a compromise is not complete until they are deleted

**Performance**

- SSE terminator scanning no longer allocates per chunk: the scan state moved
  into the response stream itself, each upstream chunk is now searched in
  place, and a fixed 40-byte stack window catches markers split across chunk
  boundaries. Previously every chunk of every stream cloned the request id
  String, locked a carry mutex, and copied carry + chunk into a fresh Vec —
  every stream byte copied twice. Marker detection is unit-tested at every
  split point, including byte-by-byte arrival, and the searched needles are
  asserted against the window size so a future longer needle cannot silently
  blind the boundary check
- Upstream response headers are now moved out of the response, hop-by-hop
  entries dropped in place, and the map moved whole into the client response;
  the old path cloned every header twice (once into a fresh HeaderMap, again
  through the response builder)

**Timestamps**

- `route show`'s `created:`, the audit log's `ts` and the log-line prefixes are
  now rendered in the system's local time zone with an explicit offset
  (`2026-11-02T17:46:16+08:00`) instead of always UTC, so they match the wall
  clock on the machine that wrote them. The offset is resolved per instant, so
  entries written across a DST change keep the right offset. Storage is
  unchanged (epoch seconds); `TZ=UTC` restores the old output, and an
  unresolvable zone falls back to UTC rather than dropping the line

## v0.1.3

*Released 2026-11-02.*

Maintenance release plus a new install channel. No behavior changes.

**Install**

- `npm install -g keysink` — one self-contained package carrying the binaries
  for Linux (amd64/arm64), macOS (Intel/Apple Silicon) and Windows (amd64). No
  postinstall download, no Rust toolchain, and it works through registry mirrors

**Dependencies**

- `h2` 0.4.19 → 0.4.20 and `log` 0.4.34 → 0.4.35 (transitive patch updates)

**Metadata**

- crates.io description and keywords now name Claude Code / OpenAI / MCP and
  use `claude-code` instead of the generic `credential`; `development-tools`
  joins the categories. Helps in-site search only

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
