# Changelog

## Unreleased

**Security**

- `serve` calls `prctl(PR_SET_DUMPABLE, 0)` at startup on Linux, so a process
  running as the same user can no longer read the gateway's memory through
  `/proc/<pid>/mem` or attach a debugger to pull real keys out of it
  (`PTRACE_ATTACH` and `/proc/<pid>/{environ,mem,maps}` now fail with `EPERM`
  for same-uid readers, whatever `kernel.yama.ptrace_scope` says). Only the
  process holding the keys can do this: `execve(2)` resets the flag, so a
  launcher cannot do it on someone else's behalf. Best effort — a kernel that
  refuses logs a warning instead of stopping the gateway. It does not protect
  the vault files: `vault.key` is still only as private as its file mode
  (see `deploy`)

**Docs**

- The README is now the front page — what it is, what it protects and does not,
  install, a five-minute quick start — and the rest moved to `docs/`: `usage.md`
  (routing, commands, health fields, vault, FAQ), `service.md` (`deploy`),
  `security.md` (threat model, audit log, bounds), `performance.md`. Nothing was
  dropped; the Chinese README mirrors the new shape and points at the same docs
- The README gains a "same user, not same process" section: an agent runs as
  your uid, so the channels a local gateway does not close by itself are your
  files (`vault.key` → offline decrypt) and your `/proc`. Both hit `keysink`
  standalone; `deploy` closes the file one
- The self-scored comparison table is gone. It lined keysink up against tools
  that solve different problems, on rows keysink chose, and won every row; a
  reader learns nothing from that. "What this is not" stays and now names the
  alternative per bullet, including the case where a plain `.env` is the
  simpler answer
- `docs/perf-test-plan.md` now exists: the scenario matrix, metric
  definitions and aggregation behind `scripts/perf.sh` lived only in script
  comments, and two of those comments pointed at this file before it was
  ever committed
- The README gains a measured performance baseline (one machine, one run;
  `scripts/perf.sh` reproduces it on your own hardware) and a pre-1.0 note
  that the CLI surface may still change between releases; the Chinese README
  picks up the docs.rs and Platforms badges the English one already had

## v0.2.2

*Released 2026-11-07.*

A hardening and observability pass from a full review of the 0.2.1 commit
series: every phase that could still hold a resource indefinitely got a bound,
the vault refuses to act on stale or foreign state, and the health endpoint
grows a `healthy` flag separate from liveness so a gateway serving a stale
backup stops looking ready.

One operational note: `route rm` now requires `--yes` when stdin is not a
terminal (removing a route destroys its route-only key). Scripts that removed
routes must add `--yes`; `route disable` remains the reversible alternative.
Drop-in otherwise — no config or storage changes.

**Stability**

- Every forwarded request has a whole-forward budget (10 minutes): each
  attempt's header wait, the backoff sleeps and the retryable-body drains are
  clamped to it. `header_timeout` alone bounds one attempt, so a route with
  `max_retries = 10` could hold an inbound permit for ~20 minutes, and
  `--max-concurrent` such requests wedged the gateway with no client-visible
  error. The budget ends the retry ladder as a 504, and a Retry-After longer
  than the remaining budget sleeps only until the deadline
- A connection that never sends its first request is closed at the head
  timeout. hyper completes the h2 handshake only after the peer's SETTINGS
  frame, and the h2 keep-alive PING starts only after that — a peer sending
  just the 24-byte preface (or stalling inside SETTINGS) held its connection
  slot forever, a one-shot remote DoS on `--allow-remote` deployments. A
  middleware notifies once the first request is dispatched and the deadline is
  disarmed; the per-request bounds and the h2 keep-alive own the connection
  from there
- The audit close is bounded (3s). The writer does blocking file I/O, and on a
  hung mount `join()` never returned, holding shutdown until the service
  manager SIGKILLed the process — losing the very flush the close exists for.
  Past the timeout the thread is detached with a warning (tail lines may be
  lost; health already reported the failure)
- A failed signal-handler registration is no longer treated as a shutdown
  request: the old code let `if let Ok(...)` fall through and resolved the
  shutdown future immediately at startup. On failure the arm parks, leaving
  the other signal (and SIGTERM/SIGKILL from the service manager) in charge
- A read-only vault directory no longer stops `serve` at the `gateway.addr`
  write. The address file is a convenience for `route add`; failing to record
  it now logs a warning and the gateway keeps serving

**Security**

- `export` refuses an `--output` that names a vault file — across canonical,
  parent-canonical and lexical spellings. `--output <vault>/vault.age` was the
  original hole (`atomic_write` would have replaced the store and left the
  backup as the only copy); the first guard compared path parents, and since
  `std::path::absolute` keeps `..` components, `<vault>/sub/../vault.age`
  slipped through it, as did a vault directory reached through a symlink. The
  guard now compares every name each path can denote
- Vault writes are refused while the store is being served from the stale
  `.bak` fallback. Writing from the one-generation-behind backup silently
  revived revoked/rotated vkeys and destroyed the evidence of whatever broke
  the primary; the fallback exists for a running gateway's availability, not
  for a write. Read-only commands still work, with a warning naming both files
- `init` and `rekey` refuse while `KEYSINK_MASTER_KEY` /
  `KEYSINK_MASTER_KEY_FILE` is configured. Both replace `vault.key`, and the
  running gateway keeps using the external identity — the new store would be
  undecryptable for it. Rotate the external credential first
- `uninstall` only deletes a directory that actually looks like a keysink
  vault (marker files, or the `init --force` `.old.*` leftovers), and refuses
  a symlinked `--home`. The path comes straight from `--home` /
  `KEYSINK_VAULT_HOME` and the command recursively deletes it; a typo
  (`--home .`) used to erase whatever was there. System installs are anchored
  at the deploy path and skip the marker check
- Route-only keys are validated at save time for the auth types that inject
  them verbatim into a header (`bearer` / `x-api-key` / custom header): a
  control character (a newline from a multi-line pipe) used to pass validation
  and turn every request on the route into a 500 at forward time. `basic`
  base64-encodes the pair, `query` percent-encodes the value, `none` never
  injects it — those accept the same bytes
- `--password-stdin` and `--route-key -` read exactly one line.
  `read_to_string` used to swallow a multi-line pipe and turn the extra lines
  into part of the secret (a key with newlines then failed in every forwarded
  header; a password just silently differed from what was meant)
- vkeys must be base64url. The well-formedness check was prefix + length, so a
  hand-edited store with `+`/`/`/`=` in the token passed and produced a vkey no
  client could ever send; the character set now fails loudly at startup
- `Route`'s `Debug` redacts the route-only key and masks the vkey. A derived
  impl put the real upstream credential into every `{:?}` — a fuzz artifact, a
  panic message, a log line added later. `headers` / `proxy` / `note` print
  as-is, matching what `route show` already shows the vault's owner
- The synthetic SSE error tail follows the stream's observed dialect: an
  `auto` stream that showed Anthropic `event: message_start` lines gets an
  Anthropic-shaped error event when truncated, instead of an OpenAI
  `data: [DONE]` tail the client cannot parse. Best-effort on purpose (a
  marker split across chunks is missed and the old behavior remains); explicit
  terminators are never overridden

**Observability**

- `/__keysink/health` reports a `healthy` flag separate from `ok`. `ok` says
  the process answers; `healthy` says it is serving data it can trust — it
  goes false when the snapshot came from the stale backup, the hot reload
  keeps failing, the audit writer cannot write, or the watcher stopped
  ticking (`watcher_age_secs` is new). Point liveness probes at `ok`, alerting
  and readiness at `healthy`
- `serve` verifies both audit rotation chains are openable for append at
  startup and refuses to start otherwise; `Audit::new` used to accept an
  unwritable path and the gateway ran "audited" while dropping every row. A
  write failure at runtime turns `audit_ok` false until the write path
  recovers — the writer probes the chains on its idle tick, so an idle gateway
  recovers too, and the next record re-verifies (previously the flag cleared
  only on the next successful record, so a zero-traffic gateway stayed
  unhealthy forever after its disk healed)
- With audit off, rejected requests no longer build an `AuditEntry` (RFC3339
  timestamp + several Strings) or take the rejection-gate mutex: a credential
  flood on an audit-off gateway used to pay that per request for rows that can
  never be written

**Performance**

- The hot-reload fingerprint drops the `.bak` stat. Every write that touches
  `.bak` also rewrites the live store (`save_store` backs up, then writes;
  `rekey` touches both), so including it only made one logical change look
  like two and triggered a second, redundant reload

**Docs**

- User-facing errors name `vault.key` / `vault.age` instead of the retired
  `master.key` / `store.age` names
- The README states what `export` actually is: a configuration backup (routes
  and metadata, real keys stripped) that can be neither dropped in as
  `vault.age` nor decrypted into a working vault — the copy that restores is
  `vault.key` + `vault.age`
- Both READMEs rewritten where they read badly: the health fields are a bullet
  list instead of one sentence with six nested parentheticals, the worst
  translationese sentences are rewritten, and the English 401 FAQ is corrected
  (an upstream 401 means the request was forwarded, not that it "never reached
  the vault" — the Chinese README already had it right)

**Packaging**

- `rust-version = "1.89"` is declared: edition 2024 needs 1.85, the let-chains
  used throughout are 1.88+, and the vault transaction lock (`std::fs::File::lock`)
  is stable since 1.89 — `cargo install` now fails with the real requirement
  instead of a wall of syntax errors

**Tests**

- New regressions: an h2 handshake stall must be dropped within the head
  timeout; a retry storm must end at the whole-forward budget; the export
  guard must catch `..` spellings and symlinked vault directories; `route rm`
  must check existence before confirmation; audit health must recover via the
  idle probe without new traffic; the symlink-refusal test no longer assumes
  the umask; the smoke script asserts rejection rows land on the `.rej` chain
  and clears `NO_PROXY` so the dead-proxy fallback case tests what it says

## v0.2.1

*Released 2026-11-05.*

A security-hardening and performance pass: the request-escape and header-echo
channels found in the audit are closed, rejection rows can no longer wash out
the forensic trail, and the audit write path shed its locks and clones.
Drop-in upgrade — no config or storage changes.

**Security**

- Request paths containing dot segments are refused with a 404 instead of
  forwarded. `build_upstream_url` concatenated base + path verbatim, and the
  downstream URL parser (reqwest/url) then removes dot segments while
  resolving the final URL — so `GET /../admin/x` against a route with
  `base_url …/v1` reached `/admin/x` upstream, and `/v1/%2e%2e/x` escaped the
  same way (the RFC 3986 double-dot definition includes the `%2e` variants;
  the WHATWG parser additionally treats `\` as a path separator for http(s)).
  A vkey's reach is now the route's base_url prefix, matching what the docs
  always implied. Locked in by a fuzz invariant that parses the built URL the
  way reqwest will and asserts the resolved path stays inside the base
  prefix, plus unit tests for every collapsible dot-segment form
- `CONNECT`/`TRACE`/`TRACK` are refused with a 405 (plus `Allow`). A TRACE the
  upstream implements would echo the forwarded headers — the injected real
  key included — back into the agent's view, the one channel that defeats the
  "real key never reaches the agent" model; CONNECT was meaningless without
  the already-refused Upgrade support
- Rejection audit rows moved to their own rotation chain (`<audit-file>.rej`,
  5 × 10 MB). The per-fingerprint throttle keys on the rejected token's
  fingerprint, so a flood of *randomized* fake vkeys evaded it entirely and
  could rotate away the whole 60 MB forensic trail in ~35 minutes at the 100
  rows/s global cap — the README claimed it couldn't, and that claim was
  wrong. Rejections keep the same admission gates but can now only evict
  their own chain; the main chain's line format is byte-identical for
  existing consumers (the `rejected` flag is serialized only on the reject
  chain)

**Hardening**

- `OPTIONS *` (asterisk-form) is refused with a 400 client error instead of
  surfacing as a 500 `configuration_error` from the URL builder
- `anthropic-api-key` and `openai-api-key` are accepted as inbound vkey
  headers, matching the outbound strip list: a client sending only one of
  them used to get a misleading 401 while the gateway stripped the same
  names on the way out
- `KEYSINK_MASTER_KEY_FILE` now gets the same file checks as the default
  `vault.key`: symlinks and group/other-readable identities are refused
  (0400/0600 pass — systemd `LoadCredential` credentials qualify). The env
  path used to skip both checks entirely
- `decrypt` caps the ciphertext at 64 MiB before handing it to age. A
  replaced `vault.age` already implies a same-UID compromise (out of scope),
  but age's reader grows the plaintext without bound; the cap keeps a wedged
  hot reload from turning one bogus file into an OOM
- `create_private_dir_all` refuses a pre-existing symlink instead of
  resolving through it and landing the 0700 chmod on the symlink's target
- The atomic-write temp name carries 8 random bytes instead of 4 — the old
  65536-name space was predictable enough for a hostile local process to
  pre-occupy and fail every vault write

**Performance**

- The audit write path is lock-free: the writer handle moved from
  `Mutex<Option<Writer>>` to an `ArcSwapOption` sender, so `is_enabled` +
  `record` are two atomic loads per audited request instead of two mutex
  acquisitions and a sender clone. The writer thread's join handle parks
  beside the slot and `close()` keeps its drain-then-join semantics (an
  in-flight record holds the channel open through its own Arc, so tail rows
  still land). Measured 7.7ms → 3.6ms for 5k records; the audit-on/audit-off
  throughput gap narrowed from ~3% to ~1%
- Timestamp rendering reuses the resolved UTC offset for one second: the time
  crate re-reads `TZ` / `/etc/localtime` on every `local_offset_at` call, which
  used to run once per audit row and once per log line. Historical display
  (`ts`) keeps per-instant resolution, so a DST switch can carry the
  pre-switch offset for at most one second of rows — and the offset is part of
  the rendered string, so every instant stays unambiguous either way
- Rejected requests allocate nothing: method/path/query stay borrowed views
  into the request parts, and the upstream key is read straight from the
  snapshot's route table instead of cloned per request (accepted requests
  clone only what goes on the wire)
- `Authorization: Bearer` tolerates extra whitespace between the scheme and
  the token (RFC 7235 wants exactly one SP; some clients send more). A glued
  `Bearer ks_…` is still not recognized as the Bearer scheme
- Dependencies: tokio's features narrowed from `full` to the set in use —
  keeping `parking_lot` explicitly, because dropping it with the rest of
  `full` measurably cost ~4% on the 80k-rps request ladder (tokio compiles its
  runtime and sync primitives against parking_lot when the feature is
  present); and fs2 (unmaintained) dropped for std's `File::lock` (stable
  since 1.89, the same blocking exclusive flock on unix / LockFileEx on
  windows), which also removes fs2's three `winapi` leftovers from the tree

## v0.2.0

*Released 2026-11-04.*

A stability and observability pass: the two remaining ways a single misbehaving
peer could stall the whole gateway are closed, shutdown is bounded instead of
relying on SIGKILL, and the states that used to fail silently (a stale snapshot,
a dead audit writer, a panic) now report themselves. Drop-in upgrade — no config
or storage changes.

One operational note for system installs: the systemd unit is written to disk at
`deploy` time, so upgrading the binary alone leaves the old unit in place. Re-run
`sudo keysink deploy` to pick up `TimeoutStopSec` 10 → 30; without it a drain
that runs near its 10s bound can still be SIGKILLed by the old stop timeout.

**Stability**

- The retry path's response-body discard is bounded. A `429`/`503`/`504` whose
  body then stalled parked the handler — and its inbound permit — forever: the
  discard read used the non-streaming client, which deliberately carries no
  client-level read timeout, and nothing else bounded that drain. `max_concurrent`
  such responses turned the gateway into 503s for every other request. The drain
  now gives up at the read idle and drops the connection instead of reusing it
- A non-streaming response body is bounded as a whole (`BODY_TOTAL_BUDGET`, 10
  minutes) on top of the per-chunk read idle. An upstream trickling a byte just
  under the idle bound was "alive" forever and held its connection slot for the
  process lifetime; streaming (SSE) bodies are still exempt by design —
  including a content-encoded stream's passthrough fallback, which used to
  inherit the 10-minute budget by mistake
- Shutdown is propagated into every live connection. hyper's connection future
  does not stop on its own, so a draining gateway kept answering *new* requests
  on existing keep-alive connections, and an idle keep-alive socket held the
  drain until its 30s header timeout expired — measured at 28s per stop, past the
  unit's `TimeoutStopSec`, i.e. every restart ended in SIGKILL (losing the audit
  flush and the runtime-file cleanup). Each connection now gets
  `graceful_shutdown` (http1 `Connection: close`, h2 `GOAWAY`), and the drain is
  bounded by `--drain-timeout-secs` (default 10, `0` = wait forever): past it the
  remaining connections are dropped with a warning. An idle keep-alive connection
  now closes immediately (measured: 0.05s vs 28s)
- `TimeoutStopSec` in the deployed unit goes 10 → 30, above the drain timeout, so
  a normal stop no longer gets SIGKILLed before the drain can finish. Existing
  installs pick this up on the next `sudo keysink deploy` (the unit is written to
  disk then, not shipped inside the binary)
- Accept errors are split three ways instead of "descriptor pressure or fatal".
  Linux and the BSDs pass per-connection failures from the backlog up through
  `accept(2)` (an aborted handshake, protocol/route errors) and document that
  they should be retried like EAGAIN; treating them as fatal turned one dropped
  handshake into a full gateway restart. Resource-pressure errors (EMFILE,
  ENFILE, ENOBUFS, ENOMEM — the last two are kernel memory pressure, where an
  immediate retry would just spin) back off 1s, and only genuinely
  listener-level errors end the serve loop
- A panic in a connection task is no longer invisible: the reaping arm logs the
  `JoinError` (previously discarded with `let _ = res`), and a process-wide panic
  hook reports panics through tracing before the default handler prints them
- The store watcher runs under a supervisor: if the watcher task dies it is
  restarted instead of silently leaving the gateway on a snapshot nothing tracks,
  and a watcher that stops ticking is reported with its tick age
- The audit writer backs off on write failures (doubling, capped at 5s) instead of
  attempting a failed open plus a warn line per record — a full disk used to cost
  a syscall spin and a log flood. The backoff wait drains the queue (counting the
  drops) and exits immediately on `close()`
- Log output goes through a bounded, non-blocking writer thread. `fmt()`'s default
  writer is synchronous on the emitting thread, so a slow consumer (journald, a
  full pipe, a paused terminal) could block a tokio worker inside a `write`
  syscall on the per-request warn paths; the request path is now a `try_send`, and
  a full queue drops lines (counted) instead of stalling the gateway. The queue is
  drained at exit (a bounded flush marker, also before a second-signal `exit`),
  a dead writer counts as drops, and the drop report can no longer panic when
  stderr is gone too
- Upstream connection pool idle timeout 90s → 30s: a pooled connection the peer
  already closed fails the next request that picks it, and a POST is not replayed,
  so the agent saw a 502 for a request that never reached the upstream
- `--listen 127.0.0.1:0` records the bound port in `gateway.addr` instead of `:0`
  (it wrote the *requested* address, so `route add` reported a bogus gateway)
- Startup warns when `--body-limit-mb × --max-concurrent` reaches 2 GiB, the
  worst-case amount of request bodies buffered at once

**Observability**

- `/__keysink/health` now reports `snapshot_age_secs`, `reload_failures`,
  `reload_attempts`, `audit`, `audit_ok`, `audit_dropped`, `shed_connections`
  and `accept_errors`. The gateway answers with the last good snapshot even
  while the hot reload is failing (a broken vault, permissions, a watcher that
  stopped), so "it answers" used to be the only signal — a rotated key still
  working was the next one. Per-connection accept errors are retried in place
  (visible before only when they were wrongly fatal), so the counter is the
  only trace they leave at info level after the first warn
- A dead audit writer thread is reported instead of silently dropping every line:
  `audit_ok:false` on health plus one error line, with `closed` distinguished from
  `died` so shutdown stays quiet

**Tests**

- New regression tests: the retry-discard path with a stalled body must not wedge
  the handler; an idle keep-alive connection must not delay shutdown and must be
  closed by it; finished connection tasks must be reaped (the gauge fails if the
  reaping arm is disabled, verified by removing it); the total body budget; the
  accept-error classification; the audit writer's liveness and backoff; the
  health payload's reload/audit fields

## v0.1.5

*Released 2026-11-03.*

Docs only — no code changes.

- Quick start now notes that `cargo install` puts the binary in `~/.cargo/bin`,
  which sudo can't see, so `sudo keysink deploy` has to be spelled
  `sudo ~/.cargo/bin/keysink deploy`.
- The Linux service section spells out `sudo -u keysink /usr/local/bin/keysink …`.
  The previous `sudo -u keysink keysink …` failed for the same reason: sudo's
  `PATH` doesn't include `/usr/local/bin`.

## v0.1.4

*Released 2026-11-03.*

A stability, security and throughput pass: a long-running gateway no longer
creeps up in memory, every request phase is bounded, and the hot path allocates
less per request, per streamed chunk and per forwarded header. Drop-in upgrade —
no config or storage changes.

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

- The per-request "forwarding request" log line is now `debug` instead of
  `info`: at ~60k RPS the info line wrote ~12MB/s of log (6.4GB over a
  10-minute soak) and its formatting plus stdout-lock cost measurably capped
  throughput. The audit log (`--audit-log`) remains the per-request record;
  `RUST_LOG=keysink=debug` restores the line for troubleshooting — update any
  monitoring that counted these lines
- With audit off (the default), successful requests no longer construct an
  audit entry at all: the entry's RFC3339 local-time format and its handful
  of String allocations were pure waste on that path; an `is_enabled()`
  check (the writer is fixed at startup, so it cannot flip mid-request)
  skips them
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

**Dependencies**

- `cc` 1.10.0 → 1.11.0 and `ctutils` 0.4.7 → 0.4.8 (transitive patch updates)

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
