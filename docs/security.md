# Security model

[← README](../README.md)

## What the gateway can see

| Channel | What it can see |
|---|---|
| `route ls` / `route show` | masked vkey, no real key |
| CLI | no read command exists |
| `export` backup | routes and metadata, key values stripped |
| agent process / env / logs | only the vkey |
| upstream | the real key, injected at forward time |

Vault files are age-encrypted, `0600`/`0700`, owned by the service user. Any of
`authorization`, `x-api-key`, `x-goog-api-key`, `api-key`, `anthropic-api-key`,
`openai-api-key` arriving from the client is dropped before forwarding. Root
that can read both `vault.key` and `vault.age` can still decrypt offline;
machine-level isolation stays your job (tight sudo, separate UID). On Linux
`serve` also makes its own memory unreadable to its uid (`PR_SET_DUMPABLE = 0`,
see below) and logs a warning if the kernel refuses.

## The other channels: same user, not same process

An agent runs as you, so it has your file permissions and your `/proc`.
Measured on Linux with agent and gateway under the same uid:

| What the agent runs | What it gets |
|---|---|
| `cat token.txt`, `.env`, `~/.config/*/credentials` | plaintext — the key was never in a vault |
| `age -d -i vault.key vault.age` | the whole vault, if `vault.key` is readable |
| `tr '\0' '\n' < /proc/<pid>/environ` | whatever a launcher injected into a sibling process |
| `/proc/<pid>/mem`, `gdb -p`, `strace -p` | a running program's memory, real keys included |

The first two rows are why `deploy` matters beyond autostart: `vault.key` is a
plain age identity, so file mode protects nothing against the user who owns it.
`deploy` puts the vault under a dedicated `keysink` uid (`0700`), routes admin
commands through `sudo -u keysink` with `timestamp_timeout=0`, and runs the
gateway as that uid — the agent cannot read any of it.

The last two rows are why `serve` hardens itself at startup: it calls
`prctl(PR_SET_DUMPABLE, 0)` on Linux, after which same-uid processes get
`EPERM` on `/proc/<pid>/{environ,mem,maps}` and on `PTRACE_ATTACH`, whatever
`kernel.yama.ptrace_scope` says. It has to be the process holding the keys:
`execve(2)` resets the flag to 1, so a launcher cannot do it on someone else's
behalf. macOS (`task_for_pid`) and Windows (`SeDebugPrivilege`) already refuse
same-user memory reads.

Standalone `serve` in your own uid leaves the vault files readable to the agent.
On a machine where the agent runs as you, use `deploy`, or run it under a
different user. macOS has no service mode, so there the boundary can only come
from the agent's uid.

## Audit log

`--audit-log` records route, vkey fingerprint, status and latency, never
headers, body or query. Off by default. Five rotated generations (10 MB each)
are kept for real traffic. Rejected requests are throttled (1/s per fingerprint,
100/s globally) and written to their own rotation chain (`<audit-file>.rej`,
another 5 × 10 MB); a flood of unauthenticated requests can only ever cycle its
own logs, never the record of real traffic. `serve` verifies both files are
openable for append at startup and refuses to start otherwise; a write failure
at runtime turns `audit_ok` false until the path is writable again: the writer
probes on its idle tick, so an idle gateway recovers too, and the next record
re-verifies it.

## Bounds

`--listen` will bind a non-loopback address if you insist, but then TLS and
network exposure are yours to solve; the intended deployment is loopback only.

Nothing is unbounded: 32 MB bodies (`--body-limit-mb`), 64 in-flight requests
(`--max-concurrent`), a capped connection count, per-phase timeouts, and 30s to
finish reading http1 request heads. A non-streaming response body is bounded per
chunk and as a whole, so an upstream trickling a byte a minute cannot hold a
connection forever; an h2 connection that stops answering keep-alive PINGs, or
one that stalls inside the handshake, is closed at the head timeout. A hung
upstream or a misbehaving agent can't take the gateway down.

Every forwarded request also has a whole-forward budget (10 minutes): retry
attempts, backoff sleeps and retryable-body drains share it, so a route with a
large `--max-retries` cannot hold an inbound slot for tens of minutes.

Shutdown is graceful and bounded: `serve` stops accepting, tells every live
connection to finish and close (`Connection: close`, h2 `GOAWAY`), and drains
for at most `--drain-timeout-secs` (default 10, `0` = wait forever) before
dropping what is left with a warning. Idle keep-alive sockets close
immediately, so a restart no longer waits out a 30s header timeout; the systemd
unit's `TimeoutStopSec=30` is the backstop above that. The store watcher is
supervised too: if it dies it is restarted, and if it stops ticking the log says
so.
