# Usage

[← README](../README.md)

Routing, commands, the health endpoint and the vault on disk. For service
deployment see [service.md](service.md); for the threat model see
[security.md](security.md).

## How routing works

One loopback port serves every route. The **vkey in the request selects the
route**, and the route carries everything upstream-specific: base URL, auth
style (`bearer` / `x-api-key` / custom header / `basic` / query param), static
headers to inject, retry policy, and an optional per-route upstream proxy.

Inbound auth headers are stripped and rebuilt from the route, so a client can
never smuggle its own credentials through. Everything else (method, path, body,
`Accept`, streaming) is passed through unchanged, and the query string is
preserved with the auth parameter managed by the route. SSE chunks are
forwarded as they arrive instead of being buffered into a whole response.

Two kinds of requests are refused outright even in passthrough mode. A request
path containing dot segments (`..`, `%2e%2e`, or their `\`-separated forms) gets
a 404: the downstream URL parser collapses those, and forwarding one would let a
request escape the route's base_url prefix on the upstream host. `CONNECT`,
`TRACE` and `TRACK` get a 405: a TRACE the upstream implements would echo the
forwarded headers, real key included, back to the caller.

`--auth` describes keysink → upstream only. Inbound, the vkey is accepted in any
of `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `api-key`,
`anthropic-api-key` or `openai-api-key` (the same names stripped before
forwarding), so the client's auth style and the route's never have to match.

Two agents on the same port can talk to two different providers, or to the same
provider with different keys, without either of them knowing.

## Retries

`429`/`503`/`504` are retried twice. A POST whose network call failed is never
replayed, and nothing is retried once SSE streaming has started — a replayed
POST is a second charge on your bill. `--retry-on-status CODE` replaces the
retryable set for a route (400..=599).

## Everyday commands

```
keysink init                     # first entry point in scripts / headless environments (interactive serve auto-initializes)
keysink route add|ls|show|rotate|update|rm|enable|disable
# `route rm` destroys the route-only key, so it asks for confirmation
# (`--yes` in scripts); `route disable` keeps the key and just stops serving it
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE] [--max-concurrent N] [--accept-degraded]
keysink status | doctor
keysink export --output FILE      # needs master password; strips all key values
keysink rekey [--yes]             # rotate the vault master key
keysink deploy | uninstall        # system install / symmetric removal
```

Useful route options:

- `--auth bearer|x-api-key|header|basic|query|none`: OpenAI is Bearer, Claude
  `x-api-key`, Gemini `x-goog-api-key`. For anything else use `--auth header`
  plus `--auth-header NAME` and optional `--auth-prefix 'Bearer '`
- `--header 'K:V'` injects static headers (repeatable), a fallback rather than
  an override: if the client sends the same header, the client's value wins.
  Only the auth header names are protected (they cannot be set statically at
  all); treat this as route defaults, never as enforcement;
  `--proxy URL|direct` sets a per-route upstream proxy, defaulting to
  `HTTP(S)_PROXY`
- `--retry-on-status CODE` overrides the retryable set per route (400..=599)

Common moves:

```bash
keysink route update claude --base-url https://api.openai.com     # switch upstream
printf %s "$NEW_KEY" | keysink route update claude --route-key -   # swap the real key
keysink route rotate claude                                       # new vkey, old one stops working
```

## Health, status, doctor

`status` prints the vault summary (home, schema, route count). `doctor` runs the
integrity checks (owner, permissions, key parses, store decrypts, backup
decrypts) and is what to run when something looks wrong.

To check the gateway itself, `GET /__keysink/health` returns
`{"ok":true,"healthy":true,"degraded":false,"version":"0.2.2","uptime_secs":…,"routes":2}`,
plus the state that used to be invisible:

- `snapshot_age_secs`: how long the served snapshot has been in place. The
  watcher only reloads on vault changes, so on a stable vault this grows with
  uptime; it reports data freshness, not watcher health, so don't alert on it.
- `reload_failures` / `reload_attempts`: the actual reload signals. Failures
  keep climbing while the vault stays broken (e.g. undecryptable).
- `watcher_age_secs`: how long since the store watcher last ticked.
- `shed_connections` / `accept_errors`: connection-cap and per-connection
  accept-error counts.
- `audit` / `audit_ok` / `audit_dropped`: a dead audit writer or a failed audit
  write reports `audit_ok:false` instead of silently dropping every line; when
  the write path recovers, the writer probes on its idle tick and the flag
  turns back on.

`ok` only says the process answers; `healthy` says it is serving data it can
trust. It goes false when the snapshot came from the stale backup, the hot
reload keeps failing, the audit writer cannot write, or the watcher stopped
ticking. Point liveness probes at `ok` (never restart a gateway that is still
answering) and alerting/production-readiness at `healthy`.

`--accept-degraded` covers a broken vault: when the primary store fails to
decrypt, the gateway can start from `vault.age.bak` instead. That backup is one
write behind, so vkeys rotated or deleted since then work again. This is a
stopgap to keep agents running, not a steady state. `doctor` tells you which
file is bad and how to restore it.

## Where the vault lives

`~/.local/share/keysink` (Windows: `%LOCALAPPDATA%\keysink`; system installs:
`/var/lib/keysink`). Move it with `--home` or `KEYSINK_VAULT_HOME`.

The master password only protects `export` backups (and is verified before one
is written). Serving, adding, rotating and disabling keys never ask for it, so
a daemon restart can't be blocked by a forgotten password.

`export` is a **configuration** backup, not a restorable vault: it contains the
routes (base URLs, auth method, retry policy, vkeys) with every real key
stripped, so it can neither be dropped in as `vault.age` nor decrypted into a
working vault. Recovery is manual: `age -d` it, then re-create the routes and
re-enter each key with `route update <name> --route-key -`. The copy that
actually restores is `vault.key` + `vault.age`, so back those two up.

`vault.key` is a plain age identity file (`0600`), not something the master
password protects: the vault's protection is file mode plus a separate UID, so
an agent running as the same user can decrypt it offline. For services, the
identity can live outside the vault directory: `KEYSINK_MASTER_KEY` (inline age
identity) or `KEYSINK_MASTER_KEY_FILE` (path to one); that is what systemd's
`LoadCredential` wants.

## FAQ

**Why isn't the vault in the current directory?**

One vault per user, not per directory. The gateway runs as a daemon while the
CLI is invoked from anywhere, so a CWD-relative vault would mean a different
vault per directory, routes that "vanish", and broken hot reload. The hardening
needs a directory it controls too: `0700`/`0600`, `O_NOFOLLOW` and owner checks
only mean something in a dedicated directory, while a CWD may well be a git repo
or a synced folder where `vault.key` + `vault.age` leak. It is also where the OS
expects app data (XDG `$XDG_DATA_HOME`, `%LOCALAPPDATA%`, `/var/lib` for
services, same convention as `~/.ssh` or `/var/lib/docker`). Use `--home` /
`KEYSINK_VAULT_HOME` when you want another location.

**Is a local proxy a single point of failure?**

It's a local process, so yes: if it's down, requests fail. `GET
/__keysink/health` says whether it's up and whether it's serving a stale backup;
under systemd the unit restarts on failure. The vault is plain files, so a crash
never loses keys.

**My agent gets 401 — is the vkey wrong or the real key?**

keysink's own 401 has a JSON body from keysink and an `x-keysink-request-id`
header, e.g. `{"error":{"type":"authentication_error","message":"virtual key is
invalid or has been rotated …"}}`. A bad *real* key comes back from the upstream
instead: same status, but the body is the provider's own error, which means the
request was forwarded.
