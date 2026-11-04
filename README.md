# keysink

English | [简体中文](README.zh-CN.md)

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keysink.svg)](https://crates.io/crates/keysink)
[![docs.rs](https://img.shields.io/docsrs/keysink)](https://docs.rs/keysink)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/wusende/keysink/releases/latest)

A small local gateway that keeps your real API keys out of your agents. The
agent gets a revocable virtual key (`ks_…`); keysink holds the real key in an
encrypted local vault and swaps it in only at forward time.

```
agent ──ks_…──▶ keysink :8787 ──real key──▶ upstream
```

There is **no read channel for real keys**: the CLI cannot print them, `export`
backups strip them, and the gateway binds loopback only.

## Why bother

**Change a key without touching an agent.** Your agent config pins one base URL
and one `ks_…` token, once. Switching provider, account or real key afterwards is
`keysink route update` — routes hot-reload into the running gateway in about a
second. No config edit, no agent restart.

**One real key, many revocable virtual keys.** Give each agent its own route:
same upstream, separate vkey, independent lifecycle. Rotate or disable one and
the others keep working.

**Retries that don't double-bill.** `429`/`503`/`504` are retried twice, but a
POST whose network call failed is never replayed, and nothing is retried once SSE
streaming has started. A replayed POST is a second charge on your bill.

And the name: a prompt-injected agent can dump everything in its environment, and
the real key was never in it.

## Quick start

1. Install — any of these:

   ```bash
   npm install -g keysink     # prebuilt binary, no toolchain
   cargo install keysink      # from crates.io, needs a Rust toolchain
   ```

   `cargo install` lands in `~/.cargo/bin`, which sudo can't see. So if you later
   run `sudo keysink deploy`, use `sudo ~/.cargo/bin/keysink deploy`.

   Prebuilt binaries are also on
   [Releases](https://github.com/wusende/keysink/releases) — Linux / macOS /
   Windows, amd64 / arm64 — put one on your `PATH`. The npm package is a thin
   launcher around that same binary; Linux x86_64 needs glibc 2.35+, arm64 needs
   2.39+, and anything uncovered (musl/Alpine, Windows arm64) falls back to
   `cargo install`.

2. Start the gateway (standalone mode — no root, no service):

   ```bash
   keysink serve
   # first run: interactive init (set a master password), then the gateway starts
   ```

3. Add a route, in another terminal:

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # guided prompts: name → base URL → upstream auth → key (hidden input)
   # non-interactive: printf %s "$KEY" | keysink route add claude --base-url … --auth x-api-key
   ```

   It prints the vkey and the two lines your agent needs:

   ```
   route `claude` created (key goes in, never out: cannot be read/exported)
   auth: x-api-key    base_url: https://api.anthropic.com
   vkey: ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   (vkey is shown only this once; if lost, only `keysink route rotate claude` can issue a new one)
   gateway: http://127.0.0.1:8787 (running)
   agent-side config (OpenAI-compatible clients usually need /v1 in base_url):
     BASE_URL=http://127.0.0.1:8787
     TOKEN=ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   ```

   Routes hot-reload into a running gateway within ~1s, so adding one never
   requires a restart.

4. Point your agent at it:

   ```
   BASE_URL=http://127.0.0.1:8787
   TOKEN=ks_...
   ```

   Claude Code: `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` in `settings.json`.
   Other clients: provider `base_url` + `apiKey`.

   The vkey rides in whatever header your client already sends — `Authorization:
   Bearer`, `x-api-key`, `x-goog-api-key` or `api-key` — so for most clients this
   is a base-URL change and nothing else.

## How routing works

One loopback port serves every route. The **vkey in the request selects the
route**, and the route carries everything upstream-specific: base URL, auth style
(`bearer` / `x-api-key` / custom header / `basic` / query param), static headers
to inject, retry policy, and an optional per-route upstream proxy.

Inbound auth headers are stripped and rebuilt from the route, so a client can
never smuggle its own credentials through. Everything else — method, path, body,
`Accept`, streaming — is passed through unchanged, and the query string is
preserved with the auth parameter managed by the route. SSE chunks are forwarded
as they arrive instead of being buffered into a whole response.

Two edge refusals keep that passthrough honest: a request path containing dot
segments (`..`, `%2e%2e`, or their `\`-separated forms) gets a 404 — the
downstream URL parser collapses those, and forwarding one would let a request
escape the route's base_url prefix on the upstream host. `CONNECT`, `TRACE` and
`TRACK` get a 405 — a TRACE the upstream implements would echo the forwarded
headers, real key included, back to the caller.

`--auth` describes keysink → upstream only. Inbound, the vkey is accepted in any
of `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `api-key`,
`anthropic-api-key` or `openai-api-key` — the same names stripped before
forwarding — so the client's auth style and the route's never have to match.

Two agents on the same port can talk to two different providers, or to the same
provider with different keys, without either of them knowing.

## Everyday commands

```
keysink init                     # first entry point in scripts / headless environments (interactive serve auto-initializes)
keysink route add|ls|show|rotate|update|rm|enable|disable
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE] [--max-concurrent N] [--accept-degraded]
keysink status | doctor
keysink export --output FILE      # needs master password; strips all key values
keysink rekey [--yes]             # rotate the vault master key
keysink deploy | uninstall        # system install / symmetric removal
```

Route options worth knowing:

- `--auth bearer|x-api-key|header|basic|query|none` — OpenAI is Bearer, Claude
  `x-api-key`, Gemini `x-goog-api-key`. For anything else use `--auth header`
  plus `--auth-header NAME` and optional `--auth-prefix 'Bearer '`
- `--header 'K:V'` injects static headers (repeatable) — a fallback, not an
  override: if the client sends the same header, the client's value wins.
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

`status` prints the vault summary (home, schema, route count). `doctor` runs the
integrity checks — owner, permissions, key parses, store decrypts, backup
decrypts — and is what to run when something looks wrong.

To check the gateway itself, `GET /__keysink/health` returns
`{"ok":true,"degraded":false,"version":"0.2.0","uptime_secs":…,"routes":2}`,
plus the state that used to be invisible: `snapshot_age_secs` (how long the
served snapshot has been in place — the watcher only reloads on vault changes,
so on a stable vault this grows with uptime; it reports data freshness, not
watcher health, so don't alert on it), `reload_failures` / `reload_attempts`
(the actual reload signals: failures climbs while the vault stays broken, e.g.
undecryptable), `shed_connections` / `accept_errors` (connection-cap and
per-connection accept-error counts), and `audit` / `audit_ok` /
`audit_dropped` (a dead audit writer reports `audit_ok:false` instead of
silently dropping every line).

`--accept-degraded` covers a broken vault: when the primary store fails to
decrypt, the gateway can start from `vault.age.bak` instead. That backup is one
write behind, so vkeys rotated or deleted since then work again — a stopgap to
keep agents running, not a state to stay in. `doctor` tells you which file is
bad and how to restore it.

## Where the vault lives

`~/.local/share/keysink` (Windows: `%LOCALAPPDATA%\keysink`; system installs:
`/var/lib/keysink`). Move it with `--home` or `KEYSINK_VAULT_HOME`.

The master password is only used to encrypt and restore `export` backups —
serving, adding, rotating and disabling keys never ask for it, so a daemon
restart can't be blocked by a forgotten password.

`vault.key` is a plain age identity file (`0600`), not something the master
password protects: the vault's protection is file mode plus a separate UID. For
services, the identity can live outside the vault directory — `KEYSINK_MASTER_KEY`
(inline age identity) or `KEYSINK_MASTER_KEY_FILE` (path to one), which is what
systemd's `LoadCredential` wants.

## Linux system service

```bash
sudo keysink deploy
```

One shot: creates the `keysink` system user and a 0700 vault dir, installs the
binary to `/usr/local/bin/keysink`, writes the systemd unit and the sudoers rule
(for the admin who ran sudo), initializes the vault interactively (hidden
password, entered twice), then enables the service. Idempotent — re-running
upgrades in place and restarts. Removal is symmetric: `sudo keysink uninstall`.

The unit refuses to start until the vault exists (`ConditionPathExists`). With no
terminal on the deploy host, init manually — interactively:

```bash
sudo -u keysink /usr/local/bin/keysink --home /var/lib/keysink init
```

or fully headless (`init` refuses to prompt without a TTY, so pipe the password):

```bash
printf '%s\n' "$MASTER_PASSWORD" | sudo -u keysink /usr/local/bin/keysink \
  --home /var/lib/keysink init --password-stdin
```

Admin commands then go through `sudo -u keysink /usr/local/bin/keysink …`; each
invocation re-authenticates (`timestamp_timeout=0`), so an agent cannot silently
run them.

## Security model

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
that can read both `vault.key` and `vault.age` can still decrypt offline —
machine-level isolation stays your job (tight sudo, separate UID).

`--audit-log` records route, vkey fingerprint, status and latency — never
headers, body or query. Off by default. Five rotated generations (10 MB each)
are kept for real traffic. Rejected requests are throttled (1/s per
fingerprint, 100/s globally) and written to their own rotation chain
(`<audit-file>.rej`, another 5 × 10 MB) — a flood of unauthenticated requests
can only ever rotate its own trail away, never the forensic record of real
traffic.

`--listen` will bind a non-loopback address if you insist, but then TLS and
network exposure are yours to solve; the intended deployment is loopback only.

Nothing is unbounded: 32 MB bodies (`--body-limit-mb`), 64 in-flight requests
(`--max-concurrent`), a capped connection count, per-phase timeouts, and 30s to
finish reading http1 request heads. A non-streaming response body is bounded
both per chunk and as a whole, so an upstream that trickles a byte a minute
cannot hold a connection forever. An h2 connection that stops answering
keep-alive PINGs is closed. A hung upstream or a misbehaving agent can't take
the gateway down.

Shutdown is graceful and bounded: `serve` stops accepting, tells every live
connection to finish and close (`Connection: close`, h2 `GOAWAY`), and drains
for at most `--drain-timeout-secs` (default 10, `0` = wait forever) before
dropping what is left with a warning. Idle keep-alive sockets close
immediately, so a restart no longer waits out a 30s header timeout; the
systemd unit's `TimeoutStopSec=30` is the backstop above that. The store
watcher is supervised too: if it dies it is restarted, and if it stops ticking
the log says so.

## What this is not

- Not a secret manager: one user, no RBAC, no HA, no KMS integration.
- Not an LLM gateway: no token accounting, budgets, model routing, caching or
  rate limiting. If you want those, put LiteLLM or one-api next to it.
- Not multi-machine: one process, one host, loopback.
- Not key pools: one upstream and one key per route, no failover.
- Not a sandbox for the agent: a vkey is a capability. `route disable` /
  `rotate` is how you take it back.

## FAQ

**Why isn't the vault in the current directory?**

One vault per user, not per directory. The gateway runs as a daemon while the CLI
is invoked from anywhere, so a CWD-relative vault would mean a different vault
per directory, routes that "vanish", and broken hot reload. The hardening needs
a directory it controls too: `0700`/`0600`, `O_NOFOLLOW` and owner checks only
mean something in a dedicated directory, while a CWD may well be a git repo or a
synced folder where `vault.key` + `vault.age` leak. It is also where the OS
expects app data (XDG `$XDG_DATA_HOME`, `%LOCALAPPDATA%`, `/var/lib` for
services — same convention as `~/.ssh` or `/var/lib/docker`). Use `--home` /
`KEYSINK_VAULT_HOME` when you want another location.

**Is a local proxy a single point of failure?**

It's a local process, so yes — if it's down, requests fail. `GET
/__keysink/health` says whether it's up and whether it's serving a stale backup;
under systemd the unit restarts on failure. The vault is plain files, so a crash
never loses keys.

**My agent gets 401 — is the vkey wrong or the real key?**

keysink's own 401 has a JSON body from keysink and an `x-keysink-request-id`
header, e.g. `{"error":{"type":"authentication_error","message":"virtual key is
invalid or has been rotated …"}}`. A bad *real* key comes back from the upstream
instead — same status, but the body is the provider's own error, and the request
never reached the vault.

## Development

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # end-to-end: fake upstream, forwarding / SSE / retry / hot-reload / export stripping
```

`cargo test` includes a seeded fuzz suite (22 targets over the pure helpers, a
vault corruption matrix, and end-to-end fuzz against a mock upstream) plus
budgeted performance scenarios. Pushing a `v*` tag makes GitHub Actions build and
publish release artifacts for all platforms, plus the npm packages once
`NPM_PUBLISH` is enabled — see `npm/README.md`.
