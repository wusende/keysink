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
streaming has started. Most naive proxies get this wrong and you pay for it twice.

And the part it's named after: an agent that gets prompt-injected can leak
everything in its environment — but the real key was never in there.

## Quick start

1. Install — either way:

   ```bash
   cargo install keysink      # from crates.io, needs a Rust toolchain
   ```

   or grab the binary for your platform from
   [Releases](https://github.com/wusende/keysink/releases) — Linux / macOS /
   Windows, amd64 / arm64 — and put it on your `PATH`.

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

   It prints the two lines your agent needs. Routes hot-reload into a running
   gateway within ~1s, so adding one never requires a restart.

4. Point your agent at it:

   ```
   BASE_URL=http://127.0.0.1:8787
   TOKEN=ks_...
   ```

   Claude Code: `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` in `settings.json`.
   Other clients: provider `base_url` + `apiKey`.

   The vkey rides in whatever header your client already sends — `Authorization:
   Bearer`, `x-api-key`, `x-goog-api-key` or `api-key` — so for most clients this
   is a base-URL change and nothing else. Your existing client code, SDK and auth
   flow stay untouched.

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

Because the vkey picks the route, "which upstream does this agent talk to" is a
keysink-side decision, not a client-side one. Two agents on the same port can
talk to two different providers, or to the same provider with different keys.

## Everyday commands

```
keysink init                     # first entry point in scripts / headless environments (interactive serve auto-initializes)
keysink route add|ls|show|rotate|update|rm|enable|disable
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE] [--max-concurrent N]
keysink status | doctor
keysink export --output FILE      # needs master password; strips all key values
keysink rekey [--yes]             # rotate the vault master key
keysink deploy | uninstall        # system install / symmetric removal
```

Route options worth knowing:

- `--auth bearer|x-api-key|header|basic|query|none` — OpenAI is Bearer, Claude
  `x-api-key`, Gemini `x-goog-api-key`. For anything else use `--auth header`
  plus `--auth-header NAME` and optional `--auth-prefix 'Bearer '`
- `--header 'K:V'` injects static headers (repeatable); `--proxy URL|direct` sets
  a per-route upstream proxy, defaulting to `HTTP(S)_PROXY`
- `--retry-on-status CODE` overrides the retryable set per route (400..=599)

## Where the vault lives

`~/.local/share/keysink` (Windows: `%LOCALAPPDATA%\keysink`; system installs:
`/var/lib/keysink`). Move it with `--home` or `KEYSINK_VAULT_HOME`.

The master password is only used to encrypt and restore `export` backups —
serving, adding, rotating and disabling keys never ask for it, so a daemon
restart can't be blocked by a forgotten password.

## Linux system service

```bash
sudo keysink deploy
```

One shot: creates the `keysink` system user and a 0700 vault dir, installs the
binary to `/usr/local/bin/keysink`, writes the systemd unit and the sudoers rule
(for the admin who ran sudo), initializes the vault interactively (hidden
password, entered twice), then enables the service. Idempotent — re-running
upgrades in place and restarts. Removal is symmetric: `sudo keysink uninstall`.

The unit refuses to start until the vault exists (`ConditionPathExists`). Without
a terminal, init manually:

```bash
runuser -u keysink -- /usr/local/bin/keysink --home /var/lib/keysink init
```

Admin commands then go through `sudo -u keysink keysink …`; each invocation
re-authenticates (`timestamp_timeout=0`), so an agent cannot silently run them.

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
headers, body or query. Off by default.

`--listen` will bind a non-loopback address if you insist, but then TLS and
network exposure are yours to solve; the intended deployment is loopback only.
Everything a request touches is bounded by default — body size, in-flight
requests, connections, time — so a hung upstream or a misbehaving agent can't
take the gateway down.

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

- **One vault per user, not per directory.** The gateway runs as a daemon while
  the CLI is invoked from anywhere; a CWD-relative vault would mean a different
  vault per directory, routes would "vanish", and hot reload would break. Use
  `--home` / `KEYSINK_VAULT_HOME` when you want another location.
- **The hardening needs a directory it controls.** `0700`/`0600`,
  `O_NOFOLLOW` and owner checks only mean something in a dedicated directory.
  CWD has arbitrary permissions and may well be a git repo or a synced folder
  where `vault.key` + `vault.age` leak.
- **It's where the OS expects app data** — XDG `$XDG_DATA_HOME`,
  `%LOCALAPPDATA%`, `/var/lib` for services. Same convention as `~/.ssh`,
  `~/.gnupg` or `/var/lib/docker`.

**Is a local proxy a single point of failure?**

It's a local process, so yes — if it's down, requests fail. `keysink status`
reports the live listen address and probes reachability, and under systemd the
unit restarts on failure. The vault is plain files, so a crash never loses keys.

## Development

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # end-to-end: fake upstream, forwarding / SSE / retry / hot-reload / export stripping
```

`cargo test` includes a seeded fuzz suite (22 targets over the pure helpers, a
vault corruption matrix, and end-to-end fuzz against a mock upstream) plus
budgeted performance scenarios. Pushing a `v*` tag makes GitHub Actions build and
publish release artifacts for all platforms.
