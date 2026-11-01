# keysink

English | [简体中文](README.zh-CN.md)

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/wusende/keysink/releases/latest)

A tiny local gateway that keeps real API keys away from your agents. The agent only ever holds a revocable virtual key (`ks_...`); keysink stores the real keys encrypted on your machine and injects them only when forwarding a request.

There is **no read channel for real keys**: the CLI cannot print them, backups strip them, and the gateway binds loopback only.

## Quick start (download & run)

1. Grab the binary for your OS from [Releases](https://github.com/wusende/keysink/releases) — Linux / macOS / Windows, amd64 / arm64. Make it executable and put it on your `PATH`.

2. Start the gateway (standalone mode — no root, no service):

   ```bash
   keysink serve
   # first run: interactive init (set a master password), then the gateway starts
   ```

3. Add a route (another terminal):

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # guided prompts: name → base URL → upstream auth → key (hidden input)
   # non-interactive:  printf %s "$KEY" | keysink route add claude --base-url ... --auth x-api-key
   ```

   `route add` prints the two lines your agent needs. Routes hot-reload into a running gateway within ~1s.

4. Point your agent at it:

   ```
   BASE_URL=http://127.0.0.1:8787
   TOKEN=ks_...
   ```

   Claude Code: `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` in `settings.json`. Other clients: provider `base_url` + `apiKey`.

Vault lives at `~/.local/share/keysink` (Windows: `%LOCALAPPDATA%\keysink`). Move it with `--home` or `KEYSINK_VAULT_HOME`. The master password is only used to encrypt/restore `export` backups — serving, adding and rotating keys never ask for it.

## Linux system service (systemd)

```bash
sudo keysink deploy
```

One shot — the binary installs itself: creates the `keysink` system user and a 0700 vault dir, copies this binary to `/usr/local/bin/keysink`, writes the systemd unit and the sudoers rule (for the admin invoking sudo), initializes the vault interactively (hidden password, entered twice), then enables the service. Idempotent — re-running upgrades in place and restarts. Removal is symmetric: `sudo keysink uninstall`.

The unit refuses to start until the vault exists (`ConditionPathExists`). Without a terminal, init manually:

```bash
runuser -u keysink -- /usr/local/bin/keysink --home /var/lib/keysink init
```

Admin commands then go through `sudo -u keysink keysink ...`; each invocation re-authenticates (`timestamp_timeout=0`), so agents can't silently run them.

## Everyday commands

```
keysink route add|ls|show|rotate|update|rm|enable|disable
keysink serve [--listen 127.0.0.1:8787] [--audit-log FILE]
keysink status | doctor
keysink export --output FILE      # needs master password; strips all key values
keysink rekey [--yes]             # rotate the vault master key
keysink uninstall [--yes]         # remove the vault; system installs also lose unit/sudoers/binary
keysink deploy                    # one-shot system install (Linux + systemd, via sudo)
```

Route options worth knowing:

- `--auth bearer|x-api-key|<custom-header>|basic|query|none` — OpenAI uses Bearer, Claude `x-api-key`, Gemini `x-goog-api-key`
- `--header 'K:V'` injects static headers; `--proxy URL|direct` sets a per-route upstream proxy (default: follow `HTTP(S)_PROXY`)
- Retries 429/503/504 twice; POST network errors are never replayed (no double billing); no retries once SSE streaming has started

## Security model: keys go in, they don't come out

| Channel | Key values |
|---|---|
| `route ls` / `route show` | masked |
| CLI read command | does not exist |
| `export` backup | stripped by design |
| agent process | only ever sees the vkey |
| upstream | real key injected at forward time; inbound auth headers stripped |

Vault files are age-encrypted, 0600/0700, owned by the service user. Root that can read both `vault.key` and `vault.age` can still decrypt offline — machine-level isolation stays your job (tight sudo, separate UID). Optional `--audit-log` records route, vkey fingerprint, status and latency — never headers, body or query.

Limitations: one upstream + one key per route (no pools / failover); audit off by default.

## FAQ

**Why isn't the vault stored in the current directory?**

The vault lives at `~/.local/share/keysink` (Windows: `%LOCALAPPDATA%\keysink`, system installs: `/var/lib/keysink`) on purpose:

- **One vault per user, not per directory.** The gateway runs as a daemon while the CLI is invoked from anywhere. A CWD-relative vault would give you a different vault per directory — routes would "vanish" and hot-reload would break. Use `--home` or `KEYSINK_VAULT_HOME` when you explicitly want another location.
- **The security model needs a directory it controls.** The 0700/0600, `O_NOFOLLOW` and owner-follow checks only mean something in a dedicated directory. CWD has arbitrary permissions — and may well be a git repo or a cloud-synced folder where `vault.key` + `vault.age` could leak.
- **It's where the OS expects app data.** XDG `$XDG_DATA_HOME` on Linux/macOS, `%LOCALAPPDATA%` on Windows, `/var/lib` for system services (FHS) — the same convention as `~/.ssh`, `~/.gnupg` or `/var/lib/docker`.

## Development

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # end-to-end: fake upstream, forwarding / SSE / retry / hot-reload / export stripping
```

Pushing a `v*` tag makes GitHub Actions build and publish release artifacts for all platforms.
