# keysink

English | [简体中文](README.zh-CN.md)

[![CI](https://github.com/wusende/keysink/actions/workflows/ci.yml/badge.svg)](https://github.com/wusende/keysink/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keysink.svg)](https://crates.io/crates/keysink)
[![docs.rs](https://img.shields.io/docsrs/keysink)](https://docs.rs/keysink)
[![Release](https://img.shields.io/github/v/release/wusende/keysink)](https://github.com/wusende/keysink/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/wusende/keysink/releases/latest)

> Pre-1.0: the CLI and route surface may still change between releases; each
> release's operational notes are in the [changelog](CHANGELOG.md).

A small local gateway that keeps your real API keys out of your agents. The
agent gets a revocable virtual key (`ks_…`); keysink holds the real key in an
encrypted local vault and swaps it in only at forward time.

```
agent ──ks_…──▶ keysink :8787 ──real key──▶ upstream
```

## The threat this exists for

Agents read untrusted content all day: web pages, issue threads, tool outputs,
fetched documents. A single prompt injection away, `env | curl …` walks your
real key out the door, and you find out from the bill.

There is **no read channel for real keys**: the CLI cannot print them, `export`
backups strip them, and the gateway binds loopback only. A dumped environment
is a dumped `ks_…` — revocable in one command while the rest of your setup
keeps working.

One real key can back many routes: each agent gets its own `ks_…`, and rotating
a key or switching provider is `keysink route update` — routes hot-reload in
about a second, so the agent's config is pinned once.

### The other channels

An agent runs as you, so it also has your files and your `/proc`. Measured on
Linux, agent and gateway under the same uid:

| What the agent runs | What it gets |
|---|---|
| `cat token.txt`, `.env`, `~/.config/*/credentials` | plaintext — the key was never in a vault |
| `age -d -i vault.key vault.age` | the whole vault, if `vault.key` is readable |
| `tr '\0' '\n' < /proc/<pid>/environ` | whatever a launcher injected into a sibling process |
| `/proc/<pid>/mem`, `gdb -p`, `strace -p` | a running program's memory, real keys included |

`deploy` closes the first two rows with a dedicated uid for the vault. `serve`
closes the last two on Linux — `prctl(PR_SET_DUMPABLE, 0)` at startup, so
same-uid reads of `/proc/<pid>/*` and `ptrace` get `EPERM`. Neither helps if
both run in your own uid: then the vault files are simply shared.
[docs/security.md](https://github.com/wusende/keysink/blob/main/docs/security.md)
has the details and what to do about them.

## How it compares

| | keysink | .env in agent config | LiteLLM / one-api | Vault / Infisical |
|---|---|---|---|---|
| Real key absent from agent env | ✅ never enters | ❌ sits in env | ⚠️ still holds upstream keys | ⚠️ agent fetches real keys |
| One-way (no key read/export path) | ✅ | ❌ | ❌ | ❌ |
| Per-agent revocable credential | ✅ vkey | ❌ | ⚠️ virtual keys, but key store holds real ones | ✅ |
| Swap provider / rotate key, agent untouched | ✅ hot-reload ~1s | ❌ edit + restart | ⚠️ | ⚠️ |
| Runs without a server or KMS | ✅ one binary, loopback | ✅ | ❌ | ❌ |
| Retries that don't double-bill | ✅ | — | ⚠️ | — |

## Quick start

1. Install — any of these:

   ```bash
   npm install -g keysink     # prebuilt binary, no toolchain
   cargo install keysink      # from crates.io, needs a Rust toolchain
   ```

   `cargo install` lands in `~/.cargo/bin`, which sudo can't see. So if you
   later run `sudo keysink deploy`, use `sudo ~/.cargo/bin/keysink deploy`.
   Prebuilt binaries are also on
   [Releases](https://github.com/wusende/keysink/releases) (Linux / macOS /
   Windows, amd64 / arm64) — put one on your `PATH`. Linux x86_64 needs glibc
   2.35+, arm64 needs 2.39+; anything uncovered (musl/Alpine, Windows arm64)
   falls back to `cargo install`.

2. Start the gateway (standalone — no root, no service):

   ```bash
   keysink serve      # first run: interactive init (set a master password), then the gateway starts
   ```

3. Add a route, in another terminal:

   ```bash
   keysink route add claude --base-url https://api.anthropic.com
   # guided prompts: name → base URL → upstream auth → key (hidden input)
   # non-interactive: printf %s "$KEY" | keysink route add claude --base-url … --auth x-api-key
   ```

   It prints the vkey (only this once) and the two lines your agent needs:

   ```
   vkey: ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
     BASE_URL=http://127.0.0.1:8787
     TOKEN=ks_R6OpUgxRjVnuCwISI0_BgtAi1E8FGUILJHQouA50tYc
   ```

   Routes hot-reload into a running gateway within ~1s, so adding one never
   requires a restart.

4. Point your agent at it: `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` in
   Claude Code's `settings.json`, provider `base_url` + `apiKey` for anything
   else (OpenAI-style clients usually need `/v1` in the base URL). The vkey
   rides in whatever header your client already sends, so for most clients this
   is a base-URL change and nothing else.

## Documentation

| Doc | What is in it |
|---|---|
| [usage.md](https://github.com/wusende/keysink/blob/main/docs/usage.md) | routing rules, every command and route option, health endpoint fields, vault layout, FAQ |
| [service.md](https://github.com/wusende/keysink/blob/main/docs/service.md) | `sudo keysink deploy`: system user, systemd unit, headless init |
| [security.md](https://github.com/wusende/keysink/blob/main/docs/security.md) | threat model, same-uid channels, audit log, bounds and shutdown |
| [performance.md](https://github.com/wusende/keysink/blob/main/docs/performance.md) | measured overhead and the `scripts/perf.sh` harness |

## What this is not

- Not a secret manager: one user, no RBAC, no HA, no KMS integration.
- Not an LLM gateway: no token accounting, budgets, model routing, caching or
  rate limiting. If you want those, put LiteLLM or one-api next to it.
- Not multi-machine: one process, one host, loopback.
- Not key pools: one upstream and one key per route, no failover.
- Not a sandbox for the agent: a vkey is a capability. `route disable` /
  `rotate` is how you take it back.

## Development

```bash
cargo test
cargo build --release
bash scripts/smoke.sh    # end-to-end: fake upstream, forwarding / SSE / retry / hot-reload / export stripping
```

`cargo test` includes a seeded fuzz suite (22 targets over the pure helpers, a
vault corruption matrix, and end-to-end fuzz against a mock upstream) plus the
perf harness in `perf/ksbench`. Pushing a `v*` tag makes GitHub Actions build
and publish release artifacts for all platforms, plus crates.io and the npm
package once `CRATES_PUBLISH` / `NPM_PUBLISH` are enabled (see
[docs/publishing.md](docs/publishing.md)).

---

If keysink let you stop pasting API keys into agent configs — or it already
caught the rotation you didn't have to do — a
[star](https://github.com/wusende/keysink/stargazers) helps other people find
it before the leak does. For file-based secrets outside agents, see the
companion tool [envpouch](https://github.com/wusende/envpouch): encrypted
`.env` profiles with the same author.
