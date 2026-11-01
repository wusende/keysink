# Security policy

keysink stores real API keys and proxies traffic to upstream providers, so
security reports are the most useful kind of report this project can get.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting — **Security → Report a
vulnerability** on https://github.com/wusende/keysink, or open it directly at
https://github.com/wusende/keysink/security/advisories/new.

Please **do not** open a public issue, and do not include real key material in
a report (use obvious fakes like `sk-ant-AAAA...`).

Helpful in a report: version or commit, OS/arch, the exact commands or HTTP
requests involved, and what you expected vs. what happened. A failing test is
the ideal form.

I acknowledge within ~3 days and aim to ship a fix within 30 days for anything
that breaks the key-isolation model. Coordinated disclosure; credit in the
release notes unless you prefer otherwise.

## In scope

- **Key material escaping the vault** through any channel: CLI output, HTTP
  responses, `export` backups, audit log, tracing output, error messages, crash
  output, or the agent's own process environment.
- **vkey / auth bypass**: a vkey reaching the wrong upstream, inbound auth
  headers not stripped, static route headers leaking the real credential,
  route confusion after hot reload.
- **Vault crypto**: age misuse, nonce reuse, weak scrypt parameters, a
  `password_hash` that lets a tampered file drive unbounded allocation.
- **File handling**: `O_NOFOLLOW`/ownership-check bypass, symlink or TOCTOU
  attacks on `vault.key`/`vault.age`/`.bak`, permission mistakes, path
  traversal via `--home` or `KEYSINK_VAULT_HOME`.
- **Proxy path**: request smuggling, header injection, response splitting,
  SSE terminator-scan bypass (a streamed error event slipping past the
  scanner), incorrect retry that could double-bill a POST.
- **Memory safety / panic** reachable from network or CLI input, including the
  pure helpers covered by the fuzz suite.
- **Privilege escalation** through the artifacts `keysink deploy` generates
  (systemd unit, sudoers rule, service user, `/var/lib/keysink` permissions).

## Out of scope

- Root — or any process running as the service UID — reading both `vault.key`
  and `vault.age` and decrypting offline. Machine-level isolation is explicitly
  the operator's job (see the security model table in the README).
- Local denial of service by a process already running as the same user.
- Compromise of an upstream provider, or TLS interception with a CA the user
  installed themselves.
- Documented limitations: one upstream + one key per route (no pools or
  failover), audit logging off by default, loopback binding only.
- Findings that require the attacker to already control the agent process the
  gateway is protecting against — that boundary is the whole point of the
  project; report it only if a vkey gives more than the intended upstream call.

## Supported versions

The latest tagged release and `main`. Older tags get a fix only if it is a
one-line backport.
