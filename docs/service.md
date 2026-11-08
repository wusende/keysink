# Linux system service

[← README](../README.md)

```bash
sudo keysink deploy
```

One shot: creates the `keysink` system user and a 0700 vault dir, installs the
binary to `/usr/local/bin/keysink`, writes the systemd unit and the sudoers rule
(for the admin who ran sudo), initializes the vault interactively (hidden
password, entered twice), then enables the service. Idempotent: re-running
upgrades in place and restarts. Removal is symmetric: `sudo keysink uninstall`.

This is not just convenience: the dedicated uid is what keeps the vault files
out of reach of an agent running as you (see
[security.md](security.md#the-other-channels-same-user-not-same-process)).

The unit refuses to start until the vault exists (`ConditionPathExists`). With
no terminal on the deploy host, init manually, interactively:

```bash
sudo -u keysink /usr/local/bin/keysink --home /var/lib/keysink init
```

or fully headless (`init` refuses to prompt without a TTY, so pipe the
password):

```bash
printf '%s\n' "$MASTER_PASSWORD" | sudo -u keysink /usr/local/bin/keysink \
  --home /var/lib/keysink init --password-stdin
```

Admin commands then go through `sudo -u keysink /usr/local/bin/keysink …`; each
invocation re-authenticates (`timestamp_timeout=0`), so an agent cannot silently
run them.

`deploy` supports Linux + systemd only; for personal use just run
`keysink serve`. `KEYSINK_MASTER_KEY` / `KEYSINK_MASTER_KEY_FILE` let the
identity live outside the vault directory, which is what systemd's
`LoadCredential` wants.
