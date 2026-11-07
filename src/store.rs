use crate::error::{Error, Result};
use crate::model::{STORE_VERSION, Store};
use crate::util;
use age::secrecy::ExposeSecret;
// The vault's read-mutate-write transaction holds a std::fs::File::lock()
// (stable since 1.89): a blocking exclusive flock on unix, LockFileEx on
// windows — the same semantics the fs2/fs4 crates provided, with no dep.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Upper bound on the encrypted store. age's reader grows the plaintext
/// without bound, so a wedged hot reload must not be able to turn one bogus
/// file into an OOM. Real vaults are a few KB; 64 MiB leaves generous
/// headroom. Enforced before the file is buffered (see
/// [`util::read_no_follow_limited`]) as well as inside [`decrypt`].
const MAX_CIPHERTEXT: usize = 64 * 1024 * 1024;

pub struct Unlocked {
    pub store: Store,
    pub identity: age::x25519::Identity,
    /// true = the main store failed to decrypt and the data came from the `.bak` backup.
    /// The backup may be stale: rotated/removed vkeys become valid again; the caller must surface a prominent warning.
    pub from_backup: bool,
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub home: PathBuf,
    key_name: &'static str,
    store_name: &'static str,
    lock_name: &'static str,
}

impl Paths {
    /// Vault: the store used by routing (including route-only keys) and serve.
    pub fn vault(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            key_name: "vault.key",
            store_name: "vault.age",
            lock_name: "vault.lock",
        }
    }

    pub fn master_key(&self) -> PathBuf {
        self.home.join(self.key_name)
    }

    pub fn master_key_bak(&self) -> PathBuf {
        self.home.join(format!("{}.bak", self.key_name))
    }

    pub fn store(&self) -> PathBuf {
        self.home.join(self.store_name)
    }

    pub fn store_bak(&self) -> PathBuf {
        self.home.join(format!("{}.bak", self.store_name))
    }

    pub fn lock(&self) -> PathBuf {
        self.home.join(self.lock_name)
    }

    /// Runtime file where serve writes the actual listen address at startup (route add reads it to report the gateway location).
    pub fn gateway_addr(&self) -> PathBuf {
        self.home.join("gateway.addr")
    }

    /// Filename prefixes of the `.old.<millis>` leftovers a `--force` rebuild
    /// leaves behind, in the same order as the renames in [`init`]. Each
    /// prefix names a key/store pair that still decrypts each other — the
    /// `vault.key.bak.old.*` pair included, which is why it must never be
    /// dropped from a "delete these to complete the rebuild" listing.
    pub fn old_backup_prefixes(&self) -> [String; 4] {
        [
            format!("{}.old.", self.key_name),
            format!("{}.old.", self.store_name),
            format!("{}.bak.old.", self.key_name),
            format!("{}.bak.old.", self.store_name),
        ]
    }

    fn ensure_home(&self) -> Result<()> {
        util::create_private_dir_all(&self.home)?;
        util::ensure_private_dir(&self.home)
    }
}

/// Whether the process is configured to load the master identity from outside
/// the vault (`KEYSINK_MASTER_KEY` / `KEYSINK_MASTER_KEY_FILE`).
///
/// `init` and `rekey` always create/replace `vault.key`; with an external
/// identity configured, the running gateway would keep using the external one
/// and could no longer decrypt a store encrypted to the new file key. The CLI
/// refuses those operations up front; the library functions stay usable for
/// tests and for callers that manage the identity themselves.
pub fn external_identity_configured() -> bool {
    std::env::var_os("KEYSINK_MASTER_KEY").is_some()
        || std::env::var_os("KEYSINK_MASTER_KEY_FILE").is_some()
}

/// Creates a new `vault.key` + `vault.age` pair.
///
/// Always generates a fresh identity; the CLI refuses to call this while
/// [`external_identity_configured`] is true, because the service would keep
/// using the external identity and could not decrypt the new store.
pub fn init(paths: &Paths, force: bool, password: &str) -> Result<()> {
    let key_exists = paths.master_key().exists();
    let store_exists = paths.store().exists();

    if (key_exists || store_exists) && !force {
        return Err(Error::msg(format!(
            "{} already contains {} or {}; to rebuild, add --force (existing files are renamed to backups first)",
            paths.home.display(),
            paths.key_name,
            paths.store_name
        )));
    }

    if force && (key_exists || store_exists) {
        // Millisecond suffix: two --force runs within the same second won't silently overwrite the previous backup via rename.
        let stamp = util::now_millis();
        if key_exists {
            fs::rename(
                paths.master_key(),
                paths.home.join(format!("{}.old.{stamp}", paths.key_name)),
            )?;
        }
        if store_exists {
            fs::rename(
                paths.store(),
                paths.home.join(format!("{}.old.{stamp}", paths.store_name)),
            )?;
        }
        for (path, base) in [
            (paths.master_key_bak(), format!("{}.bak", paths.key_name)),
            (paths.store_bak(), format!("{}.bak", paths.store_name)),
        ] {
            if path.exists() {
                fs::rename(&path, paths.home.join(format!("{base}.old.{stamp}")))?;
            }
        }
    }

    paths.ensure_home()?;

    let identity = age::x25519::Identity::generate();
    let key_text = identity.to_string();
    util::write_new_private(
        &paths.master_key(),
        format!("{}\n", key_text.expose_secret()).as_bytes(),
    )?;

    let mut store = Store::new();
    store.password_hash = Some(crate::password::hash_password(password)?);
    save_store(paths, &store, &identity)?;

    Ok(())
}

/// Read the master key. Supports:
/// - `KEYSINK_MASTER_KEY` (inline age identity)
/// - `KEYSINK_MASTER_KEY_FILE` (points to an identity file)
/// - Default `<vault home>/vault.key` (decided by `--home` / `$KEYSINK_VAULT_HOME` / directory probing)
pub fn load_identity(paths: &Paths) -> Result<age::x25519::Identity> {
    let raw = if let Ok(inline) = std::env::var("KEYSINK_MASTER_KEY") {
        inline
    } else if let Ok(file) = std::env::var("KEYSINK_MASTER_KEY_FILE") {
        let key_file = Path::new(&file);
        // Same standard as the default vault.key path: refuse symlinks and
        // group/other-readable identities. 0400/0600 pass, so systemd
        // LoadCredential credentials qualify.
        util::ensure_private_file(key_file, "KEYSINK_MASTER_KEY_FILE")?;
        String::from_utf8(util::read_no_follow(key_file)?)
            .map_err(|_| Error::msg("KEYSINK_MASTER_KEY_FILE is not UTF-8"))?
    } else {
        let key_path = paths.master_key();
        if !key_path.exists() {
            // When not yet initialized, give actionable guidance instead of a bare ENOENT.
            return Err(Error::msg(format!(
                "not initialized: {} ({}) not found; run init first",
                key_path.display(),
                paths.key_name
            )));
        }
        util::ensure_private_file(&key_path, paths.key_name)?;
        String::from_utf8(util::read_no_follow(&key_path)?)
            .map_err(|_| Error::msg(format!("{} is not UTF-8", paths.key_name)))?
    };

    let line = raw
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| Error::msg("master.key is empty"))?;

    line.parse::<age::x25519::Identity>()
        .map_err(|e| Error::Age(format!("failed to parse master.key: {e}")))
}

pub fn unlock(paths: &Paths) -> Result<Unlocked> {
    let identity = load_identity(paths)?;
    let (store, from_backup) = load_store(paths, &identity)?;
    Ok(Unlocked {
        store,
        identity,
        from_backup,
    })
}

/// Returns (store, from_backup). from_backup=true means we fell back to `.bak`:
/// an availability-first tradeoff, but "revoked/deleted vkeys becoming active again" must stay visible to the caller.
pub fn load_store(paths: &Paths, identity: &age::x25519::Identity) -> Result<(Store, bool)> {
    match load_store_file(&paths.store(), identity) {
        Ok(store) => Ok((store, false)),
        Err(primary_err) => {
            if paths.store_bak().exists() {
                tracing::error!(
                    error = %primary_err,
                    "failed to read the primary store, falling back to the .bak backup; the backup may be stale (rotated/removed vkeys may become valid again); fix it as soon as possible"
                );
                load_store_file(&paths.store_bak(), identity)
                    .map(|store| (store, true))
                    .map_err(|backup_err| {
                        Error::msg(format!(
                            "neither the store nor the backup can be decrypted: primary={primary_err}; backup={backup_err}"
                        ))
                    })
            } else {
                Err(primary_err)
            }
        }
    }
}

pub fn load_store_file(path: &Path, identity: &age::x25519::Identity) -> Result<Store> {
    util::ensure_private_file(path, "vault.age")?;
    let ciphertext = util::read_no_follow_limited(path, MAX_CIPHERTEXT).map_err(|e| match e {
        Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => Error::msg(format!(
            "failed to read {}: Permission denied; the file owner/permissions may have been rewritten by root (the service user cannot read it). \
             Use `sudo -u keysink keysink ...` to manage the vault, or restore ownership to the service user and retry",
            path.display()
        )),
        other => other,
    })?;
    let plaintext = Zeroizing::new(decrypt(&ciphertext, identity)?);
    let store: Store = serde_json::from_slice(plaintext.as_slice())?;
    if store.version != STORE_VERSION {
        return Err(Error::msg(format!(
            "store version {} is not supported (supported version: {})",
            store.version, STORE_VERSION
        )));
    }
    store.validate()?;
    Ok(store)
}

/// Refuses a destructive operation when the vault is being served from the
/// `.bak` backup.
///
/// `unlock` falls back to the backup on any primary-store failure, which is
/// right for a running gateway (availability) but wrong for a write: the
/// backup is one generation behind, so writing from it silently revives
/// revoked/rotated vkeys and destroys the evidence of whatever broke the
/// primary. The caller must repair the primary first (or serve with
/// `--accept-degraded` in the read-only gateway, which does not persist it).
fn refuse_when_degraded(paths: &Paths, action: &str, from_backup: bool) -> Result<()> {
    if !from_backup {
        return Ok(());
    }
    Err(Error::msg(format!(
        "refusing to {action}: the primary store {} could not be decrypted, so the vault is \
         being read from the older backup {}. That backup is one write behind: revoked or \
         rotated vkeys may work again from it. Save the broken primary for inspection, repair \
         it first (for example by copying the backup over it), then retry. `keysink doctor` \
         reports the exact failure.",
        paths.store().display(),
        paths.store_bak().display()
    )))
}

/// Runs "read → mutate → atomic write" under file lock protection.
///
/// Refuses to write when the data came from the `.bak` fallback: see
/// [`refuse_when_degraded`].
pub fn update<F, T>(paths: &Paths, f: F) -> Result<T>
where
    F: FnOnce(&mut Store) -> Result<T>,
{
    paths.ensure_home()?;
    let _lock = LockGuard::acquire(paths)?;
    let Unlocked {
        mut store,
        identity,
        from_backup,
    } = unlock(paths)?;
    refuse_when_degraded(paths, "write the vault", from_backup)?;
    let out = f(&mut store)?;
    save_store(paths, &store, &identity)?;
    Ok(out)
}

pub fn save_store(paths: &Paths, store: &Store, identity: &age::x25519::Identity) -> Result<()> {
    store.validate()?;
    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(store)?);
    let ciphertext = encrypt_to(plaintext.as_slice(), &[identity])?;

    if paths.store().exists() {
        // Read the old ciphertext once: it confirms the file still decrypts (so we don't clobber the only usable backup)
        // and doubles as the backup content for the atomic write — fs::copy crashing mid-way would leave a truncated .bak.
        let sane = util::read_no_follow_limited(&paths.store(), MAX_CIPHERTEXT)
            .ok()
            .and_then(|bytes| {
                let plain = decrypt(&bytes, identity).ok()?;
                serde_json::from_slice::<Store>(&plain).ok()?;
                Some(bytes)
            });
        match sane {
            Some(bytes) => {
                if let Err(e) = util::atomic_write(&paths.store_bak(), &bytes, 0o600) {
                    tracing::warn!(error = %e, "failed to write {}, continuing", paths.store_bak().display());
                }
            }
            None => tracing::warn!(
                "current {} cannot be decrypted, skipping backup overwrite",
                paths.store().display()
            ),
        }
    }

    util::atomic_write(&paths.store(), &ciphertext, 0o600)
}

/// Rotates the master key: first encrypt the store to both old and new keys, then replace master.key, finally converge on the new key.
/// If any step crashes, at least one key can still decrypt the current store.
pub fn rekey(paths: &Paths) -> Result<()> {
    paths.ensure_home()?;
    let _lock = LockGuard::acquire(paths)?;
    let Unlocked {
        store,
        identity: old,
        from_backup,
    } = unlock(paths)?;
    refuse_when_degraded(paths, "rotate the master key", from_backup)?;
    let new = age::x25519::Identity::generate();

    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(&store)?);
    let dual = encrypt_to(plaintext.as_slice(), &[&old, &new])?;
    util::atomic_write(&paths.store(), &dual, 0o600)?;

    let new_text = new.to_string();
    if paths.master_key().exists() {
        // Atomic write for the same reason as the store: avoids a half-written fs::copy backup.
        let old_key = util::read_no_follow(&paths.master_key())?;
        util::atomic_write(&paths.master_key_bak(), &old_key, 0o600)?;
    }
    util::atomic_write(
        &paths.master_key(),
        format!("{}\n", new_text.expose_secret()).as_bytes(),
        0o600,
    )?;

    let final_ct = encrypt_to(plaintext.as_slice(), &[&new])?;
    util::atomic_write(&paths.store(), &final_ct, 0o600)?;
    // Sync the backup to the new key, so doctor can decrypt the old backup with the current key.
    util::atomic_write(&paths.store_bak(), &final_ct, 0o600)?;

    Ok(())
}

/// Passphrase-encrypted export, for off-site backup.
///
/// route-only keys (`inline_key`) are deliberately kept out of the export: such keys are only allowed inside routing
/// and offer no read/backup channel. Returns the number of stripped routes; the caller is responsible for reporting it.
pub fn export(paths: &Paths, output: &Path, passphrase: &str) -> Result<usize> {
    let Unlocked {
        mut store,
        from_backup,
        ..
    } = unlock(paths)?;
    refuse_when_degraded(paths, "export the vault", from_backup)?;
    let mut stripped = 0usize;
    for route in store.routes.values_mut() {
        // take moves the value out of Route, bypassing Route::Drop's zeroing, so we must zeroize it manually
        if let Some(mut value) = route.inline_key.take() {
            value.zeroize();
            stripped += 1;
        }
    }
    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(&store)?);
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
        passphrase.to_string(),
    ));
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext.as_slice())?;
    writer.finish()?;
    util::atomic_write(output, &out, 0o600)?;
    Ok(stripped)
}

pub(crate) fn encrypt_to(
    plaintext: &[u8],
    identities: &[&age::x25519::Identity],
) -> Result<Vec<u8>> {
    let recipients: Vec<Box<dyn age::Recipient>> = identities
        .iter()
        .map(|id| Box::new(id.to_public()) as Box<dyn age::Recipient>)
        .collect();
    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient),
    )
    .map_err(|e| Error::msg(format!("age: recipient encryption setup failed: {e}")))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

pub(crate) fn decrypt(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    // A replaced vault.age already implies a same-UID compromise (out of
    // scope), but age's reader grows the plaintext without bound: cap the
    // ciphertext so a wedged hot reload cannot turn one bogus file into an
    // OOM. Real vaults are a few KB; 64 MiB leaves generous headroom.
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Error::msg(format!(
            "vault file exceeds the {} MiB decrypt limit; refusing to read it",
            MAX_CIPHERTEXT / (1024 * 1024)
        )));
    }
    let decryptor = age::Decryptor::new(ciphertext)?;
    if decryptor.is_scrypt() {
        return Err(Error::msg(
            "this is a passphrase-encrypted age file and cannot be decrypted with master.key",
        ));
    }
    let mut plaintext = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| {
            Error::Age(format!(
                "master.key does not match the store or the file is corrupt: {e}"
            ))
        })?;
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

struct LockGuard {
    file: File,
}

impl LockGuard {
    fn acquire(paths: &Paths) -> Result<Self> {
        let lock_path = paths.lock();
        let mut opts = util::private_open_options(0o600);
        opts.read(true).write(true).create(true);
        let file = opts.open(&lock_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Error::msg(format!(
                    "failed to open lock file {}: Permission denied; the owner may be root (it was managed directly with sudo), \
                         switch to `sudo -u keysink keysink ...` or restore ownership to the service user",
                    lock_path.display()
                ))
            } else {
                Error::Io(e)
            }
        })?;
        // When root first creates the lock file it ends up root:root and the service user can no longer open it;
        // follow the directory's owner here too, so the next lock doesn't lock itself out.
        util::inherit_dir_owner(&lock_path, &lock_path)?;
        file.lock()?;
        Ok(Self { file })
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Route};
    use std::collections::BTreeMap;

    fn tmp_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::vault(dir.path().join("ks"));
        (dir, paths)
    }

    fn init_test(paths: &Paths) -> age::x25519::Identity {
        let identity = age::x25519::Identity::generate();
        util::create_private_dir_all(&paths.home).unwrap();
        util::write_new_private(
            &paths.master_key(),
            format!("{}\n", identity.to_string().expose_secret()).as_bytes(),
        )
        .unwrap();
        let store = Store::new();
        save_store(paths, &store, &identity).unwrap();
        identity
    }

    #[test]
    fn encrypt_roundtrip_and_tamper() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        let Unlocked {
            store,
            identity,
            from_backup,
        } = unlock(&paths).unwrap();
        assert_eq!(store.version, STORE_VERSION);
        assert!(!from_backup);
        assert_eq!(
            load_store(&paths, &identity).unwrap().0.version,
            STORE_VERSION
        );

        let ct = fs::read(paths.store()).unwrap();
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        fs::write(paths.store(), bad).unwrap();
        assert!(load_store(&paths, &identity).is_err());
    }

    #[test]
    fn update_persists_and_backs_up() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        update(&paths, |store| {
            store.routes.insert(
                "r".into(),
                Route::new(
                    crate::vkey::generate(),
                    "https://example.com".into(),
                    "inline-value".into(),
                    Auth::Bearer,
                    BTreeMap::new(),
                ),
            );
            Ok(())
        })
        .unwrap();
        let Unlocked { store, .. } = unlock(&paths).unwrap();
        assert!(store.routes.contains_key("r"));
        assert!(paths.store_bak().exists());
    }

    #[test]
    fn rekey_keeps_store_readable() {
        let (_dir, paths) = tmp_paths();
        let old = init_test(&paths);
        rekey(&paths).unwrap();
        let new = load_identity(&paths).unwrap();
        assert!(load_store(&paths, &new).is_ok());
        assert!(load_store(&paths, &old).is_err());
    }

    #[test]
    fn corrupt_primary_falls_back_to_backup_with_flag() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        // .bak lags one generation behind (save_store backs up the old content before writing the new): write twice,
        // so that .bak is the "previous good version containing the x route".
        update(&paths, |store| {
            store.routes.insert(
                "x".into(),
                Route::new(
                    crate::vkey::generate(),
                    "https://example.com".into(),
                    "v".into(),
                    Auth::Bearer,
                    BTreeMap::new(),
                ),
            );
            Ok(())
        })
        .unwrap();
        update(&paths, |store| {
            store.routes.get_mut("x").unwrap().note = "w".into();
            Ok(())
        })
        .unwrap();
        assert!(paths.store_bak().exists());
        fs::write(paths.store(), b"not-an-age-file").unwrap();
        let Unlocked {
            store, from_backup, ..
        } = unlock(&paths).unwrap();
        assert!(
            from_backup,
            "from_backup must be set when falling back to .bak"
        );
        assert!(
            store.routes.contains_key("x"),
            "backup content should be the previous good version"
        );
        assert_ne!(
            store.routes["x"].note, "w",
            ".bak lags one generation behind and does not include the last write"
        );
    }

    #[test]
    fn refuses_to_write_a_store_loaded_from_backup() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        add_route(&paths, "r1");
        add_route(&paths, "r2");
        // .bak is now the previous generation (r1 only).
        fs::write(paths.store(), b"corrupt-primary").unwrap();

        let err = update(&paths, |store| {
            store.routes.insert(
                "r3".into(),
                Route::new(
                    crate::vkey::generate(),
                    "https://example.com".into(),
                    "v".into(),
                    Auth::Bearer,
                    BTreeMap::new(),
                ),
            );
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("refusing to write"), "{err}");
        assert!(err.contains("revoked or rotated"), "{err}");
        // The corrupt primary must be left for inspection; the write must not
        // have persisted the stale backup content over it.
        assert_eq!(fs::read(paths.store()).unwrap(), b"corrupt-primary");
        let unlocked = unlock(&paths).unwrap();
        assert!(unlocked.from_backup);
        assert!(unlocked.store.routes.contains_key("r1"));
        assert!(!unlocked.store.routes.contains_key("r2"));
        assert!(!unlocked.store.routes.contains_key("r3"));
    }

    #[test]
    fn refuses_to_rekey_from_backup() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        add_route(&paths, "r1");
        add_route(&paths, "r2");
        fs::write(paths.store(), b"corrupt-primary").unwrap();

        let err = rekey(&paths).unwrap_err().to_string();
        assert!(err.contains("refusing to rotate the master key"), "{err}");
        // The key files are untouched, so recovering the backup by hand still works.
        assert!(load_identity(&paths).is_ok());
    }

    #[test]
    fn refuses_to_export_from_backup() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        add_route(&paths, "r1");
        add_route(&paths, "r2");
        fs::write(paths.store(), b"corrupt-primary").unwrap();

        let out = paths.home.join("backup.age");
        let err = export(&paths, &out, "test-pass").unwrap_err().to_string();
        assert!(err.contains("refusing to export the vault"), "{err}");
        assert!(!out.exists(), "a refused export must not leave a file");
    }

    fn add_route(paths: &Paths, name: &str) {
        update(paths, |store| {
            store.routes.insert(
                name.into(),
                Route::new(
                    crate::vkey::generate(),
                    "https://example.com".into(),
                    "v".into(),
                    Auth::Bearer,
                    BTreeMap::new(),
                ),
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unlock_without_init_hints_init() {
        let (_dir, paths) = tmp_paths(); // directory not created, no key
        let err = unlock(&paths).map(|_| ()).unwrap_err().to_string();
        assert!(
            err.contains("init"),
            "error should hint at running init first: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn master_key_file_env_is_permission_checked_like_the_default_path() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        std::fs::write(&key, "not-a-real-identity-but-parses-later\n").unwrap();
        std::fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        // No other test reads this variable, so setting it here is race-free.
        // SAFETY: single-threaded test process-wide usage of this variable.
        unsafe { std::env::set_var("KEYSINK_MASTER_KEY_FILE", &key) };
        let paths = Paths::vault(dir.path().join("v"));
        let err = load_identity(&paths)
            .err()
            .expect("0644 identity must be refused")
            .to_string();
        assert!(
            err.contains("permissions too wide"),
            "0644 identity must be refused like the default path: {err}"
        );

        // 0600 passes the checks and proceeds to the (failing) identity parse.
        std::fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let err = load_identity(&paths)
            .err()
            .expect("a bogus identity must still fail to parse")
            .to_string();
        assert!(
            !err.contains("permissions"),
            "0600 identity must get past the file checks: {err}"
        );
        // SAFETY: paired with the set_var above; see the note there.
        unsafe { std::env::remove_var("KEYSINK_MASTER_KEY_FILE") };
    }

    #[test]
    fn load_store_file_refuses_an_oversized_file_before_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.age");
        let file = fs::File::create(&path).unwrap();
        // Sparse: no 64 MiB of data is actually written, but a plain
        // read_to_end would still buffer 64 MiB before the old post-read
        // check. The limited read must stop at the cap.
        file.set_len((MAX_CIPHERTEXT + 1) as u64).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let identity = age::x25519::Identity::generate();
        let err = load_store_file(&path, &identity).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn decrypt_refuses_oversized_ciphertext() {
        let identity = age::x25519::Identity::generate();
        let blob = vec![0u8; 64 * 1024 * 1024 + 1];
        let err = decrypt(&blob, &identity).unwrap_err().to_string();
        assert!(err.contains("decrypt limit"), "{err}");
    }

    #[test]
    fn export_requires_passphrase() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        let out = paths.home.join("backup.age");
        export(&paths, &out, "test-pass").unwrap();
        let ct = fs::read(&out).unwrap();
        assert!(age::Decryptor::new(&ct[..]).unwrap().is_scrypt());
    }

    #[test]
    fn export_strips_route_only_keys() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        update(&paths, |store| {
            store.routes.insert(
                "r".into(),
                Route::new(
                    crate::vkey::generate(),
                    "https://example.com".into(),
                    "never-leak".into(),
                    Auth::Bearer,
                    BTreeMap::new(),
                ),
            );
            Ok(())
        })
        .unwrap();
        let out = paths.home.join("backup.age");
        let stripped = export(&paths, &out, "test-pass").unwrap();
        assert_eq!(stripped, 1);
        // The export file itself is age passphrase-encrypted, so being unable to grep the plaintext is only a necessary condition;
        // decrypt it to verify the key value is really absent.
        let ct = fs::read(&out).unwrap();
        let decryptor = age::Decryptor::new(&ct[..]).unwrap();
        assert!(
            decryptor.is_scrypt(),
            "export should be passphrase-encrypted"
        );
        let mut plain = Vec::new();
        decryptor
            .decrypt(std::iter::once(
                &age::scrypt::Identity::new(age::secrecy::SecretString::from(
                    "test-pass".to_string(),
                )) as &dyn age::Identity,
            ))
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert!(
            !text.contains("never-leak"),
            "export must not contain key values"
        );
        assert!(
            text.contains("\"routes\""),
            "export should preserve route configuration"
        );
    }

    #[test]
    fn vault_force_init_keeps_vault_names() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::vault(dir.path().join("v"));
        init(&paths, false, "test-password").unwrap();
        assert!(init(&paths, false, "test-password").is_err());
        // A vault that has served (written) carries the .bak pair; --force
        // must preserve those under .bak.old.<millis> exactly like the live
        // pair, and the leftover listing must match — a .bak.old key still
        // decrypts its .bak.old store, so dropping it from the listing would
        // leave an unnoticed live credential after a flush-compromise rebuild.
        std::fs::write(paths.master_key_bak(), b"bak-key").unwrap();
        std::fs::write(paths.store_bak(), b"bak-store").unwrap();
        init(&paths, true, "test-password").unwrap();
        assert!(paths.master_key().exists());
        assert!(paths.store().exists());
        let names: Vec<String> = std::fs::read_dir(&paths.home)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        for prefix in paths.old_backup_prefixes() {
            assert!(
                names.iter().any(|n| n.starts_with(&prefix)),
                "old {prefix}* should be renamed keeping the original name: {names:?}"
            );
        }
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("master.key") || n.starts_with("store.age")),
            "the vault directory should not contain user-store naming: {names:?}"
        );
    }
}
