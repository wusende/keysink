use crate::error::{Error, Result};
use crate::model::{STORE_VERSION, Store};
use crate::util;
use age::secrecy::ExposeSecret;
use fs2::FileExt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

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

    fn ensure_home(&self) -> Result<()> {
        util::create_private_dir_all(&self.home)?;
        util::ensure_private_dir(&self.home)
    }
}

pub fn init(paths: &Paths, force: bool, password: &str) -> Result<()> {
    let key_exists = paths.master_key().exists();
    let store_exists = paths.store().exists();

    if (key_exists || store_exists) && !force {
        return Err(Error::msg(format!(
            "{} 已存在 {} 或 {}；如需重建请加 --force（会先改名备份）",
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
        String::from_utf8(util::read_no_follow(Path::new(&file))?)
            .map_err(|_| Error::msg("KEYSINK_MASTER_KEY_FILE 不是 UTF-8"))?
    } else {
        let key_path = paths.master_key();
        if !key_path.exists() {
            // When not yet initialized, give actionable guidance instead of a bare ENOENT.
            return Err(Error::msg(format!(
                "尚未初始化：找不到 {}（{}）；请先运行 init",
                key_path.display(),
                paths.key_name
            )));
        }
        util::ensure_private_file(&key_path, paths.key_name)?;
        String::from_utf8(util::read_no_follow(&key_path)?)
            .map_err(|_| Error::msg(format!("{} 不是 UTF-8", paths.key_name)))?
    };

    let line = raw
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| Error::msg("master.key 为空"))?;

    line.parse::<age::x25519::Identity>()
        .map_err(|e| Error::Age(format!("master.key 解析失败: {e}")))
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
                    "主 store 读取失败，回落到 .bak 备份；备份可能过期（已轮换/删除的 vkey 可能重新生效），请尽快修复"
                );
                load_store_file(&paths.store_bak(), identity)
                    .map(|store| (store, true))
                    .map_err(|backup_err| {
                        Error::msg(format!(
                            "store 与备份都无法解密：primary={primary_err}; backup={backup_err}"
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
    let ciphertext = util::read_no_follow(path).map_err(|e| match e {
        Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => Error::msg(format!(
            "读取 {} 失败：Permission denied；文件属主/权限可能被 root 改写过（服务用户读不到）。\
             请用 `sudo -u keysink keysink ...` 管理 vault，或把属主改回服务用户后重试",
            path.display()
        )),
        other => other,
    })?;
    let plaintext = Zeroizing::new(decrypt(&ciphertext, identity)?);
    let store: Store = serde_json::from_slice(plaintext.as_slice())?;
    if store.version != STORE_VERSION {
        return Err(Error::msg(format!(
            "store 版本 {} 不受支持（当前支持 {}）",
            store.version, STORE_VERSION
        )));
    }
    store.validate()?;
    Ok(store)
}

/// Runs "read → mutate → atomic write" under file lock protection.
pub fn update<F, T>(paths: &Paths, f: F) -> Result<T>
where
    F: FnOnce(&mut Store) -> Result<T>,
{
    paths.ensure_home()?;
    let _lock = LockGuard::acquire(paths)?;
    let Unlocked {
        mut store,
        identity,
        ..
    } = unlock(paths)?;
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
        let sane = util::read_no_follow(&paths.store()).ok().and_then(|bytes| {
            let plain = decrypt(&bytes, identity).ok()?;
            serde_json::from_slice::<Store>(&plain).ok()?;
            Some(bytes)
        });
        match sane {
            Some(bytes) => {
                if let Err(e) = util::atomic_write(&paths.store_bak(), &bytes, 0o600) {
                    tracing::warn!(error = %e, "写 {} 失败，继续", paths.store_bak().display());
                }
            }
            None => tracing::warn!("当前 {} 无法解密，跳过备份覆盖", paths.store().display()),
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
        ..
    } = unlock(paths)?;
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
    let Unlocked { mut store, .. } = unlock(paths)?;
    let mut stripped = 0usize;
    for route in store.routes.values_mut() {
        // take moves the value out of Route, bypassing Route::Drop's zeroing, so we must zeroize it manually
        if let Some(mut value) = route.inline_key.take() {
            value.zeroize();
            stripped += 1;
        }
    }
    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(&store)?);
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::new(
        passphrase.to_string(),
    ));
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext.as_slice())?;
    writer.finish()?;
    util::atomic_write(output, &out, 0o600)?;
    Ok(stripped)
}

fn encrypt_to(plaintext: &[u8], identities: &[&age::x25519::Identity]) -> Result<Vec<u8>> {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = identities
        .iter()
        .map(|id| Box::new(id.to_public()) as Box<dyn age::Recipient + Send>)
        .collect();
    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| Error::msg("age: 没有可用的 recipient"))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

fn decrypt(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut plaintext = Vec::new();
    match decryptor {
        age::Decryptor::Recipients(d) => {
            let mut reader = d
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .map_err(|e| Error::Age(format!("master.key 与 store 不匹配或文件损坏: {e}")))?;
            reader.read_to_end(&mut plaintext)?;
        }
        age::Decryptor::Passphrase(_) => {
            return Err(Error::msg(
                "这是口令加密的 age 文件，不能用 master.key 解开",
            ));
        }
    }
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
                    "打开锁文件 {} 失败：Permission denied；属主可能是 root（用 sudo 直接管理过），\
                         请改用 `sudo -u keysink keysink ...` 或把属主改回服务用户",
                    lock_path.display()
                ))
            } else {
                Error::Io(e)
            }
        })?;
        // When root first creates the lock file it ends up root:root and the service user can no longer open it;
        // follow the directory's owner here too, so the next lock doesn't lock itself out.
        util::inherit_dir_owner(&lock_path, &lock_path)?;
        file.lock_exclusive()?;
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
        assert!(from_backup, "回落 .bak 时必须置 from_backup");
        assert!(store.routes.contains_key("x"), "备份内容应是上一次的好版本");
        assert_ne!(store.routes["x"].note, "w", ".bak 落后一代，不含最后一次写");
    }

    #[test]
    fn unlock_without_init_hints_init() {
        let (_dir, paths) = tmp_paths(); // directory not created, no key
        let err = unlock(&paths).map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("init"), "错误应提示先 init：{err}");
    }

    #[test]
    fn export_requires_passphrase() {
        let (_dir, paths) = tmp_paths();
        init_test(&paths);
        let out = paths.home.join("backup.age");
        export(&paths, &out, "test-pass").unwrap();
        let ct = fs::read(&out).unwrap();
        assert!(matches!(
            age::Decryptor::new(&ct[..]).unwrap(),
            age::Decryptor::Passphrase(_)
        ));
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
        let age::Decryptor::Passphrase(d) = decryptor else {
            panic!("导出应是口令加密");
        };
        let mut plain = Vec::new();
        d.decrypt(
            &age::secrecy::SecretString::new("test-pass".to_string()),
            None,
        )
        .unwrap()
        .read_to_end(&mut plain)
        .unwrap();
        let text = String::from_utf8(plain).unwrap();
        assert!(!text.contains("never-leak"), "导出不得包含 key 值");
        assert!(text.contains("\"routes\""), "导出应保留路由配置");
    }

    #[test]
    fn vault_force_init_keeps_vault_names() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::vault(dir.path().join("v"));
        init(&paths, false, "test-password").unwrap();
        assert!(init(&paths, false, "test-password").is_err());
        init(&paths, true, "test-password").unwrap();
        assert!(paths.master_key().exists());
        assert!(paths.store().exists());
        let names: Vec<String> = std::fs::read_dir(&paths.home)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n.starts_with("vault.key.old.")),
            "旧 vault.key 应保留原名改名: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.starts_with("vault.age.old.")),
            "旧 vault.age 应保留原名改名: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("master.key") || n.starts_with("store.age")),
            "vault 目录不应出现 user 库命名: {names:?}"
        );
    }
}
