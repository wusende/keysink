use crate::error::{Error, Result};
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Millisecond-resolution timestamp: used as the init --force backup-name suffix so two runs within the same second don't overwrite each other.
pub fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn ts(secs: u64) -> String {
    OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| secs.to_string())
}

pub fn now_ts() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| now_secs().to_string())
}

pub fn allow_insecure() -> bool {
    std::env::var("KEYSINK_ALLOW_INSECURE").as_deref() == Ok("1")
}

/// Platform layer for open options: on Unix, mode + O_NOFOLLOW (refuse to
/// follow symlinks, land on disk as 0600 immediately); Windows has no
/// equivalent for either, so open plainly — symlink defense falls back to
/// the stat checks in ensure_private_*.
pub(crate) fn private_open_options(mode: u32) -> OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut opts = OpenOptions::new();
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
        opts
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        OpenOptions::new()
    }
}

/// Verifies the file is not a symlink and its permissions are not open to
/// group/other (mode semantics exist on Unix only).
pub fn ensure_private_file(path: &Path, what: &str) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(Error::msg(format!(
            "{what} is a symlink, refusing to use it: {}",
            path.display()
        )));
    }
    if !md.is_file() {
        return Err(Error::msg(format!(
            "{what} is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 && !allow_insecure() {
            return Err(Error::msg(format!(
                "{what} permissions too wide ({:o}); chmod 600 {} — or set KEYSINK_ALLOW_INSECURE=1 once you accept the risk",
                mode,
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(Error::msg(format!(
            "directory is a symlink, refusing to use it: {}",
            path.display()
        )));
    }
    if !md.is_dir() {
        return Err(Error::msg(format!("not a directory: {}", path.display())));
    }
    #[cfg(unix)]
    {
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 && !allow_insecure() {
            return Err(Error::msg(format!(
                "directory permissions too wide ({:o}); chmod 700 {} — or set KEYSINK_ALLOW_INSECURE=1 once you accept the risk",
                mode,
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn create_private_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Reads a file, refusing to follow symlinks (for Windows see private_open_options).
pub fn read_no_follow(path: &Path) -> Result<Vec<u8>> {
    let mut f = private_open_options(0).read(true).open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Writes a new file with 0600; fails if it already exists (prevents silently overwriting a key).
pub fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = private_open_options(0o600)
        .write(true)
        .create_new(true)
        .open(path)?;
    inherit_dir_owner(path, path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// When running as root, new files should follow the owning directory's owner.
///
/// The vault directory is owned by the service user `keysink`. Bypassing
/// `sudo -u keysink` and running `sudo keysink ...` directly leaves files as
/// `root:root 0600`; the gateway running as keysink then can't read the
/// store, the snapshot sticks at the old version, and it surfaces as
/// **all vkeys suddenly returning 401**. Here the owner is fixed back to
/// the directory's owner before the file lands on disk, so misusing root
/// no longer breaks the service.
#[cfg(unix)]
pub(crate) fn inherit_dir_owner(file: &Path, target: &Path) -> Result<()> {
    // SAFETY: geteuid merely reads process credentials and has no side effects.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let md = fs::symlink_metadata(dir)?;
    if md.uid() == 0 && md.gid() == 0 {
        return Ok(());
    }
    std::os::unix::fs::chown(file, Some(md.uid()), Some(md.gid())).map_err(|e| {
        Error::msg(format!(
            "failed to set owner of {} to {}:{}: {e}",
            file.display(),
            md.uid(),
            md.gid()
        ))
    })?;
    Ok(())
}

/// Windows has no uid/gid semantics; owner inheritance is a no-op.
#[cfg(not(unix))]
pub(crate) fn inherit_dir_owner(_file: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

/// Whether the file's owner matches its containing directory.
///
/// Writing the vault directly as root changes the owner to root, and the
/// service user then hits `Permission denied`; doctor uses this check to
/// surface "file stats fine but the service can't read it" up front.
#[cfg(unix)]
pub fn owner_matches_dir(path: &Path) -> Result<bool> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = fs::symlink_metadata(path)?;
    let dir = fs::symlink_metadata(dir)?;
    Ok(file.uid() == dir.uid() && file.gid() == dir.gid())
}

#[cfg(not(unix))]
pub fn owner_matches_dir(_path: &Path) -> Result<bool> {
    Ok(true)
}

/// Atomic write: temp file in the same directory + fsync + rename + fsync(dir).
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::msg(format!("invalid path: {}", path.display())))?;
    let mut suffix = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp = dir.join(format!(".{file_name}.tmp.{}", hex(&suffix)));

    let result = (|| -> Result<()> {
        let mut f = private_open_options(mode)
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        inherit_dir_owner(&tmp, path)?;
        fs::rename(&tmp, path)?;
        // fsync the directory so the rename itself is durable; Windows can't
        // open a directory handle, so accept the crash window there.
        #[cfg(unix)]
        {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Minimal percent-encoding for query parameter values (everything outside RFC 3986 unreserved gets escaped).
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_basic() {
        assert_eq!(percent_encode("abc-._~"), "abc-._~");
        assert_eq!(percent_encode("a b&c"), "a%20b%26c");
    }

    #[test]
    fn hex_roundtrip_shape() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn atomic_write_replaces_content_without_residue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.age");
        atomic_write(&path, b"one", 0o600).unwrap();
        atomic_write(&path, b"two", 0o600).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"two");
        // No temp file should be left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_mode_and_dir_owner() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.age");
        atomic_write(&path, b"one", 0o600).unwrap();

        let md = fs::metadata(&path).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
        assert_eq!(md.uid(), fs::metadata(dir.path()).unwrap().uid());
    }

    #[test]
    fn owner_matches_dir_detects_same_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.age");
        fs::write(&path, b"x").unwrap();
        assert!(owner_matches_dir(&path).unwrap());
    }
}
