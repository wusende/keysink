use crate::error::{Error, Result};
use rand::Rng;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::UtcOffset;
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

/// The system's UTC offset at `at`, falling back to UTC when the platform
/// cannot resolve one (no `/etc/localtime`, an unreadable `TZ`, ...).
///
/// Resolved per instant rather than once at startup, so timestamps written
/// across a DST change keep the wall-clock offset that was in force then.
fn local_offset(at: OffsetDateTime) -> UtcOffset {
    UtcOffset::local_offset_at(at).unwrap_or(UtcOffset::UTC)
}

fn ts_at(at: OffsetDateTime, offset: UtcOffset) -> String {
    at.to_offset(offset)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// Renders an epoch-second timestamp in the system's local time zone.
///
/// The offset is part of the output (`+08:00`), so the instant stays
/// unambiguous; only the wall-clock rendering follows the machine.
pub fn ts(secs: u64) -> String {
    let at = OffsetDateTime::from_unix_timestamp(secs as i64).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    ts_at(at, local_offset(at))
}

/// UTC fallback when the system zone cannot be resolved (see [`local_offset`]).
pub fn now_ts() -> String {
    let now = OffsetDateTime::now_utc();
    now.to_offset(local_offset(now))
        .format(&Rfc3339)
        .unwrap_or_else(|_| now_secs().to_string())
}

/// tracing timer: local wall-clock time, with the same UTC fallback as
/// [`now_ts`], so an unresolvable zone never drops a log line.
pub struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        w.write_str(&now_ts())
    }
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

/// Crash-safe write: the temp file lands in the same directory so the final
/// rename cannot straddle filesystems (rename across devices is not atomic),
/// and both the data and the directory entry are fsynced — a rename alone
/// survives a crash with the new name pointing at empty blocks.
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
    rand::rng().fill_bytes(&mut suffix);
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
    rand::rng().fill_bytes(&mut out);
    out
}

/// Depth of the log queue. Generous next to a burst (a rejected flood, an
/// upstream outage) and small enough that a dead consumer cannot grow the
/// process by more than a few MB.
const LOG_QUEUE_DEPTH: usize = 4096;

/// What the log queue carries: a formatted line, or a flush marker. The
/// channel is FIFO, so everything enqueued before a marker is written before
/// the marker is acked — `flush_logs` relies on exactly that ordering.
enum LogMsg {
    Line(Vec<u8>),
    /// Written-back acknowledgement channel for `flush_logs`.
    Flush(std::sync::mpsc::Sender<()>),
}

/// The writer thread's handle on the queue, for `flush_logs` at exit: the
/// subscriber installed by `.init()` leaks its sender for the process
/// lifetime, so the writer never sees the channel close and would otherwise
/// race process teardown with whatever lines are still queued.
static LOG_FLUSH: OnceLock<SyncSender<LogMsg>> = OnceLock::new();

/// Non-blocking writer for the log output.
///
/// `tracing_subscriber::fmt()` writes to stdout synchronously, on whichever
/// thread emitted the event — for this gateway that is a tokio worker handling
/// a request. The hot warn paths (upstream timeout, retry, shed) fire per
/// request, so a slow consumer (journald, a full pipe, a paused terminal) blocks
/// a worker inside a `write` syscall and stalls unrelated requests. A dedicated
/// thread with a bounded channel keeps the request path to a `try_send`; when
/// the queue is full, lines are dropped (and counted) instead of blocking the
/// gateway.
pub fn non_blocking_stdout() -> NonBlockingMakeWriter {
    let (tx, rx) = sync_channel::<LogMsg>(LOG_QUEUE_DEPTH);
    let dropped = Arc::new(AtomicU64::new(0));
    let spawned = std::thread::Builder::new()
        .name("keysink-log".into())
        .spawn({
            // Deliberately not `stdout().lock()`: holding the global stdout
            // lock across the blocking recv would deadlock any other writer
            // (the CLI's println! output) for the process lifetime.
            let mut out = std::io::stdout();
            move || log_writer_loop(rx, &mut out)
        });
    if let Err(e) = spawned {
        // Cannot fall back to a synchronous writer from here; say so once on
        // stderr and let the channel drop lines rather than wedge the process.
        // (writeln!, never eprintln!: this must not be able to panic — see
        // the drop report in QueuedWriter::flush.)
        let _ = writeln!(
            std::io::stderr(),
            "keysink: failed to start the log writer thread ({e}); log output will be dropped"
        );
    }
    let _ = LOG_FLUSH.set(tx.clone());
    NonBlockingMakeWriter { tx, dropped }
}

/// The log writer thread body, separate so the queue protocol has tests.
///
/// On a write error (stdout gone: a closed fd, a full disk) the loop stops
/// writing but keeps draining so producers never block, and keeps acking
/// flush markers so an exit-time flush does not wait out its whole timeout.
fn log_writer_loop(rx: Receiver<LogMsg>, out: &mut impl Write) {
    while let Ok(msg) = rx.recv() {
        let line = match msg {
            LogMsg::Flush(ack) => {
                // Everything enqueued before the marker is already written
                // (FIFO); release the waiter and keep serving.
                let _ = out.flush();
                let _ = ack.send(());
                continue;
            }
            LogMsg::Line(line) => line,
        };
        if out.write_all(&line).and_then(|()| out.flush()).is_err() {
            for msg in rx.iter() {
                if let LogMsg::Flush(ack) = msg {
                    let _ = ack.send(());
                }
            }
            break;
        }
    }
    let _ = out.flush();
}

/// Best-effort drain of the log queue before the process exits: enqueue a
/// flush marker behind everything still queued and wait for the writer to
/// ack it. Bounded by `timeout` — a wedged consumer (the situation the
/// non-blocking writer exists for) must not be able to delay the exit too.
/// No-op when the non-blocking writer was never installed.
pub fn flush_logs(timeout: Duration) {
    let Some(tx) = LOG_FLUSH.get() else {
        return;
    };
    send_flush_marker(tx, timeout);
}

/// Enqueues a `Flush` marker behind the queued lines and waits for its ack.
/// A full queue is retried until the deadline (the writer is consuming it);
/// a disconnected one means the writer is gone and there is nothing to wait
/// for.
fn send_flush_marker(tx: &SyncSender<LogMsg>, timeout: Duration) {
    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
    let deadline = Instant::now() + timeout;
    loop {
        match tx.try_send(LogMsg::Flush(ack_tx.clone())) {
            Ok(()) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let _ = ack_rx.recv_timeout(left);
                return;
            }
            Err(TrySendError::Full(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            // Deadline passed with a full queue, or the writer is gone.
            Err(_) => return,
        }
    }
}

pub struct NonBlockingMakeWriter {
    tx: SyncSender<LogMsg>,
    dropped: Arc<AtomicU64>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for NonBlockingMakeWriter {
    type Writer = QueuedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        QueuedWriter {
            tx: self.tx.clone(),
            buf: Vec::new(),
            dropped: self.dropped.clone(),
        }
    }
}

/// Collects one formatted event and hands it to the log thread on flush/drop.
/// Never blocks: a full queue drops the line.
pub struct QueuedWriter {
    tx: SyncSender<LogMsg>,
    buf: Vec<u8>,
    dropped: Arc<AtomicU64>,
}

impl Write for QueuedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let line = std::mem::take(&mut self.buf);
        let len = line.len();
        // Both failure kinds mean the line is gone: a full queue (slow
        // consumer) or a dead writer (thread failed to start, or it stopped
        // draining). Counted either way — the count is the only trace a
        // dropped line leaves.
        if self.tx.try_send(LogMsg::Line(line)).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 1000 == 1 {
                // stderr, not the log: the log is what is backed up. writeln!,
                // never eprintln!: eprintln! panics when the stderr write
                // fails, this code runs on a tokio worker inside the tracing
                // write path, and "both outputs unwritable" (daemonized with
                // the fds closed) is exactly when lines drop.
                let _ = writeln!(
                    std::io::stderr(),
                    "keysink: log queue full or writer gone; dropping log lines ({n} dropped so far, {len} bytes)"
                );
            }
        }
        Ok(())
    }
}

impl Drop for QueuedWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
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
    use std::sync::Mutex;

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
    fn ts_at_honours_the_offset() {
        let epoch = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(ts_at(epoch, UtcOffset::UTC), "1970-01-01T00:00:00Z");
        assert_eq!(
            ts_at(epoch, UtcOffset::from_hms(8, 0, 0).unwrap()),
            "1970-01-01T08:00:00+08:00"
        );
        assert_eq!(
            ts_at(epoch, UtcOffset::from_hms(-5, 0, 0).unwrap()),
            "1969-12-31T19:00:00-05:00"
        );
    }

    #[test]
    fn ts_round_trips_to_the_same_instant() {
        // 2026-03-08T07:30:00Z: inside the US DST switch window, so a machine
        // with a DST zone must still resolve the offset in force at that time.
        let secs = 1_772_955_000_u64;
        let parsed = OffsetDateTime::parse(&ts(secs), &Rfc3339).unwrap();
        assert_eq!(parsed.unix_timestamp(), secs as i64);
    }

    #[test]
    fn now_ts_is_rfc3339_and_close_to_now() {
        let text = now_ts();
        let parsed = OffsetDateTime::parse(&text, &Rfc3339).unwrap();
        let skew = (parsed.unix_timestamp() - now_secs() as i64).abs();
        assert!(skew <= 5, "now_ts drifted: {text}");
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

    #[test]
    fn queued_log_writer_drops_instead_of_blocking() {
        // A full queue must drop the line and return immediately: this runs on
        // the request path, where blocking on a slow log consumer stalls a
        // tokio worker (and with it unrelated requests).
        let (tx, rx) = sync_channel::<LogMsg>(1);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut w = QueuedWriter {
            tx,
            buf: Vec::new(),
            dropped: dropped.clone(),
        };
        w.write_all(b"first\n").unwrap();
        w.flush().unwrap();
        w.write_all(b"second\n").unwrap();
        w.flush().unwrap();
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(
            matches!(rx.try_recv(), Ok(LogMsg::Line(line)) if line == b"first\n"),
            "the first line must be queued"
        );
        assert!(
            rx.try_recv().is_err(),
            "the second line must have been dropped, not queued"
        );
    }

    /// Vec sink shareable with the writer thread without holding a lock
    /// across recv() (which would deadlock the assertions).
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn flush_marker_drains_queued_lines_before_acking() {
        // The exit-time flush (flush_logs) is the marker protocol: everything
        // enqueued before the marker must be written before the ack — FIFO
        // ordering is what the ack certifies.
        let (tx, rx) = sync_channel::<LogMsg>(4);
        let sink = Arc::new(Mutex::new(Vec::new()));
        let writer_sink = sink.clone();
        let handle = std::thread::spawn(move || {
            let mut writer_sink = SharedSink(writer_sink);
            log_writer_loop(rx, &mut writer_sink)
        });
        tx.try_send(LogMsg::Line(b"a\n".to_vec())).unwrap();
        tx.try_send(LogMsg::Line(b"b\n".to_vec())).unwrap();
        send_flush_marker(&tx, Duration::from_secs(2));
        assert_eq!(
            sink.lock().unwrap().as_slice(),
            b"a\nb\n".as_slice(),
            "the ack must certify the queued lines are written"
        );
        drop(tx);
        handle.join().unwrap();
    }

    struct BrokenSink;

    impl Write for BrokenSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("stdout gone"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("stdout gone"))
        }
    }

    #[test]
    fn broken_log_sink_still_acks_flush_markers() {
        // stdout gone: the loop stops writing but keeps draining. Flush
        // markers must still be acked in drain mode, or the exit-time flush
        // would wait out its whole timeout on every shutdown of such a
        // process. Both arms ack, so no timing is needed: whichever path the
        // marker lands in, this asserts it is released.
        let (tx, rx) = sync_channel::<LogMsg>(4);
        let handle = std::thread::spawn(move || log_writer_loop(rx, &mut BrokenSink));
        tx.try_send(LogMsg::Line(b"a\n".to_vec())).unwrap();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        tx.try_send(LogMsg::Flush(ack_tx)).unwrap();
        ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("drain mode must ack flush markers");
        drop(tx);
        handle.join().unwrap();
    }
}
