use crate::util;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated generations kept on disk: `.1` (newest) through `.{N}` (oldest).
/// Rotation is the log's only retention mechanism, and rejected requests are
/// audited too — without generations, a flood of unauthenticated requests
/// evicts the forensic trail of real traffic (60MB of history at N=5, plus
/// the live file) in a few minutes at loopback speeds.
const AUDIT_GENERATIONS: usize = 5;
/// Bounded queue depth: under disk-write jitter, prefer dropping audit lines (with a counted warning) over blocking the request path.
const QUEUE_DEPTH: usize = 1024;
/// How long the writer idles before flushing buffered lines: under load,
/// lines batch into the BufWriter (flushed at its 8KB capacity), so one
/// syscall carries many lines; when the queue goes quiet, this bounds how
/// long a `tail -f` style consumer waits for the tail.
const FLUSH_IDLE: Duration = Duration::from_millis(50);
/// Per-fingerprint admission interval for rejection rows: a single probing
/// key leaves a steady, complete trail (one row per second) without being
/// able to rotate the log on its own.
const REJECT_FP_INTERVAL: Duration = Duration::from_secs(1);
/// Global rejection admission per window: bounds floods that randomize the
/// fingerprint (each fake token is a fresh bucket, so the per-fingerprint
/// gate alone cannot cap them).
const REJECT_GLOBAL_WINDOW: Duration = Duration::from_secs(1);
const REJECT_GLOBAL_MAX: usize = 100;
/// Per-fingerprint table bound: randomized-token floods would otherwise grow
/// it without limit; when full it resets (buckets re-arm, the global cap
/// still holds).
const REJECT_FP_TABLE_MAX: usize = 4096;
/// First wait after a failed audit write, doubling per consecutive failure and
/// capped: a full disk or a vanished directory would otherwise cost one failed
/// open + one warn line *per record*, turning an audit-on gateway into a
/// syscall spin and a log flood.
const WRITE_BACKOFF_START: Duration = Duration::from_millis(50);
const WRITE_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Audit disk writes run on a dedicated thread + bounded channel:
/// - the request path only does try_send, never a synchronous open/write/chmod on a tokio worker;
/// - a single writer naturally eliminates the race where two concurrent requests trigger the rotation rename at the same time.
pub struct Audit {
    writer: Mutex<Option<Writer>>,
    /// Rejection-side admission state (see record_reject): bounded, checked
    /// on the calling thread before the queue.
    rejects: Mutex<RejectGate>,
    /// Liveness/counters shared with the writer thread, the request path and
    /// the health endpoint.
    state: Arc<AuditState>,
}

/// Writer-thread liveness and counters.
///
/// A dead writer thread used to be completely silent: every record hit
/// `Disconnected` and returned, `is_enabled()` still said yes, and nothing
/// anywhere said audit had stopped recording. `alive`/`closed` make the
/// difference between "closed during shutdown" (expected) and "the writer
/// died" (an alert) visible, and `dropped` gives the health endpoint the loss
/// count that used to live only in a static counter nobody could read.
struct AuditState {
    alive: AtomicBool,
    closed: AtomicBool,
    dropped: AtomicU64,
    dead_warned: AtomicBool,
}

struct RejectGate {
    per_fp: HashMap<String, Instant>,
    window_start: Instant,
    window_count: usize,
    suppressed: u64,
}

impl Default for RejectGate {
    fn default() -> Self {
        Self {
            per_fp: HashMap::new(),
            window_start: Instant::now(),
            window_count: 0,
            suppressed: 0,
        }
    }
}

struct Writer {
    tx: SyncSender<AuditEntry>,
    handle: JoinHandle<()>,
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub ts: String,
    pub rid: String,
    pub route: String,
    pub key_fp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub ms: u64,
    pub bytes_in: usize,
    pub stream: bool,
    pub attempts: u8,
}

impl Audit {
    pub fn disabled() -> Self {
        Self {
            writer: Mutex::new(None),
            rejects: Mutex::new(RejectGate::default()),
            state: Arc::new(AuditState {
                alive: AtomicBool::new(false),
                closed: AtomicBool::new(true),
                dropped: AtomicU64::new(0),
                dead_warned: AtomicBool::new(false),
            }),
        }
    }

    /// Whether rows are being written. The writer is chosen once at startup
    /// (--audit-log or not), so the answer cannot change mid-request; callers
    /// skip `AuditEntry` construction entirely when this is false — its
    /// RFC3339 local-time format plus several String allocations are pure
    /// waste on the default audit-off path. Same lock (and same early-out)
    /// that `record` would take anyway.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Whether audit is doing what it says: disabled counts as healthy, an
    /// enabled audit whose writer thread died does not.
    pub fn healthy(&self) -> bool {
        !self.is_enabled() || self.state.alive.load(Ordering::Relaxed)
    }

    /// Lines dropped so far (queue full or a failed write). Surfaced on the
    /// health endpoint; throttled rejection rows are counted separately in the
    /// log and never reach the writer at all.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    pub fn new(path: PathBuf) -> Self {
        // mode(0o600) only takes effect at creation; if an existing file has overly broad permissions, warn once at startup.
        if path.exists()
            && let Err(e) = util::ensure_private_file(&path, "audit log")
        {
            tracing::warn!(error = %e, "audit log permissions too wide; consider tightening to 0600");
        }
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        let state = Arc::new(AuditState {
            alive: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            dead_warned: AtomicBool::new(false),
        });
        let thread_state = state.clone();
        match std::thread::Builder::new()
            .name("keysink-audit".into())
            .spawn(move || writer_loop(path, rx, thread_state))
        {
            Ok(handle) => Self {
                writer: Mutex::new(Some(Writer { tx, handle })),
                rejects: Mutex::new(RejectGate::default()),
                state,
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to start audit writer thread; audit disabled for this run");
                Self::disabled()
            }
        }
    }

    /// Records only route/fingerprint/status/latency/byte counts; never headers, bodies, or query.
    pub fn record(&self, entry: AuditEntry) {
        let tx = {
            let guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|w| w.tx.clone())
        };
        let Some(tx) = tx else {
            return;
        };
        match tx.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let n = self.state.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 100 == 1 {
                    tracing::warn!(dropped = n, "audit queue full; dropping audit lines");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                // The writer thread is gone. During a clean close that is
                // expected; otherwise audit silently stopped recording, which
                // is exactly what used to go unnoticed (health now shows
                // audit_ok=false, and this line says it once).
                if !self.state.closed.load(Ordering::Relaxed)
                    && !self.state.dead_warned.swap(true, Ordering::Relaxed)
                {
                    tracing::error!(
                        "audit writer thread exited; audit is no longer recording (see /__keysink/health audit_ok)"
                    );
                }
            }
        }
    }

    /// Audits a rejected request (auth failure, disabled route, body limits,
    /// route configuration errors). Rejection rows are the one audit input an
    /// unauthenticated peer controls, so they pass an admission gate before
    /// the queue: per-fingerprint (one row per `REJECT_FP_INTERVAL`) plus a
    /// global cap per window. Suppressed rows are counted, never silent.
    pub fn record_reject(&self, entry: AuditEntry) {
        let admit = {
            let mut gate = self.rejects.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if now.duration_since(gate.window_start) >= REJECT_GLOBAL_WINDOW {
                gate.window_start = now;
                gate.window_count = 0;
            }
            let admitted = if gate.window_count >= REJECT_GLOBAL_MAX {
                false
            } else {
                match gate.per_fp.get_mut(&entry.key_fp) {
                    Some(last) => {
                        if now.duration_since(*last) >= REJECT_FP_INTERVAL {
                            *last = now;
                            true
                        } else {
                            false
                        }
                    }
                    None => {
                        if gate.per_fp.len() >= REJECT_FP_TABLE_MAX {
                            gate.per_fp.clear();
                        }
                        gate.per_fp.insert(entry.key_fp.clone(), now);
                        true
                    }
                }
            };
            if admitted {
                gate.window_count += 1;
            } else {
                gate.suppressed += 1;
                let n = gate.suppressed;
                if n % 100 == 1 {
                    tracing::warn!(
                        suppressed = n,
                        global_per_sec = REJECT_GLOBAL_MAX,
                        "rejection audit rows throttled (1/s per fingerprint); a flood can no longer rotate the log away"
                    );
                }
            }
            admitted
        };
        if admit {
            self.record(entry);
        }
    }

    /// On shutdown, drain the queue and wait for the writer thread to exit so tail audit lines are not lost.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Relaxed);
        let mut guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = guard.take() {
            drop(w.tx);
            let _ = w.handle.join();
        }
    }
}

/// Marks the writer thread dead on every exit path, a panic included.
struct AliveGuard(Arc<AuditState>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.alive.store(false, Ordering::Relaxed);
    }
}

fn writer_loop(path: PathBuf, rx: Receiver<AuditEntry>, state: Arc<AuditState>) {
    let _alive = AliveGuard(state.clone());
    // The handle stays open, buffered: lines batch in a BufWriter instead of
    // costing one write syscall each; the buffer flushes at capacity, when
    // the queue goes idle (FLUSH_IDLE), and before rotation or shutdown. On
    // rotation or write failure the handle becomes None and the next record
    // reopens.
    let mut log = OpenLog {
        file: None,
        written: 0,
    };
    let mut failures = 0u32;
    loop {
        match rx.recv_timeout(FLUSH_IDLE) {
            Ok(entry) => match append(&path, &mut log, &entry) {
                Ok(()) => failures = 0,
                Err(e) => {
                    // Dropping the BufWriter attempts a best-effort flush of
                    // whatever is still buffered; the next record reopens.
                    log.file = None;
                    failures += 1;
                    state.dropped.fetch_add(1, Ordering::Relaxed);
                    if failures == 1 || failures.is_multiple_of(100) {
                        tracing::warn!(
                            error = %e,
                            failures,
                            "failed to write audit log (backing off; audit lines are dropped until it recovers)"
                        );
                    }
                    // Back off instead of retrying the open/write per line: a
                    // full disk would otherwise cost a failed syscall and a
                    // warn line for every record.
                    if !wait_for_recovery(&rx, write_backoff(failures), &state) {
                        break;
                    }
                }
            },
            Err(RecvTimeoutError::Timeout) => flush_dirty(&mut log),
            // Disconnected (after close): drain, flush, exit so tail audit lines are not lost.
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    flush_dirty(&mut log);
}

/// Wait after `failures` consecutive write failures: doubling, capped.
fn write_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    WRITE_BACKOFF_START
        .saturating_mul(1u32 << shift)
        .min(WRITE_BACKOFF_MAX)
}

/// Sleeps out a write backoff while draining (and counting) the queue, so a
/// shutdown (`close`) is noticed immediately instead of waiting for the full
/// backoff. Returns false when the channel closed, i.e. the writer must exit.
fn wait_for_recovery(rx: &Receiver<AuditEntry>, backoff: Duration, state: &AuditState) -> bool {
    let until = Instant::now() + backoff;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        match rx.recv_timeout(left.min(FLUSH_IDLE)) {
            Ok(_) => {
                state.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn flush_dirty(log: &mut OpenLog) {
    let Some(writer) = log.file.as_mut() else {
        return;
    };
    if writer.buffer().is_empty() {
        return;
    }
    if let Err(e) = writer.flush() {
        tracing::warn!(error = %e, "failed to flush audit log");
        log.file = None;
    }
}

struct OpenLog {
    file: Option<BufWriter<File>>,
    written: u64,
}

fn append(path: &Path, log: &mut OpenLog, entry: &AuditEntry) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
    line.push(b'\n');
    if log.file.is_none() {
        rotate_if_needed(path, log)?;
        let file = util::private_open_options(0o600)
            .create(true)
            .append(true)
            .open(path)?;
        log.written = file.metadata()?.len();
        log.file = Some(BufWriter::new(file));
    }
    // Unreachable in practice (the block above just opened it), but the
    // invariant is enforced here instead of asserted with an unwrap.
    let Some(writer) = log.file.as_mut() else {
        return Ok(());
    };
    writer.write_all(&line)?;
    log.written += line.len() as u64;
    if log.written >= MAX_AUDIT_BYTES {
        // Flush before the handle is dropped: the rotation rename happens on
        // the next reopen, and buffered-but-unwritten tail lines must not be
        // left behind in a file that is about to be renamed. (Windows also
        // refuses to rename an open file.)
        writer.flush()?;
        log.file = None;
    }
    Ok(())
}

fn rotate_if_needed(path: &Path, log: &mut OpenLog) -> std::io::Result<()> {
    if log.written < MAX_AUDIT_BYTES {
        return Ok(());
    }
    // Shift the chain one generation older (.N-1 → .N … current → .1),
    // dropping the previous .N. remove-before-rename keeps Windows happy
    // (rename refuses to replace an existing file there); the live file's
    // replacement target (.1) was just vacated by the shift.
    for generation in (2..=AUDIT_GENERATIONS).rev() {
        let from = PathBuf::from(format!("{}.{}", path.display(), generation - 1));
        let to = PathBuf::from(format!("{}.{}", path.display(), generation));
        if from.exists() {
            let _ = std::fs::remove_file(&to);
            std::fs::rename(&from, &to)?;
        }
    }
    let rotated = PathBuf::from(format!("{}.1", path.display()));
    std::fs::rename(path, rotated)?;
    log.written = 0;
    Ok(())
}

impl AuditEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rid: impl Into<String>,
        route: impl Into<String>,
        key_fp: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        bytes_in: usize,
        stream: bool,
    ) -> Self {
        Self {
            ts: util::now_ts(),
            rid: rid.into(),
            route: route.into(),
            key_fp: key_fp.into(),
            method: method.into(),
            path: path.into(),
            status: 0,
            ms: 0,
            bytes_in,
            stream,
            attempts: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_enabled_reflects_the_writer() {
        assert!(!Audit::disabled().is_enabled());
        assert!(
            Audit::disabled().healthy(),
            "audit off is not an unhealthy audit"
        );
        let dir = tempfile::tempdir().unwrap();
        let audit = Audit::new(dir.path().join("audit.jsonl"));
        assert!(audit.is_enabled());
        assert!(audit.healthy());
        audit.close();
        assert!(!audit.is_enabled(), "close() takes the writer out");
    }

    #[test]
    fn dead_writer_is_reported_unhealthy() {
        // Simulate the writer thread dying under a still-enabled audit (a
        // panic in the writer): `is_enabled` keeps saying yes, so health must
        // be the thing that notices.
        let dir = tempfile::tempdir().unwrap();
        let audit = Audit::new(dir.path().join("audit.jsonl"));
        audit.state.alive.store(false, Ordering::Relaxed);
        assert!(audit.is_enabled());
        assert!(!audit.healthy(), "a dead writer must not look healthy");
        audit.close();
    }

    #[test]
    fn write_backoff_doubles_and_caps() {
        assert_eq!(write_backoff(1), WRITE_BACKOFF_START);
        assert_eq!(write_backoff(2), WRITE_BACKOFF_START * 2);
        assert_eq!(write_backoff(30), WRITE_BACKOFF_MAX);
    }

    #[test]
    fn recovery_wait_stops_on_close() {
        // close() drops the sender; the writer's backoff wait must notice and
        // exit instead of sleeping out the whole backoff (a shutdown would
        // otherwise hang for up to WRITE_BACKOFF_MAX).
        let (tx, rx) = sync_channel::<AuditEntry>(4);
        let state = AuditState {
            alive: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            dead_warned: AtomicBool::new(false),
        };
        drop(tx);
        assert!(!wait_for_recovery(&rx, Duration::from_secs(30), &state));
    }

    #[test]
    fn queued_entries_are_counted_as_dropped_while_backing_off() {
        let (tx, rx) = sync_channel::<AuditEntry>(4);
        let state = AuditState {
            alive: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            dead_warned: AtomicBool::new(false),
        };
        tx.try_send(AuditEntry::new("R9", "r", "fp", "GET", "/x", 0, false))
            .unwrap();
        assert!(wait_for_recovery(&rx, Duration::from_millis(1), &state));
        assert_eq!(state.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn writes_one_json_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::new(path.clone());
        let mut entry =
            AuditEntry::new("R1", "claude", "abcd1234", "POST", "/v1/messages", 12, true);
        entry.status = 200;
        entry.ms = 42;
        audit.record(entry);
        audit.close(); // assert only after the queue is drained
        let text = std::fs::read_to_string(path).unwrap();
        assert_eq!(text.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["route"], "claude");
        assert_eq!(v["status"], 200);
        assert!(v.get("query").is_none());
    }

    #[test]
    fn rotates_after_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, vec![b'x'; MAX_AUDIT_BYTES as usize + 1]).unwrap();
        let audit = Audit::new(path.clone());
        // The first record pushes written past the limit (forcing the next close); the second opens a new file.
        audit.record(AuditEntry::new("R3", "r", "fp", "GET", "/x", 0, false));
        audit.record(AuditEntry::new("R4", "r", "fp", "GET", "/x", 0, false));
        audit.close();

        let rotated = dir.path().join("audit.jsonl.1");
        assert!(rotated.exists());
        assert!(std::fs::metadata(&rotated).unwrap().len() > MAX_AUDIT_BYTES);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(
            text.contains("R4"),
            "new file after rotation should contain only the last entry: {text}"
        );
    }

    #[test]
    fn record_after_close_is_silent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Audit::new(dir.path().join("audit.jsonl"));
        audit.close();
        audit.record(AuditEntry::new("R2", "r", "fp", "GET", "/x", 0, false));
        assert!(!dir.path().join("audit.jsonl").exists());
    }

    #[test]
    fn rotation_shifts_generations_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "current").unwrap();
        std::fs::write(dir.path().join("audit.jsonl.1"), "gen1").unwrap();
        std::fs::write(dir.path().join("audit.jsonl.2"), "gen2").unwrap();
        let mut log = OpenLog {
            file: None,
            written: u64::MAX, // force rotation
        };
        rotate_if_needed(&path, &mut log).unwrap();
        assert_eq!(log.written, 0);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("audit.jsonl.1")).unwrap(),
            "current"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("audit.jsonl.2")).unwrap(),
            "gen1"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("audit.jsonl.3")).unwrap(),
            "gen2"
        );
        assert!(!dir.path().join("audit.jsonl.4").exists());
        assert!(!path.exists(), "the live file moves into .1 on rotation");
    }

    #[test]
    fn rotation_drops_the_oldest_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "current").unwrap();
        for generation in 1..=AUDIT_GENERATIONS {
            std::fs::write(
                dir.path().join(format!("audit.jsonl.{generation}")),
                format!("gen{generation}"),
            )
            .unwrap();
        }
        let mut log = OpenLog {
            file: None,
            written: u64::MAX,
        };
        rotate_if_needed(&path, &mut log).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("audit.jsonl.5")).unwrap(),
            format!("gen{}", AUDIT_GENERATIONS - 1)
        );
        assert!(
            !dir.path()
                .join(format!("audit.jsonl.{}", AUDIT_GENERATIONS + 1))
                .exists()
        );
    }

    #[test]
    fn rejection_rows_throttle_per_fingerprint_and_globally() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::new(path.clone());
        audit.record_reject(AuditEntry::new("A1", "-", "fpX", "GET", "/x", 0, false));
        audit.record_reject(AuditEntry::new("A2", "-", "fpX", "GET", "/x", 0, false));
        // Unique fingerprints (randomized-token flood): admitted only up to
        // the global window cap, which fpX's first row already counted against.
        for i in 0..150 {
            audit.record_reject(AuditEntry::new(
                format!("U{i}"),
                "-",
                format!("fp{i}"),
                "GET",
                "/x",
                0,
                false,
            ));
        }
        audit.record(AuditEntry::new(
            "F1",
            "claude",
            "fpOK",
            "POST",
            "/v1/messages",
            12,
            true,
        ));
        audit.close();

        let text = std::fs::read_to_string(path).unwrap();
        let count = text.lines().count();
        assert!(text.contains("\"A1\""));
        assert!(
            !text.contains("\"A2\""),
            "same-fingerprint repeat within the interval must be suppressed"
        );
        assert_eq!(
            count,
            1 + REJECT_GLOBAL_MAX,
            "gate admits the window cap plus the forward"
        );
    }
}
