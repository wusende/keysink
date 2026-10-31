use crate::util;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

const MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;
/// Bounded queue depth: under disk-write jitter, prefer dropping audit lines (with a counted warning) over blocking the request path.
const QUEUE_DEPTH: usize = 1024;

/// Audit disk writes run on a dedicated thread + bounded channel:
/// - the request path only does try_send, never a synchronous open/write/chmod on a tokio worker;
/// - a single writer naturally eliminates the race where two concurrent requests trigger the rotation rename at the same time.
pub struct Audit {
    writer: Mutex<Option<Writer>>,
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
        }
    }

    pub fn new(path: PathBuf) -> Self {
        // mode(0o600) only takes effect at creation; if an existing file has overly broad permissions, warn once at startup.
        if path.exists()
            && let Err(e) = util::ensure_private_file(&path, "audit log")
        {
            tracing::warn!(error = %e, "audit log permissions too wide; consider tightening to 0600");
        }
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        match std::thread::Builder::new()
            .name("keysink-audit".into())
            .spawn(move || writer_loop(path, rx))
        {
            Ok(handle) => Self {
                writer: Mutex::new(Some(Writer { tx, handle })),
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
        if let Err(TrySendError::Full(_)) = tx.try_send(entry) {
            static DROPPED: AtomicU64 = AtomicU64::new(0);
            let n = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 100 == 1 {
                tracing::warn!(dropped = n, "audit queue full; dropping audit lines");
            }
        }
        // Disconnected (after close) is silent: audit is no longer needed during shutdown.
    }

    /// On shutdown, drain the queue and wait for the writer thread to exit so tail audit lines are not lost.
    pub fn close(&self) {
        let mut guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = guard.take() {
            drop(w.tx);
            let _ = w.handle.join();
        }
    }
}

fn writer_loop(path: PathBuf, rx: Receiver<AuditEntry>) {
    // The handle stays open: one write per line, not the open+write+close
    // syscall triple per line; on rotation or write failure it becomes None
    // and the next record reopens.
    let mut log = OpenLog {
        file: None,
        written: 0,
    };
    while let Ok(entry) = rx.recv() {
        if let Err(e) = append(&path, &mut log, &entry) {
            tracing::warn!(error = %e, "failed to write audit log");
            log.file = None;
        }
    }
}

struct OpenLog {
    file: Option<File>,
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
        log.file = Some(file);
    }
    log.file.as_mut().unwrap().write_all(&line)?;
    log.written += line.len() as u64;
    if log.written >= MAX_AUDIT_BYTES {
        // Close the handle before the rename: Windows refuses to rename an open file.
        log.file = None;
    }
    Ok(())
}

fn rotate_if_needed(path: &Path, log: &mut OpenLog) -> std::io::Result<()> {
    if log.written < MAX_AUDIT_BYTES {
        return Ok(());
    }
    let rotated = PathBuf::from(format!("{}.1", path.display()));
    let _ = std::fs::remove_file(&rotated);
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
}
