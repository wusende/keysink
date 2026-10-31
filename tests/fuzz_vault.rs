//! Scenario-level fuzzing around the vault: corruption matrix, concurrent
//! writers, and the hot-reload watcher.
//!
//! Corruption cases are deterministic (seeded LCG) so failures reproduce; the
//! core invariant everywhere is "corrupt input must surface as a clean error
//! or a `from_backup` fallback, never a panic".

use age::secrecy::ExposeSecret;
use keysink::model::{Auth, Route, Store};
use keysink::store::{self, Paths};
use keysink::vkey;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn route() -> Route {
    Route::new(
        vkey::generate(),
        "https://upstream.invalid".into(),
        "inline-secret".into(),
        Auth::Bearer,
        BTreeMap::new(),
    )
}

fn seed_vault(paths: &Paths) -> age::x25519::Identity {
    store::init(paths, false, "test-password").expect("init vault");
    store::update(paths, |s| {
        s.routes.insert("r1".into(), route());
        Ok(())
    })
    .unwrap();
    store::update(paths, |s| {
        s.routes.insert("r2".into(), route());
        Ok(())
    })
    .unwrap();
    store::load_identity(paths).unwrap()
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn fresh_dir(tag: &str) -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::vault(dir.path().join(tag));
    (dir, paths)
}

/// Per-case corruption plan: mutated store, untouched .bak, mutated key.
struct CasePlan {
    name: String,
    store: Vec<u8>,
    bak: Vec<u8>,
    key: Vec<u8>,
}

/// Deterministic splitmix-style generator so failures reproduce.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

// ---------- corruption matrix ----------

#[test]
fn vault_corruption_matrix_never_panics() {
    let (_base_dir, base_paths) = fresh_dir("base");
    seed_vault(&base_paths);
    let key = std::fs::read(base_paths.master_key()).unwrap();
    let store_ct = std::fs::read(base_paths.store()).unwrap();
    let bak_ct = std::fs::read(base_paths.store_bak()).unwrap();
    assert!(!store_ct.is_empty() && !bak_ct.is_empty());

    let mut rng = Lcg(0xA5A5_5A5A);
    let wrong_identity = age::x25519::Identity::generate().to_string();
    let cases: Vec<CasePlan> = (0..24)
        .map(|i| {
            let mut s = store_ct.clone();
            let b = bak_ct.clone();
            let mut k = key.clone();
            match i % 8 {
                0 => {
                    s.truncate(rng.below(s.len() + 1));
                }
                1 => {
                    for _ in 0..(1 + rng.below(16)) {
                        let pos = rng.below(s.len());
                        s[pos] ^= (rng.next() % 255 + 1) as u8;
                    }
                }
                2 => {
                    let start = rng.below(s.len());
                    let end = (start + 1 + rng.below(64)).min(s.len());
                    for byte in &mut s[start..end] {
                        *byte = 0;
                    }
                }
                3 => s.extend_from_slice(&[0x07; 128]),
                4 => s = Vec::new(),
                5 => {
                    // swap in a passphrase-encrypted export as the store
                    s = passphrase_blob("not-the-vault-pass");
                }
                6 => {
                    // well-formed but wrong identity: decrypt mismatch path
                    k = wrong_identity.expose_secret().as_bytes().to_vec();
                }
                _ => {
                    s = store_ct[..store_ct.len() / 2].to_vec();
                    s.extend_from_slice(&store_ct[..store_ct.len() / 2]);
                }
            }
            CasePlan {
                name: format!("case{i:02}"),
                store: s,
                bak: b,
                key: k,
            }
        })
        .collect();

    for case in &cases {
        let (_dir, paths) = fresh_dir(&case.name);
        std::fs::create_dir_all(&paths.home).unwrap();
        write_private(&paths.master_key(), &case.key);
        write_private(&paths.store(), &case.store);
        write_private(&paths.store_bak(), &case.bak);

        let outcome = std::panic::catch_unwind(|| store::unlock(&paths));
        match outcome {
            Err(_) => panic!("unlock panicked on corruption case {}", case.name),
            Ok(Err(e)) => assert!(!e.to_string().is_empty()),
            Ok(Ok(unlocked)) => {
                // A successful unlock must yield a structurally valid store;
                // if it fell back to .bak, that must be flagged.
                unlocked.store.validate().unwrap_or_else(|e| {
                    panic!("case {}: unlocked store failed validate: {e}", case.name)
                });
                assert_eq!(unlocked.store.version, 1);
                if unlocked.from_backup {
                    assert!(
                        paths.store_bak().exists(),
                        "case {}: from_backup without a .bak on disk",
                        case.name
                    );
                }
            }
        }
    }
}

fn passphrase_blob(pass: &str) -> Vec<u8> {
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(pass));
    let mut out = Vec::new();
    let mut w = encryptor.wrap_output(&mut out).unwrap();
    w.write_all(br#"{"version":1,"routes":{}}"#).unwrap();
    w.finish().unwrap();
    out
}

#[test]
fn vault_truncation_sweep_never_panics() {
    let (_base_dir, base_paths) = fresh_dir("sweep");
    seed_vault(&base_paths);
    let ct = std::fs::read(base_paths.store()).unwrap();

    let key_bytes = std::fs::read(base_paths.master_key()).unwrap();
    for cut in (0..ct.len()).step_by(7) {
        let (_dir, paths) = fresh_dir("cut");
        std::fs::create_dir_all(&paths.home).unwrap();
        write_private(&paths.master_key(), &key_bytes);
        write_private(&paths.store(), &ct[..cut]);

        match std::panic::catch_unwind(|| store::unlock(&paths)) {
            Err(_) => panic!("unlock panicked on truncation at {cut}"),
            Ok(Ok(_)) => panic!("truncated ciphertext (cut={cut}) must not decrypt"),
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn vault_double_corruption_reports_both_halves() {
    let (_base_dir, base_paths) = fresh_dir("both");
    seed_vault(&base_paths);
    let (_dir, paths) = fresh_dir("victim");
    std::fs::create_dir_all(&paths.home).unwrap();
    write_private(
        &paths.master_key(),
        &std::fs::read(base_paths.master_key()).unwrap(),
    );
    write_private(&paths.store(), b"garbage-primary");
    write_private(&paths.store_bak(), b"garbage-backup");

    let err = match store::unlock(&paths) {
        Ok(_) => panic!("double corruption must not unlock"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("primary") && err.contains("backup"),
        "error should name both halves: {err}"
    );
}

// ---------- concurrent writers ----------

#[test]
fn concurrent_store_update_no_lost_writes() {
    let (_dir, paths) = fresh_dir("conc");
    store::init(&paths, false, "test-password").unwrap();

    const WRITERS: usize = 6;
    const ROUNDS: usize = 10;
    let done = Arc::new(AtomicBool::new(false));
    let reader_max = Arc::new(AtomicU64::new(0));
    let reader_err = Arc::new(AtomicU64::new(0));

    let mut writers = Vec::new();
    for t in 0..WRITERS {
        let paths = paths.clone();
        writers.push(std::thread::spawn(move || {
            for j in 0..ROUNDS {
                store::update(&paths, |s| {
                    s.routes.insert(format!("t{t}-{j}"), route());
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("writer {t} round {j} failed: {e}"));
            }
        }));
    }

    let reader_done = done.clone();
    let reader_paths = paths.clone();
    let max_out = reader_max.clone();
    let err_out = reader_err.clone();
    let reader = std::thread::spawn(move || {
        let mut last = 0u64;
        while !reader_done.load(Ordering::Relaxed) {
            match store::unlock(&reader_paths) {
                Ok(unlocked) => {
                    let n = unlocked.store.routes.len() as u64;
                    // Atomic writes are rename-based: readers must observe
                    // whole snapshots with a monotonically non-decreasing
                    // route count in this add-only workload.
                    assert!(n >= last, "route count went backwards: {n} < {last}");
                    last = last.max(n);
                    max_out.store(last, Ordering::Relaxed);
                }
                Err(e) => {
                    err_out.fetch_add(1, Ordering::Relaxed);
                    panic!("concurrent read failed: {e}");
                }
            }
        }
    });

    for w in writers {
        w.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    reader.join().unwrap();

    // The reader may lag the final write when it stops; the monotonic check
    // inside the loop is the actual race invariant, completeness is asserted
    // by the final unlock below.
    assert!(
        reader_max.load(Ordering::Relaxed) <= (WRITERS * ROUNDS) as u64,
        "reader observed more routes than were ever written"
    );
    let unlocked = store::unlock(&paths).unwrap();
    assert_eq!(
        unlocked.store.routes.len(),
        WRITERS * ROUNDS,
        "all concurrent writes must survive"
    );
    assert!(!unlocked.from_backup);
    assert_eq!(reader_err.load(Ordering::Relaxed), 0);
}

// ---------- hot-reload watcher ----------

#[tokio::test]
async fn watcher_hot_reload_scenarios() {
    let (_dir, paths) = fresh_dir("watch");
    seed_vault(&paths); // r1 + r2 on disk

    let state = Arc::new(keysink::proxy::AppState {
        snapshot: arc_swap::ArcSwap::from_pointee(keysink::proxy::Snapshot {
            store: Arc::new(Store::new()),
            table: keysink::vkey::RouteTable::build(&Store::new()).unwrap(),
            from_backup: false,
        }),
        clients: keysink::proxy::ProxyClients::new().unwrap(),
        retry: keysink::retry::RetryPolicy::default(),
        body_limit: 32 * 1024 * 1024,
        audit: keysink::audit::Audit::disabled(),
        started: Instant::now(),
    });
    keysink::proxy::spawn_watcher(state.clone(), paths.clone());

    let routes = |state: &Arc<keysink::proxy::AppState>| {
        let snap = state.snapshot.load();
        (snap.table.len(), snap.from_backup)
    };
    async fn wait_for(secs: u64, cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    // 1. Disk write is picked up (r1 + r2 → r3 added).
    let p = paths.clone();
    tokio::task::spawn_blocking(move || {
        store::update(&p, |s| {
            s.routes.insert("r3".into(), route());
            Ok(())
        })
        .unwrap();
    })
    .await
    .unwrap();
    assert!(
        wait_for(8, &|| routes(&state) == (3, false)).await,
        "watcher should adopt the added route, got {:?}",
        routes(&state)
    );

    // 2. Corrupt the primary: watcher must refuse the stale .bak downgrade
    //    (memory keeps the latest good snapshot, revoked vkeys stay dead).
    let stale = routes(&state);
    write_private(&paths.store(), b"corrupted-primary");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        routes(&state),
        stale,
        "watcher must not downgrade a good snapshot to the .bak fallback"
    );

    // 3. Repair via update(): unlock falls back to .bak (r1), r4 is added,
    //    primary is rewritten — watcher adopts the repaired disk state.
    let p = paths.clone();
    tokio::task::spawn_blocking(move || {
        store::update(&p, |s| {
            s.routes.insert("r4".into(), route());
            Ok(())
        })
        .unwrap();
    })
    .await
    .unwrap();
    // Wait on membership, not on the count: the pre-corruption memory
    // snapshot already matches (3, false).
    assert!(
        wait_for(8, &|| {
            let snap = state.snapshot.load();
            !snap.from_backup
                && snap.store.routes.contains_key("r4")
                && !snap.store.routes.contains_key("r3")
        })
        .await,
        "watcher should adopt the repaired store, got {:?}",
        routes(&state)
    );

    // 4. Corrupt again: .bak (pre-r4) is still older than memory → refuse.
    let stale = routes(&state);
    write_private(&paths.store(), b"corrupted-again");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        routes(&state),
        stale,
        "second corruption must not downgrade either"
    );

    // 5. Full repair (r1..r4) is adopted.
    let p = paths.clone();
    let identity = store::load_identity(&p).unwrap();
    tokio::task::spawn_blocking(move || {
        let mut s = Store::new();
        s.routes.insert("r1".into(), route());
        s.routes.insert("r4".into(), route());
        s.routes.insert("r5".into(), route());
        store::save_store(&p, &s, &identity).unwrap();
    })
    .await
    .unwrap();
    assert!(
        wait_for(8, &|| {
            state.snapshot.load().store.routes.contains_key("r5")
        })
        .await,
        "watcher should adopt the fully repaired store, got {:?}",
        routes(&state)
    );
}
