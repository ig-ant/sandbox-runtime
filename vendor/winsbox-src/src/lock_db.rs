//! Phase 5A — SQLite state-DB foundation for share-mode / ACL hybrid FS
//! isolation. Infrastructure only: 5A maintains rows silently; 5B/5C/5D
//! will add `acquire_share_mode`, `acquire_acl_stamp`, and broker-to-
//! broker pipe discovery on top.
//!
//! Schema (see [[winsbox-phase5-share-mode-hybrid]]):
//!   - `proc_sessions(broker_pid, pipe_name, process_create_time, started_at)`
//!     One row per live broker. `process_create_time` is the broker's
//!     creation FILETIME (100-ns since 1601-01-01) so PID-recycle on
//!     the next startup can be detected.
//!   - `path_locks(canonical_path, broker_pid, kind, acquired_at)` —
//!     5B/5C populate. CASCADEs from `proc_sessions`.
//!   - `acl_snapshots(canonical_path, original_dacl, stamped_dacl, ...)`
//!     5C populates; persists across broker restarts so the LAST broker
//!     to release a path can restore the user's original DACL.
//!
//! DB lives at `%LOCALAPPDATA%\winsbox\state.db` (per-user; the parent
//! dir's default DACL is user-only, so the DB inherits same).

use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version persisted in `PRAGMA user_version`. Bump when the
/// schema changes incompatibly; for now we just create-if-missing.
const SCHEMA_VERSION: i64 = 1;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS proc_sessions (
    broker_pid           INTEGER PRIMARY KEY,
    pipe_name            TEXT    NOT NULL,
    process_create_time  INTEGER NOT NULL,
    started_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS path_locks (
    canonical_path TEXT    NOT NULL,
    broker_pid     INTEGER NOT NULL,
    kind           TEXT    NOT NULL CHECK (kind IN ('share_mode','acl_stamp')),
    acquired_at    INTEGER NOT NULL,
    PRIMARY KEY (canonical_path, broker_pid),
    FOREIGN KEY (broker_pid) REFERENCES proc_sessions(broker_pid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS acl_snapshots (
    canonical_path           TEXT    PRIMARY KEY,
    original_dacl            BLOB    NOT NULL,
    stamped_dacl             BLOB    NOT NULL,
    captured_by_broker_pid   INTEGER NOT NULL,
    captured_at              INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS path_locks_by_path ON path_locks (canonical_path);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    ShareMode,
    AclStamp,
}

impl LockKind {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            LockKind::ShareMode => "share_mode",
            LockKind::AclStamp => "acl_stamp",
        }
    }

    #[allow(dead_code)]
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "share_mode" => Ok(LockKind::ShareMode),
            "acl_stamp" => Ok(LockKind::AclStamp),
            other => Err(anyhow!("unknown LockKind {other:?}")),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProcSession {
    pub broker_pid: u32,
    pub pipe_name: String,
    pub process_create_time: i64,
    pub started_at: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PathLock {
    pub canonical_path: String,
    pub broker_pid: u32,
    pub kind: LockKind,
    pub acquired_at: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AclSnapshot {
    pub canonical_path: String,
    pub original_dacl: Vec<u8>,
    pub stamped_dacl: Vec<u8>,
    pub captured_by_broker_pid: u32,
    pub captured_at: i64,
}

pub struct LockDb {
    conn: Connection,
}

impl LockDb {
    /// Open (or create) the per-user state DB at
    /// `%LOCALAPPDATA%\winsbox\state.db` in WAL mode with the schema
    /// applied.
    pub fn open() -> Result<Self> {
        let p = default_db_path()?;
        Self::open_at(&p)
    }

    /// Open (or create) at an arbitrary path. Used by tests; also the
    /// implementation backing `open()`.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("sqlite open {}", path.display()))?;
        // WAL gives us concurrent readers / single writer with crash
        // safety. `synchronous=NORMAL` is the recommended companion
        // and is still durable across power loss for WAL.
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("PRAGMA journal_mode=WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("PRAGMA synchronous=NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("PRAGMA foreign_keys=ON")?;
        conn.execute_batch(SCHEMA_SQL).context("apply schema")?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("PRAGMA user_version")?;
        Ok(Self { conn })
    }

    /// INSERT a row for the current broker. `pipe_name` is the path
    /// the broker WILL listen on. Storing it now lets 5D's clients
    /// discover the pipe via the DB.
    ///
    /// If the row already exists (e.g. the prior process with this PID
    /// died without `end_session`, and crash recovery hasn't pruned it
    /// because we're being called twice in one process), we REPLACE so
    /// the freshest pipe_name / create_time wins.
    pub fn begin_session(&self, broker_pid: u32, pipe_name: &str) -> Result<()> {
        let create_time = current_process_create_time()?;
        let started_at = unix_epoch_seconds();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO proc_sessions
                    (broker_pid, pipe_name, process_create_time, started_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![broker_pid as i64, pipe_name, create_time, started_at],
            )
            .context("INSERT proc_sessions")?;
        Ok(())
    }

    /// Remove the current broker's session row. CASCADE removes its
    /// `path_locks`. Called on graceful broker exit.
    pub fn end_session(&self, broker_pid: u32) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM proc_sessions WHERE broker_pid = ?1",
                params![broker_pid as i64],
            )
            .context("DELETE proc_sessions")?;
        Ok(())
    }

    /// Phase 5B: INSERT one `path_locks` row of kind `share_mode` for
    /// the current broker. Caller is responsible for already holding
    /// the underlying `HANDLE` open — this just records the bookkeeping
    /// row so other brokers (5D) can find us.
    pub fn insert_share_mode_lock(
        &self,
        broker_pid: u32,
        canonical_path: &str,
    ) -> Result<()> {
        let now = unix_epoch_seconds();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO path_locks
                    (canonical_path, broker_pid, kind, acquired_at)
                 VALUES (?1, ?2, 'share_mode', ?3)",
                params![canonical_path, broker_pid as i64, now],
            )
            .context("INSERT path_locks(share_mode)")?;
        Ok(())
    }

    /// Phase 5B: DELETE all of THIS broker's share-mode rows in one
    /// transaction. Called from the `ShareModeLocks` RAII Drop. Closing
    /// the underlying `HANDLE`s is the caller's responsibility — this
    /// only removes the DB bookkeeping.
    pub fn delete_my_share_mode_locks(&self, broker_pid: u32) -> Result<usize> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin delete-share-mode tx")?;
        let n = tx
            .execute(
                "DELETE FROM path_locks
                 WHERE broker_pid = ?1 AND kind = 'share_mode'",
                params![broker_pid as i64],
            )
            .context("DELETE path_locks(share_mode)")?;
        tx.commit().context("commit delete-share-mode tx")?;
        Ok(n)
    }

    /// Phase 5C: INSERT a row into `path_locks` of kind `acl_stamp` for
    /// the current broker, optionally inserting / updating the
    /// matching `acl_snapshots` row in the same transaction.
    ///
    /// `snapshot_if_new` is `Some(original_dacl_bytes, stamped_dacl_bytes)`
    /// the first time a path is stamped (broker that actually wrote the
    /// DACL must pass these); subsequent brokers picking up a
    /// previously-stamped path pass `None` and just record their
    /// holder row.
    pub fn insert_acl_stamp_lock(
        &self,
        broker_pid: u32,
        canonical_path: &str,
        snapshot_if_new: Option<(&[u8], &[u8])>,
    ) -> Result<()> {
        let now = unix_epoch_seconds();
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin insert_acl_stamp_lock tx")?;
        if let Some((orig, stamped)) = snapshot_if_new {
            // INSERT OR IGNORE so a racing broker that beat us to the
            // snapshot insert doesn't lose its row. The "real" check
            // for whether we should stamp happens in the SELECT before
            // calling this fn — this is the "and if anyone slipped in
            // between, defer to them" safety net.
            tx.execute(
                "INSERT OR IGNORE INTO acl_snapshots
                    (canonical_path, original_dacl, stamped_dacl,
                     captured_by_broker_pid, captured_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    canonical_path,
                    orig,
                    stamped,
                    broker_pid as i64,
                    now
                ],
            )
            .context("INSERT acl_snapshots")?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO path_locks
                (canonical_path, broker_pid, kind, acquired_at)
             VALUES (?1, ?2, 'acl_stamp', ?3)",
            params![canonical_path, broker_pid as i64, now],
        )
        .context("INSERT path_locks(acl_stamp)")?;
        tx.commit().context("commit insert_acl_stamp_lock tx")?;
        Ok(())
    }

    /// Phase 5C: query whether an `acl_snapshots` row exists for the
    /// given canonical_path. Used by `acquire_acl_stamp` to decide
    /// whether to call `SetSecurityInfo` (no row → stamp) or just
    /// add a holder row (row exists → reuse).
    pub fn acl_snapshot_exists(&self, canonical_path: &str) -> Result<bool> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM acl_snapshots WHERE canonical_path = ?1",
                params![canonical_path],
                |r| r.get(0),
            )
            .context("SELECT count acl_snapshots")?;
        Ok(n > 0)
    }

    /// Phase 5C: SELECT the snapshot pair for a path. Returns
    /// `(original_dacl, stamped_dacl)` — bytes blobs. Used by the
    /// release path to compare against the current DACL before
    /// restoring.
    pub fn get_acl_snapshot(
        &self,
        canonical_path: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT original_dacl, stamped_dacl FROM acl_snapshots
                 WHERE canonical_path = ?1",
            )
            .context("prepare SELECT acl_snapshots")?;
        let mut rows = stmt
            .query(params![canonical_path])
            .context("query acl_snapshots")?;
        if let Some(row) = rows.next().context("row acl_snapshots")? {
            let orig: Vec<u8> = row.get(0).context("col original_dacl")?;
            let stamped: Vec<u8> = row.get(1).context("col stamped_dacl")?;
            Ok(Some((orig, stamped)))
        } else {
            Ok(None)
        }
    }

    /// Phase 5C: DELETE one `acl_snapshots` row.
    pub fn delete_acl_snapshot(&self, canonical_path: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM acl_snapshots WHERE canonical_path = ?1",
                params![canonical_path],
            )
            .context("DELETE acl_snapshots")?;
        Ok(())
    }

    /// Phase 5C release-step transaction: delete this broker's holder
    /// row for `canonical_path` and return how many `acl_stamp` rows
    /// remain on the same path *after* the delete. If the returned
    /// count is 0, the caller is the last holder and should restore.
    pub fn delete_my_acl_stamp_holder(
        &self,
        broker_pid: u32,
        canonical_path: &str,
    ) -> Result<i64> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin delete-acl-stamp-holder tx")?;
        tx.execute(
            "DELETE FROM path_locks
             WHERE broker_pid = ?1
               AND canonical_path = ?2
               AND kind = 'acl_stamp'",
            params![broker_pid as i64, canonical_path],
        )
        .context("DELETE path_locks(acl_stamp) for self")?;
        let remaining: i64 = tx
            .query_row(
                "SELECT count(*) FROM path_locks
                 WHERE canonical_path = ?1 AND kind = 'acl_stamp'",
                params![canonical_path],
                |r| r.get(0),
            )
            .context("count remaining acl_stamp holders")?;
        tx.commit().context("commit delete-acl-stamp-holder tx")?;
        Ok(remaining)
    }

    /// Scan `proc_sessions` for dead PIDs and prune them + their
    /// CASCADE-deleted `path_locks`. For each path whose last
    /// `acl_stamp` holder is being pruned, attempt a check-then-restore
    /// of the original DACL via `acl_restore` (the closure) and
    /// remove the `acl_snapshots` row afterwards.
    ///
    /// `acl_restore(canonical_path, original_dacl_bytes,
    ///              stamped_dacl_bytes)` should return `Ok(true)` if
    /// the restore landed cleanly, `Ok(false)` if the current DACL no
    /// longer matched stamped (and we should NOT restore), or `Err`
    /// for a GetNamedSecurityInfoW / SetNamedSecurityInfoW failure
    /// (logged + treated as "leave it").
    ///
    /// Returns count of pruned sessions.
    #[allow(dead_code)]
    pub fn crash_recovery_scan(&self) -> Result<u32> {
        self.crash_recovery_scan_with(|_, _, _| Ok(false))
    }

    /// Like `crash_recovery_scan` but the caller supplies an
    /// `acl_restore` callback. Phase 5C's `main.rs` plumbing passes a
    /// closure that calls into `acl::restore_full_sd` after a current-
    /// DACL match. Non-Windows / non-5C callers use the default scan
    /// above which logs orphaned stamps and moves on.
    pub fn crash_recovery_scan_with(
        &self,
        mut acl_restore: impl FnMut(&str, &[u8], &[u8]) -> Result<bool>,
    ) -> Result<u32> {
        let mut stmt = self
            .conn
            .prepare("SELECT broker_pid, process_create_time FROM proc_sessions")
            .context("SELECT proc_sessions")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .context("query_map proc_sessions")?;
        let mut dead: Vec<i64> = Vec::new();
        for r in rows {
            let (pid_i, recorded_create) = r.context("row proc_sessions")?;
            let pid_u = pid_i as u32;
            if is_session_dead(pid_u, recorded_create) {
                dead.push(pid_i);
            }
        }
        drop(stmt);

        if dead.is_empty() {
            return Ok(0);
        }

        // Pre-prune: collect orphaned acl_stamp paths per dead pid.
        // For each path, after the CASCADE delete (below), if no
        // other broker still holds it, attempt restore.
        let mut orphan_paths: Vec<String> = Vec::new();
        for &pid_i in &dead {
            let mut s = self
                .conn
                .prepare(
                    "SELECT canonical_path FROM path_locks
                     WHERE broker_pid = ?1 AND kind = 'acl_stamp'",
                )
                .context("SELECT orphan acl_stamp rows")?;
            let iter = s
                .query_map(params![pid_i], |row| row.get::<_, String>(0))
                .context("query_map orphan acl_stamp")?;
            for row in iter {
                orphan_paths.push(row.context("row acl_stamp")?);
            }
        }

        // Now DELETE the sessions (CASCADE removes path_locks).
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin crash-recovery tx")?;
        for &pid_i in &dead {
            tx.execute(
                "DELETE FROM proc_sessions WHERE broker_pid = ?1",
                params![pid_i],
            )
            .context("DELETE dead proc_sessions")?;
        }
        tx.commit().context("commit crash-recovery tx")?;

        // Phase 5C: for each orphan path, check whether ANY live
        // acl_stamp holder remains after the CASCADE prune. If not,
        // we own the cleanup — try restore (via caller's closure) and
        // delete the acl_snapshots row regardless of restore outcome.
        // Deduplicate paths to avoid double-restore attempts.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for path in orphan_paths {
            if !seen.insert(path.clone()) {
                continue;
            }
            let still_held: i64 = self
                .conn
                .query_row(
                    "SELECT count(*) FROM path_locks
                     WHERE canonical_path = ?1 AND kind = 'acl_stamp'",
                    params![&path],
                    |r| r.get(0),
                )
                .context("count remaining acl_stamp holders post-prune")?;
            if still_held > 0 {
                // A live broker still holds an ACL stamp on this path
                // — leave the snapshot alone; it'll Drop properly.
                continue;
            }
            // Get the snapshot pair, dispatch to the restore callback,
            // delete the snapshot row regardless of the outcome (we
            // won't get another chance).
            let snap = self.get_acl_snapshot(&path)?;
            if let Some((orig, stamped)) = snap {
                match acl_restore(&path, &orig, &stamped) {
                    Ok(true) => {
                        eprintln!(
                            "[winsbox lock_db] crash recovery: restored DACL on {path}"
                        );
                    }
                    Ok(false) => {
                        eprintln!(
                            "[winsbox lock_db] WARNING: crash recovery on {path}: \
                             current DACL no longer matches stamped — leaving alone"
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[winsbox lock_db] WARNING: crash recovery DACL \
                             restore on {path}: {e:#}"
                        );
                    }
                }
            } else {
                // Path had an acl_stamp row but no acl_snapshots row.
                // Shouldn't happen in normal operation, but if it does
                // we have nothing to restore from — just log.
                eprintln!(
                    "[winsbox lock_db] WARNING: orphaned acl_stamp on {path} \
                     but no acl_snapshots row; nothing to restore"
                );
            }
            self.delete_acl_snapshot(&path)?;
        }
        Ok(dead.len() as u32)
    }
}

/// `%LOCALAPPDATA%\winsbox\state.db`. Creates the parent dir if missing.
pub fn default_db_path() -> Result<PathBuf> {
    let local_appdata = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| anyhow!("LOCALAPPDATA env var not set"))?;
    let mut p = PathBuf::from(local_appdata);
    p.push("winsbox");
    std::fs::create_dir_all(&p)
        .with_context(|| format!("create_dir_all {}", p.display()))?;
    p.push("state.db");
    Ok(p)
}

fn unix_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Return the current (broker) process's creation FILETIME as i64
/// (100-ns ticks since 1601-01-01 UTC).
#[cfg(windows)]
pub fn current_process_create_time() -> Result<i64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let h = unsafe { GetCurrentProcess() };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes(current)")?;
    }
    Ok(filetime_to_i64(creation))
}

#[cfg(not(windows))]
pub fn current_process_create_time() -> Result<i64> {
    // Tests under `cargo test --lib` on non-Windows hosts: stub.
    Ok(unix_epoch_seconds())
}

#[cfg(windows)]
fn filetime_to_i64(ft: windows::Win32::Foundation::FILETIME) -> i64 {
    (((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)) as i64
}

/// Return true iff the recorded session is no longer live: either
/// `OpenProcess(SYNCHRONIZE)` fails, or it succeeds but the recorded
/// `process_create_time` differs from `GetProcessTimes(dwCreationTime)`
/// (PID was recycled).
#[cfg(windows)]
fn is_session_dead(pid: u32, recorded_create_time: i64) -> bool {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SYNCHRONIZE alone isn't enough to call GetProcessTimes; we need
    // QUERY_LIMITED_INFORMATION. The original phase 5A spec said
    // OpenProcess(SYNCHRONIZE), but if open succeeds you still need
    // query rights for the create-time recheck. Use the narrower
    // QUERY_LIMITED_INFORMATION right (granted to same-user same-IL
    // processes by default) so both probes happen in one handle.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let h = match h {
        Ok(h) if !h.is_invalid() => h,
        _ => return true, // OpenProcess failed => process gone (or denied)
    };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user)
    };
    unsafe {
        let _ = CloseHandle(h);
    }
    if ok.is_err() {
        return true;
    }
    let actual = filetime_to_i64(creation);
    // Mismatch => PID was recycled. Treat as dead.
    actual != recorded_create_time
}

#[cfg(not(windows))]
fn is_session_dead(_pid: u32, _recorded_create_time: i64) -> bool {
    // Tests under `cargo test --lib` on non-Windows hosts: conservatively
    // treat everything as alive so unit tests can populate rows without
    // them disappearing.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tmp_db() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "winsbox-lockdb-test-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(p.with_extension("db-wal"));
        let _ = std::fs::remove_file(p.with_extension("db-shm"));
    }

    #[test]
    fn open_creates_schema_and_round_trips() {
        let p = unique_tmp_db();
        let db = LockDb::open_at(&p).expect("open");

        // All three tables should exist.
        for tbl in &["proc_sessions", "path_locks", "acl_snapshots"] {
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master \
                     WHERE type='table' AND name=?1",
                    params![tbl],
                    |r| r.get(0),
                )
                .expect("master query");
            assert_eq!(n, 1, "table {tbl} should exist");
        }

        db.begin_session(12345, r"\\.\pipe\winsbox-broker-12345")
            .expect("begin");
        let count: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM proc_sessions WHERE broker_pid=12345",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(count, 1);
        db.end_session(12345).expect("end");
        let after: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM proc_sessions WHERE broker_pid=12345",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(after, 0);

        cleanup(&p);
    }

    #[test]
    fn crash_recovery_scan_is_empty_with_no_rows() {
        let p = unique_tmp_db();
        let db = LockDb::open_at(&p).expect("open");
        let pruned = db.crash_recovery_scan().expect("scan");
        assert_eq!(pruned, 0);
        cleanup(&p);
    }
}
