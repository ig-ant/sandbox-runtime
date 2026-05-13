//! Phase 5B — per-broker share-mode-0 lock acquisition for
//! `Policy.fs_deny_read` paths.
//!
//! For each path:
//!   1. `CreateFileW(GENERIC_READ, FILE_SHARE_DELETE, OPEN_EXISTING)`.
//!      `FILE_SHARE_DELETE` (no `FILE_SHARE_READ`, no `FILE_SHARE_WRITE`)
//!      means any later open from the sandbox child that requests
//!      `GENERIC_READ` will fail with `ERROR_SHARING_VIOLATION (32)`,
//!      but the user can still `rm` the file from outside the sandbox.
//!   2. Canonicalize via `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED)`.
//!   3. INSERT a row into `path_locks(kind='share_mode')` so other
//!      brokers (5D) can find us.
//!
//! On `ERROR_FILE_NOT_FOUND (2)`: skip with a warning (a configured
//! secret path may not exist in this workspace; not a config error).
//!
//! On `ERROR_SHARING_VIOLATION (32)`: return a structured
//! `LockError::SharingViolation` so phase 5C can intercept and fall
//! back to the ACL-stamp path. Best-effort Restart-Manager lookup of
//! the conflicting holder is wired here but currently deferred — see
//! comment on `LockError`.
//!
//! On Drop: close every handle, then transactionally remove all our
//! `path_locks(kind='share_mode')` rows via
//! `LockDb::delete_my_share_mode_locks`.

use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_NORMAL,
    FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, OPEN_EXISTING,
};

use crate::lock_db::LockDb;
use crate::util::wstr;

/// Structured failure for a per-path acquire attempt.
///
/// `SharingViolation` is the case Phase 5C needs to intercept (fall
/// back to an ACL stamp). Restart-Manager lookup of the conflicting
/// holder is deferred — see comment at the bottom of this file. For
/// now we surface the path so the error message names the file.
#[derive(Debug)]
#[allow(dead_code)]
pub enum LockError {
    /// `CreateFileW` returned `ERROR_SHARING_VIOLATION` — another
    /// handle is already open with an incompatible share mode. Phase
    /// 5C will fall back to the ACL-stamp path here.
    SharingViolation { path: PathBuf },

    /// Anything else (`ERROR_ACCESS_DENIED`, `ERROR_INVALID_NAME`, …).
    /// Bubbles up as a fatal acquire error in 5B.
    CreateFile {
        path: PathBuf,
        err: anyhow::Error,
    },

    /// Canonicalization failure (kept distinct so logs are clear).
    Canonicalize {
        path: PathBuf,
        err: anyhow::Error,
    },

    /// SQLite INSERT failure. Caller's burden to roll back the open
    /// handle, but for 5B we just fail the whole acquire and Drop will
    /// close everything we already opened.
    Db {
        path: PathBuf,
        err: anyhow::Error,
    },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::SharingViolation { path } => write!(
                f,
                "share-mode acquire failed for {}: sharing violation \
                 (err=32, hr=0x80070020); other process holds the file open \
                 with incompatible share mode",
                path.display()
            ),
            LockError::CreateFile { path, err } => write!(
                f,
                "share-mode acquire failed for {}: {err}",
                path.display()
            ),
            LockError::Canonicalize { path, err } => write!(
                f,
                "GetFinalPathNameByHandleW failed for {}: {err}",
                path.display()
            ),
            LockError::Db { path, err } => write!(
                f,
                "INSERT path_locks failed for {}: {err}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LockError::SharingViolation { .. } => None,
            LockError::CreateFile { err, .. }
            | LockError::Canonicalize { err, .. }
            | LockError::Db { err, .. } => Some(err.as_ref()),
        }
    }
}

/// One acquired handle + its canonical path. Held in `ShareModeLocks`
/// until Drop. `canonical` is unused in 5B (we already INSERTed the
/// row keyed by it); 5D will read it for cross-broker DuplicateHandle
/// routing.
struct HeldHandle {
    handle: HANDLE,
    #[allow(dead_code)]
    canonical: String,
}

/// RAII holder for the broker's share-mode-0 locks.
///
/// `_share_locks` in `launch::run` keeps this struct alive past
/// `WaitForSingleObject(child)`. Dropping it closes every handle and
/// removes the rows we INSERTed.
pub struct ShareModeLocks<'a> {
    db: Option<&'a LockDb>,
    broker_pid: u32,
    held: Vec<HeldHandle>,
}

impl<'a> ShareModeLocks<'a> {
    /// Acquire share-mode locks on every path in `paths`.
    ///
    /// `db` is optional because the broker can run in "phase 5
    /// degraded" mode (DB open failed at startup). In that mode we
    /// still open handles — the kernel share-mode check fires
    /// regardless of bookkeeping — but skip the DB INSERTs. Phase 5D
    /// cross-broker DUP_HANDLE will silently lose visibility.
    pub fn acquire(
        db: Option<&'a LockDb>,
        paths: &[PathBuf],
        broker_pid: u32,
    ) -> Result<Self, LockError> {
        let mut held: Vec<HeldHandle> = Vec::new();

        // Two-stage: open all handles first, then INSERT. If anything
        // fails mid-way, Drop on the partial `ShareModeLocks` closes
        // the handles we already opened — but we need the struct to
        // exist for that. Build incrementally.
        let mut locks = ShareModeLocks {
            db,
            broker_pid,
            held: Vec::new(),
        };

        for p in paths {
            match try_acquire_one(p) {
                Ok(Some((handle, canonical))) => {
                    if let Some(db) = locks.db {
                        if let Err(e) = db.insert_share_mode_lock(broker_pid, &canonical) {
                            // Close the handle we just opened before
                            // bailing; Drop will sweep up the rest.
                            unsafe { let _ = CloseHandle(handle); }
                            return Err(LockError::Db {
                                path: p.clone(),
                                err: e,
                            });
                        }
                    }
                    held.push(HeldHandle { handle, canonical });
                }
                Ok(None) => {
                    // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND — skip.
                    eprintln!(
                        "winsbox: path {} not present, skipping share-mode lock",
                        p.display()
                    );
                }
                Err(e) => {
                    // Move whatever we've accumulated into locks so
                    // Drop runs and closes them.
                    locks.held = held;
                    return Err(e);
                }
            }
        }

        locks.held = held;
        Ok(locks)
    }
}

impl<'a> Drop for ShareModeLocks<'a> {
    fn drop(&mut self) {
        // Close every handle first (regardless of DB success); the
        // kernel decrements the share-mode refcount as we close.
        for h in self.held.drain(..) {
            unsafe {
                let _ = CloseHandle(h.handle);
            }
        }
        // Then sweep our DB rows. If this fails (DB locked, disk
        // full), log; we're in Drop, no propagating. Crash recovery
        // on the next broker startup picks up the slack.
        if let Some(db) = self.db {
            if let Err(e) = db.delete_my_share_mode_locks(self.broker_pid) {
                eprintln!(
                    "[winsbox share-mode] WARNING: delete_my_share_mode_locks \
                     failed during Drop: {e:#}"
                );
            }
        }
    }
}

/// Attempt one path. Returns:
///   - `Ok(Some((handle, canonical)))` — opened + canonicalized.
///   - `Ok(None)`                       — path not present, skip.
///   - `Err(LockError)`                 — anything else.
fn try_acquire_one(path: &Path) -> Result<Option<(HANDLE, String)>, LockError> {
    let w = wstr(&path.display().to_string());
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };
    let handle = match h {
        Ok(h) => h,
        Err(e) => {
            let le = unsafe { GetLastError() };
            // ERROR_FILE_NOT_FOUND (2) and ERROR_PATH_NOT_FOUND (3)
            // are both "the path simply doesn't exist here" — skip.
            if le == ERROR_FILE_NOT_FOUND || le == ERROR_PATH_NOT_FOUND {
                return Ok(None);
            }
            if le == ERROR_SHARING_VIOLATION {
                // Phase 5C will catch this and fall back to ACL stamp.
                return Err(LockError::SharingViolation {
                    path: path.to_path_buf(),
                });
            }
            return Err(LockError::CreateFile {
                path: path.to_path_buf(),
                err: anyhow::Error::new(e)
                    .context(format!("CreateFileW({})", path.display())),
            });
        }
    };

    // Canonicalize. GetFinalPathNameByHandleW returns the path with a
    // `\\?\` prefix; strip it for a friendlier DB row.
    let mut buf = [0u16; 512];
    let n = unsafe {
        GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED)
    };
    if n == 0 || (n as usize) >= buf.len() {
        // Failure (n==0) or buffer too small (n >= len → required size).
        unsafe { let _ = CloseHandle(handle); }
        return Err(LockError::Canonicalize {
            path: path.to_path_buf(),
            err: anyhow::anyhow!(
                "GetFinalPathNameByHandleW returned {n}; buffer 512 chars"
            )
            .context("canonicalize share-mode handle"),
        });
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    // Strip the `\\?\` prefix for stable DB rows (matches what callers
    // typed). `\\?\UNC\server\share\...` becomes `\\server\share\...`.
    let canonical = strip_nt_prefix(&s);

    Ok(Some((handle, canonical)))
}

/// Strip the Win32 `\\?\` prefix returned by
/// `GetFinalPathNameByHandleW`. `\\?\UNC\srv\share` → `\\srv\share`.
fn strip_nt_prefix(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        let mut out = String::with_capacity(rest.len() + 2);
        out.push_str(r"\\");
        out.push_str(rest);
        out
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.to_string()
    }
    // Note: we deliberately do NOT lowercase or further normalize —
    // GetFinalPathNameByHandleW already resolved symlinks, junctions,
    // and 8.3 short names, which is what the DB key needs.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_nt_prefix_basic() {
        assert_eq!(strip_nt_prefix(r"\\?\C:\foo\bar"), r"C:\foo\bar");
        assert_eq!(strip_nt_prefix(r"\\?\UNC\srv\share\x"), r"\\srv\share\x");
        assert_eq!(strip_nt_prefix(r"C:\already\stripped"), r"C:\already\stripped");
    }
}
