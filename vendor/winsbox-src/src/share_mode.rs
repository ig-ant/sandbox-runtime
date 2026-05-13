//! Phase 5B/5C — per-broker FS isolation acquisition for
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
//! On `ERROR_SHARING_VIOLATION (32)` (Phase 5C):
//!   1. Restart-Manager-best-effort: log the conflicting holders so the
//!      user can correlate `J2: fell back to ACL` with which app held it.
//!   2. Canonicalize the path (via a permissive `CreateFileW` with
//!      full sharing — we only need the final-path-name back, not a
//!      lock).
//!   3. ACL-stamp the file: capture original SD bytes, write the
//!      "winsbox-allowed + SYSTEM + Admins + OWNER_RIGHTS=0" DACL,
//!      record both in `acl_snapshots` for crash recovery.
//!   4. Track as kind='acl_stamp' so Drop reverts.
//!
//! On Drop: process every held entry in reverse order. For
//! share-mode entries close the handle then sweep DB rows; for
//! acl-stamp entries delete our holder row, check current DACL still
//! equals what we stamped, restore originals if we were the last
//! holder, then delete the snapshot row.

use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_NORMAL,
    FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

use crate::acl;
use crate::lock_db::LockDb;
use crate::util::wstr;

/// Structured failure for a per-path acquire attempt.
///
/// `SharingViolation` is kept for compatibility / log diagnostics —
/// Phase 5C intercepts it internally and falls back to the ACL-stamp
/// path before returning it to callers. Remaining call sites raise
/// `AclStamp` if the ACL fallback itself fails for a non-recoverable
/// reason (e.g. `SetSecurityInfo` returns ACCESS_DENIED because the
/// broker isn't even running as the file owner).
#[derive(Debug)]
#[allow(dead_code)]
pub enum LockError {
    /// `CreateFileW` returned `ERROR_SHARING_VIOLATION` — another
    /// handle is already open with an incompatible share mode. Phase
    /// 5C intercepts this and falls back to the ACL-stamp path; we
    /// only surface it externally for diagnostic / test paths that
    /// keep this signal around (and as the underlying error inside
    /// `AclStamp` if the fallback itself fails).
    SharingViolation { path: PathBuf },

    /// Anything else (`ERROR_ACCESS_DENIED`, `ERROR_INVALID_NAME`, …).
    /// Bubbles up as a fatal acquire error.
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

    /// Phase 5C: ACL fallback acquire itself failed (capture / stamp /
    /// DB INSERT). The `err` carries the structured cause.
    AclStamp {
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
            LockError::AclStamp { path, err } => write!(
                f,
                "ACL-stamp fallback failed for {}: {err}",
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
            | LockError::Db { err, .. }
            | LockError::AclStamp { err, .. } => Some(err.as_ref()),
        }
    }
}

/// One per-path entry the broker is holding. Phase 5B paths carry a
/// kernel HANDLE; Phase 5C paths carry no HANDLE but instead persist
/// the DACL stamp until Drop runs.
enum HeldEntry {
    ShareMode {
        handle: HANDLE,
        #[allow(dead_code)]
        canonical: String,
    },
    AclStamp {
        canonical: String,
    },
}

/// RAII holder for the broker's FS isolation locks (both kinds).
///
/// `_share_locks` in `launch::run` keeps this struct alive past
/// `WaitForSingleObject(child)`. Dropping it closes every share-mode
/// handle, reverts every ACL stamp (if we're the last holder), and
/// removes our DB bookkeeping rows.
pub struct ShareModeLocks<'a> {
    db: Option<&'a LockDb>,
    broker_pid: u32,
    held: Vec<HeldEntry>,
}

impl<'a> ShareModeLocks<'a> {
    /// Acquire FS isolation locks on every path in `paths`.
    ///
    /// `db` is optional because the broker can run in "phase 5
    /// degraded" mode (DB open failed at startup). In that mode we
    /// still attempt the share-mode-0 open — the kernel share-mode
    /// check fires regardless of bookkeeping — but skip DB inserts
    /// AND skip the ACL fallback (the fallback needs the DB to
    /// coordinate single-stamper-multiple-holders).
    ///
    /// `allowed_sid` is the `winsbox-allowed` group SID in string form,
    /// required by the ACL fallback path. Pass an empty string in
    /// share-mode-only callers (Phase 5C ACL fallback will surface a
    /// configuration error if it's needed).
    pub fn acquire(
        db: Option<&'a LockDb>,
        paths: &[PathBuf],
        broker_pid: u32,
        allowed_sid: &str,
    ) -> Result<Self, LockError> {
        // Two-stage: process paths one at a time, accumulating into a
        // partial holder. If anything fails mid-way, the partial
        // holder's Drop will close opened handles and remove inserted
        // rows.
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
                            unsafe { let _ = CloseHandle(handle); }
                            return Err(LockError::Db {
                                path: p.clone(),
                                err: e,
                            });
                        }
                    }
                    locks.held.push(HeldEntry::ShareMode { handle, canonical });
                }
                Ok(None) => {
                    eprintln!(
                        "winsbox: path {} not present, skipping FS lock",
                        p.display()
                    );
                }
                Err(LockError::SharingViolation { path }) => {
                    // Phase 5C: another process has the file open with
                    // incompatible share mode. Best-effort Restart-
                    // Manager-derived diagnostic, then ACL-stamp.
                    let holders = restart_manager_holders(&path);
                    eprintln!(
                        "winsbox: share-mode acquisition failed for {}, \
                         falling back to ACL stamp ({})",
                        path.display(),
                        holders
                    );
                    if locks.db.is_none() {
                        // Without a DB we can't coordinate ACL revert.
                        // Surface a hard error rather than stamp +
                        // leak.
                        return Err(LockError::AclStamp {
                            path: path.clone(),
                            err: anyhow::anyhow!(
                                "share-mode SHARING_VIOLATION but state DB \
                                 unavailable; refusing to ACL-stamp without \
                                 a way to coordinate revert"
                            ),
                        });
                    }
                    if allowed_sid.is_empty() {
                        return Err(LockError::AclStamp {
                            path: path.clone(),
                            err: anyhow::anyhow!(
                                "ACL fallback needs winsbox-allowed SID; \
                                 caller passed empty string"
                            ),
                        });
                    }
                    match acquire_acl_stamp(
                        locks.db.unwrap(),
                        &path,
                        broker_pid,
                        allowed_sid,
                    ) {
                        Ok(canonical) => {
                            locks.held.push(HeldEntry::AclStamp { canonical });
                        }
                        Err(e) => {
                            return Err(LockError::AclStamp {
                                path: path.clone(),
                                err: e,
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(locks)
    }
}

impl<'a> Drop for ShareModeLocks<'a> {
    fn drop(&mut self) {
        // Walk every held entry. ShareMode: close handle. AclStamp:
        // delete our row, possibly restore DACL.
        let mut acl_paths: Vec<String> = Vec::new();
        for entry in self.held.drain(..) {
            match entry {
                HeldEntry::ShareMode { handle, .. } => unsafe {
                    let _ = CloseHandle(handle);
                },
                HeldEntry::AclStamp { canonical } => {
                    acl_paths.push(canonical);
                }
            }
        }
        // Share-mode DB rows in one sweep.
        if let Some(db) = self.db {
            if let Err(e) = db.delete_my_share_mode_locks(self.broker_pid) {
                eprintln!(
                    "[winsbox share-mode] WARNING: delete_my_share_mode_locks \
                     failed during Drop: {e:#}"
                );
            }
            for path in acl_paths {
                if let Err(e) = release_acl_stamp(db, self.broker_pid, &path) {
                    eprintln!(
                        "[winsbox acl-stamp] WARNING: release on {path} \
                         failed during Drop: {e:#}"
                    );
                }
            }
        }
    }
}

/// Phase 5C: stamp `path` with our broker-only DACL and persist the
/// snapshot. Returns the canonical path string (used as the DB key
/// and as the AclStamp::canonical field).
///
/// Workflow:
///   1. Re-open the file with full sharing JUST to canonicalize. We
///      drop the handle immediately.
///   2. Check DB for an existing `acl_snapshots` row. If present,
///      another broker already stamped the file. Skip the
///      SetSecurityInfo write; just record our holder row.
///   3. Otherwise: capture full SD bytes (DACL + Owner + Group), apply
///      the stamp, record snapshot + holder row in one transaction.
fn acquire_acl_stamp(
    db: &LockDb,
    path: &Path,
    broker_pid: u32,
    allowed_sid: &str,
) -> anyhow::Result<String> {
    // 1) Canonicalize via a permissive (READ+WRITE+DELETE share) open.
    //    This won't conflict with the third-party holder that caused
    //    our SHARING_VIOLATION (they hold some share mode that allows
    //    at least READ — otherwise nobody else could even open it).
    let canonical = canonicalize_permissive(path)?;

    // 2) Existing snapshot? If so, skip the write and just record our
    //    holder row.
    let already_snapped = db.acl_snapshot_exists(&canonical)
        .map_err(|e| anyhow::anyhow!("acl_snapshot_exists: {e:#}"))?;
    if already_snapped {
        db.insert_acl_stamp_lock(broker_pid, &canonical, None)
            .map_err(|e| {
                anyhow::anyhow!("insert_acl_stamp_lock (reuse): {e:#}")
            })?;
        return Ok(canonical);
    }

    // 3) First stamper: capture, write, record.
    let original = acl::capture_full_sd(path)
        .map_err(|e| anyhow::anyhow!("capture_full_sd: {e:#}"))?;
    let stamped_canonical = acl::apply_stamp(path, allowed_sid)
        .map_err(|e| anyhow::anyhow!("apply_stamp: {e:#}"))?;
    db.insert_acl_stamp_lock(
        broker_pid,
        &canonical,
        Some((original.as_bytes(), &stamped_canonical)),
    )
    .map_err(|e| anyhow::anyhow!("insert_acl_stamp_lock (new): {e:#}"))?;
    Ok(canonical)
}

/// Phase 5C release for one acl-stamp path.
///   1. DELETE our holder row, count remaining.
///   2. If count == 0 (we're last): GetSecurityInfo current DACL,
///      compare to stamped, restore from original if match, log if not.
///   3. DELETE acl_snapshots row.
fn release_acl_stamp(
    db: &LockDb,
    broker_pid: u32,
    canonical: &str,
) -> anyhow::Result<()> {
    let remaining = db
        .delete_my_acl_stamp_holder(broker_pid, canonical)
        .map_err(|e| anyhow::anyhow!("delete_my_acl_stamp_holder: {e:#}"))?;
    if remaining > 0 {
        // Other broker still holds it; leave DACL + snapshot in place.
        return Ok(());
    }
    let snap = db
        .get_acl_snapshot(canonical)
        .map_err(|e| anyhow::anyhow!("get_acl_snapshot: {e:#}"))?;
    if let Some((orig_bytes, stamped_bytes)) = snap {
        let path = std::path::PathBuf::from(canonical);
        let current = acl::capture_dacl_bytes(&path)
            .map_err(|e| anyhow::anyhow!("capture_dacl_bytes: {e:#}"))?;
        if current == stamped_bytes {
            acl::restore_full_sd(&path, &orig_bytes)
                .map_err(|e| anyhow::anyhow!("restore_full_sd: {e:#}"))?;
        } else {
            eprintln!(
                "[winsbox acl-stamp] WARNING: current DACL on {canonical} \
                 differs from stamped; leaving alone"
            );
        }
    }
    db.delete_acl_snapshot(canonical)
        .map_err(|e| anyhow::anyhow!("delete_acl_snapshot: {e:#}"))?;
    Ok(())
}

/// Best-effort canonicalization. Open with maximum sharing so we
/// don't conflict with whichever process has the file open.
fn canonicalize_permissive(path: &Path) -> anyhow::Result<String> {
    let w = wstr(&path.display().to_string());
    let h = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };
    let handle = match h {
        Ok(h) => h,
        Err(e) => {
            return Err(anyhow::Error::new(e)
                .context(format!("permissive open for canonicalize: {}", path.display())));
        }
    };
    let mut buf = [0u16; 512];
    let n = unsafe {
        GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED)
    };
    unsafe { let _ = CloseHandle(handle); }
    if n == 0 || (n as usize) >= buf.len() {
        return Err(anyhow::anyhow!(
            "GetFinalPathNameByHandleW returned {n}; buffer 512 chars"
        ));
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    Ok(strip_nt_prefix(&s))
}

/// Best-effort: use Restart Manager to identify which processes hold
/// `path` open. Returns a human-readable summary string. Never
/// propagates errors — diagnostic output only.
#[cfg(windows)]
fn restart_manager_holders(path: &Path) -> String {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_MORE_DATA;
    use windows::Win32::System::RestartManager::{
        RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
        RM_PROCESS_INFO,
    };

    let mut session_handle: u32 = 0;
    let mut session_key = [0u16; 64]; // CCH_RM_SESSION_KEY+1=33; round up.
    let r = unsafe {
        RmStartSession(
            &mut session_handle as *mut u32,
            0,
            PWSTR(session_key.as_mut_ptr()),
        )
    };
    if r.is_err() {
        return "RM unavailable".to_string();
    }
    let s = path.display().to_string();
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let resources: [PCWSTR; 1] = [PCWSTR(w.as_ptr())];
    let r = unsafe {
        RmRegisterResources(
            session_handle,
            Some(&resources),
            None,
            None,
        )
    };
    if r.is_err() {
        unsafe { let _ = RmEndSession(session_handle); }
        return "RM register failed".to_string();
    }
    // RmGetList expects pre-sized buffer; do the standard two-call.
    let mut needed: u32 = 0;
    let mut have: u32 = 0;
    let mut reboot_reasons: u32 = 0;
    let mut buf: Vec<RM_PROCESS_INFO> = Vec::new();
    // First call to size.
    let _ = unsafe {
        RmGetList(
            session_handle,
            &mut needed,
            &mut have,
            None,
            &mut reboot_reasons,
        )
    };
    if needed == 0 {
        unsafe { let _ = RmEndSession(session_handle); }
        return "no holders".to_string();
    }
    buf.resize(needed as usize, unsafe { std::mem::zeroed() });
    have = needed;
    let r = unsafe {
        RmGetList(
            session_handle,
            &mut needed,
            &mut have,
            Some(buf.as_mut_ptr()),
            &mut reboot_reasons,
        )
    };
    // windows-rs RmGetList returns WIN32_ERROR. Accept 0 (success) and
    // ERROR_MORE_DATA (we had the right buffer size; success-ish).
    if r.is_err() && r != ERROR_MORE_DATA {
        unsafe { let _ = RmEndSession(session_handle); }
        return "RM get_list failed".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    for i in 0..have as usize {
        let pi = &buf[i];
        // strAppName is fixed-size wchar[CCH_RM_MAX_APP_NAME+1].
        let name = {
            let raw = &pi.strAppName;
            let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            String::from_utf16_lossy(&raw[..len])
        };
        let pid = pi.Process.dwProcessId;
        parts.push(format!("PID {pid} ({name})"));
    }
    unsafe { let _ = RmEndSession(session_handle); }
    if parts.is_empty() {
        "no holders".to_string()
    } else {
        parts.join(", ")
    }
}

#[cfg(not(windows))]
fn restart_manager_holders(_path: &Path) -> String {
    "RM unavailable (non-Windows)".to_string()
}

/// Attempt one path. Returns:
///   - `Ok(Some((handle, canonical)))` — opened + canonicalized.
///   - `Ok(None)`                       — path not present, skip.
///   - `Err(LockError::SharingViolation)` — caller should try ACL fallback.
///   - `Err(LockError::...)`            — other failure.
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
            if le == ERROR_FILE_NOT_FOUND || le == ERROR_PATH_NOT_FOUND {
                return Ok(None);
            }
            if le == ERROR_SHARING_VIOLATION {
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

    let mut buf = [0u16; 512];
    let n = unsafe {
        GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED)
    };
    if n == 0 || (n as usize) >= buf.len() {
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
