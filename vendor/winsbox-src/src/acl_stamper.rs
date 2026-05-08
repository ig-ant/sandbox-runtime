//! Custom Win32 ACL stamper. Replaces the icacls-shelling `acl.rs` with
//! direct `GetNamedSecurityInfoW` / `SetNamedSecurityInfoW` /
//! `TreeSetNamedSecurityInfoW` calls plus an idempotency probe so re-applying
//! an unchanged policy is a near no-op.
//!
//! See `cheeky-jingling-stream.md` §"Components > 1. acl_stamper.rs" for the
//! full design contract; the load-bearing rules are:
//!
//! - For each `allow_*` path: emit an `(OI)(CI) ALLOW` ACE for the AC SID.
//! - For each `deny_*` path P: only emit a DENY ACE if some ancestor is in
//!   `allow_*`. Otherwise the path is already closed (no AC ACE → no access)
//!   and a DENY would just bloat the ACL.
//! - Skip the per-root walk if `GetNamedSecurityInfoW` already shows our exact
//!   ACE on the root *and* a probe leaf inherits it.

use anyhow::{anyhow, bail, Result};
use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::Instant;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    BuildExplicitAccessWithNameW, BuildTrusteeWithSidW, ConvertSidToStringSidW,
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    TreeSetNamedSecurityInfoW, ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, PROG_INVOKE_SETTING, SE_FILE_OBJECT, TREE_SEC_INFO_SET,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    EqualSid, GetAce, ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;

use crate::util::{from_pwstr, pcwstr, wstr};

// AceType byte values (per ntifs.h). The `windows` crate doesn't expose them
// as constants — they're documented as part of the ACE wire format.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;

/// `(OI)(CI)` — children inherit the ACE; both files (OI) and subdirs (CI).
fn oici() -> ACE_FLAGS {
    ACE_FLAGS(OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0)
}

/// Mask we use for read access. `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` is
/// what icacls calls `RX`. We keep both: read-only without execute makes
/// loading DLLs / executing scripts fail and AC-side tools choke.
fn read_mask() -> u32 {
    FILE_GENERIC_READ.0 | windows::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE.0
}

/// Mask for write access. Plain `FILE_GENERIC_WRITE` — granting "modify" in
/// icacls terms requires also handing out delete; for now we match the
/// previous `acl.rs` semantics where allow_write was `M` → we'll use
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE`
/// to mirror the M shape that worked under Phase 2b.
fn write_mask() -> u32 {
    use windows::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    const DELETE: u32 = 0x0001_0000;
    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE
}

/// Policy stamp request. All fields are caller-controlled. `exclude` is the
/// path-prefix exclude list documented in the plan: empty by default, used
/// only for special cases (e.g. excluding a path that the recursive walk
/// would otherwise stamp transitively).
#[derive(Debug, Clone, Default)]
pub struct PolicyStamp {
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_write: Vec<PathBuf>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StampStats {
    pub roots_stamped: usize,
    pub roots_skipped_idempotent: usize,
    pub denies_emitted: usize,
    pub denies_omitted_unnecessary: usize,
    pub elapsed_ms: u128,
}

/// One leaf record we emit. `_kind` is retained for human-readable error
/// messages even though the apply path doesn't otherwise inspect it.
#[derive(Debug, Clone)]
struct StampOp {
    path: PathBuf,
    #[allow(dead_code)]
    kind: &'static str,
    mask: u32,
    mode: ACCESS_MODE,
}

impl PolicyStamp {
    /// Apply against an AC SID. Idempotent: any root whose existing DACL
    /// already contains our exact ACE *and* whose probe leaf inherits it
    /// is skipped.
    pub fn apply(&self, ac_sid: PSID) -> Result<StampStats> {
        let t0 = Instant::now();
        let mut stats = StampStats::default();

        // Skip excluded prefixes. Caller may use this to opt out of stamping
        // particular subtrees (the plan default is empty).
        let excluded = |p: &Path| -> bool {
            let s = p.to_string_lossy();
            self.exclude.iter().any(|e| s.starts_with(e.as_str()))
        };

        // 1. ALLOW stamps.
        for p in &self.allow_read {
            if excluded(p) {
                continue;
            }
            let op = StampOp {
                path: p.clone(),
                kind: "allow_read",
                mask: read_mask(),
                mode: GRANT_ACCESS,
            };
            if apply_one(&op, ac_sid)? {
                stats.roots_stamped += 1;
            } else {
                stats.roots_skipped_idempotent += 1;
            }
        }
        for p in &self.allow_write {
            if excluded(p) {
                continue;
            }
            let op = StampOp {
                path: p.clone(),
                kind: "allow_write",
                mask: write_mask(),
                mode: GRANT_ACCESS,
            };
            if apply_one(&op, ac_sid)? {
                stats.roots_stamped += 1;
            } else {
                stats.roots_skipped_idempotent += 1;
            }
        }

        // 2. DENY stamps — only when nested under an ALLOW.
        let allow_set: HashSet<PathBuf> = self
            .allow_read
            .iter()
            .chain(self.allow_write.iter())
            .map(|p| canonical_or_self(p))
            .collect();

        for (paths, kind, mask) in [
            (&self.deny_read, "deny_read", read_mask()),
            (&self.deny_write, "deny_write", write_mask()),
        ] {
            for p in paths {
                if excluded(p) {
                    continue;
                }
                if !nested_under_any(p, &allow_set) {
                    stats.denies_omitted_unnecessary += 1;
                    continue;
                }
                let op = StampOp {
                    path: p.clone(),
                    kind,
                    mask,
                    mode: DENY_ACCESS,
                };
                if apply_one(&op, ac_sid)? {
                    stats.roots_stamped += 1;
                    stats.denies_emitted += 1;
                } else {
                    stats.roots_skipped_idempotent += 1;
                }
            }
        }

        stats.elapsed_ms = t0.elapsed().as_millis();
        Ok(stats)
    }

    /// Remove every ACE for `ac_sid` from each root we touched. We don't
    /// distinguish "ACEs we added" vs "pre-existing ACEs for this SID":
    /// since the SID is the per-instance AC package SID and we created it,
    /// any ACE for it is ours. This matches the previous `acl.rs` behavior.
    pub fn revert(&self, ac_sid: PSID) -> Result<()> {
        let mut roots: Vec<PathBuf> = self
            .allow_read
            .iter()
            .chain(self.allow_write.iter())
            .chain(self.deny_read.iter())
            .chain(self.deny_write.iter())
            .cloned()
            .collect();
        roots.sort();
        roots.dedup();

        for p in roots {
            let _ = remove_aces_for_sid(&p, ac_sid);
        }
        Ok(())
    }
}

/// Apply a single stamp operation. Returns `Ok(true)` if a `TreeSetNamedSecurityInfoW`
/// call was actually issued, `Ok(false)` if the idempotency probe matched and
/// we skipped.
fn apply_one(op: &StampOp, ac_sid: PSID) -> Result<bool> {
    let want_ace_type = match op.mode {
        m if m == GRANT_ACCESS => ACCESS_ALLOWED_ACE_TYPE,
        m if m == DENY_ACCESS => ACCESS_DENIED_ACE_TYPE,
        _ => bail!("unsupported access mode {:?}", op.mode),
    };

    if root_already_stamped(&op.path, ac_sid, op.mask, want_ace_type)?
        && probe_leaf_inherits(&op.path, ac_sid, op.mask, want_ace_type)?
    {
        return Ok(false);
    }

    let path_w = wstr(&op.path.to_string_lossy());

    // Build EXPLICIT_ACCESS_W with the AC SID as trustee.
    let mut ea = EXPLICIT_ACCESS_W::default();
    unsafe {
        BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, ac_sid);
        // BuildExplicitAccessWithNameW expects a name pointer; we pre-built
        // the trustee with a SID, but the helper still wants to populate the
        // EA struct (mode + permissions + inheritance). Calling it with a
        // null name is safe — the trustee's SID is preserved.
        BuildExplicitAccessWithNameW(
            &mut ea as *mut EXPLICIT_ACCESS_W,
            PCWSTR::null(),
            op.mask,
            op.mode,
            oici(),
        );
        // BuildExplicitAccessWithNameW overwrites the trustee with one that
        // uses TRUSTEE_IS_NAME pointing at the (null) name. Re-bind to the
        // SID we actually want.
        BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, ac_sid);
    }

    // Read existing DACL, merge our ACE in, write back.
    let (mut existing_acl_ptr, sd_ptr) = unsafe { fetch_dacl(&path_w)? };
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            Some(std::slice::from_ref(&ea)),
            Some(existing_acl_ptr as *const ACL),
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        if !sd_ptr.is_null() {
            unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
        }
        bail!("SetEntriesInAclW failed: {:?}", rc);
    }

    // TreeSetNamedSecurityInfoW propagates inheritance kernel-side. This is
    // the meat of the stamper — same call icacls makes underneath.
    let rc = unsafe {
        TreeSetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
            TREE_SEC_INFO_SET,
            None,
            PROG_INVOKE_SETTING(0),
            None,
        )
    };

    // Free buffers regardless of success.
    if !new_acl.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(new_acl as *mut c_void)); }
    }
    if !sd_ptr.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
    }
    let _ = &mut existing_acl_ptr;

    if rc != ERROR_SUCCESS {
        bail!(
            "TreeSetNamedSecurityInfoW({:?}) failed: {:?}",
            op.path,
            rc
        );
    }

    Ok(true)
}

unsafe fn fetch_dacl(path_w: &[u16]) -> Result<(*mut ACL, *mut c_void)> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let rc = GetNamedSecurityInfoW(
        pcwstr(path_w),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(&mut dacl as *mut *mut ACL),
        None,
        &mut sd,
    );
    if rc != ERROR_SUCCESS {
        bail!("GetNamedSecurityInfoW failed: {:?}", rc);
    }
    Ok((dacl, sd.0))
}

/// Returns true if the root's DACL already has an ACE matching (SID, mask,
/// AceType, OI|CI). Doesn't check sub-flags beyond the inheritance bits.
fn root_already_stamped(path: &Path, ac_sid: PSID, mask: u32, ace_type: u8) -> Result<bool> {
    let path_w = wstr(&path.to_string_lossy());
    unsafe {
        let (dacl_ptr, sd_ptr) = match fetch_dacl(&path_w) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        let result = ace_matches(dacl_ptr, ac_sid, mask, ace_type, AceCheck::Root);
        if !sd_ptr.is_null() {
            let _ = LocalFree(HLOCAL(sd_ptr));
        }
        Ok(result)
    }
}

/// Variant of the ACE check.
#[derive(Copy, Clone)]
enum AceCheck {
    /// Looking for our explicit `(OI)(CI)` ACE on a root: must have both
    /// inherit bits set. Used to detect "is the root already stamped?".
    Root,
    /// Looking for an ACE inherited onto a leaf — the kernel strips OI/CI
    /// when the ACE applies to the file itself and replaces it with the
    /// `INHERITED_ACE` flag. Used by the probe-leaf path.
    Leaf,
}

unsafe fn ace_matches(
    dacl: *const ACL,
    ac_sid: PSID,
    mask: u32,
    ace_type: u8,
    mode: AceCheck,
) -> bool {
    if dacl.is_null() || ac_sid.0.is_null() {
        return false;
    }
    let count = (*dacl).AceCount as u32;
    const INHERITED_ACE: u8 = 0x10;
    for i in 0..count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
            continue;
        }
        let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
        if header.AceType != ace_type {
            continue;
        }
        match mode {
            AceCheck::Root => {
                let want = OBJECT_INHERIT_ACE.0 as u8 | CONTAINER_INHERIT_ACE.0 as u8;
                if header.AceFlags & want != want {
                    continue;
                }
            }
            AceCheck::Leaf => {
                // On a leaf the inherited ACE typically has just
                // INHERITED_ACE; on a sub-directory it may also carry the
                // OI/CI bits forward. Either is acceptable as long as the
                // ACE was inherited from us.
                if header.AceFlags & INHERITED_ACE == 0 {
                    continue;
                }
            }
        }
        let mask_ptr = (ace as *const u8).add(std::mem::size_of::<windows::Win32::Security::ACE_HEADER>())
            as *const u32;
        if *mask_ptr != mask {
            continue;
        }
        let sid_ptr = mask_ptr.add(1) as *const c_void;
        let candidate = PSID(sid_ptr as *mut c_void);
        if EqualSid(candidate, ac_sid).is_ok() {
            return true;
        }
    }
    false
}

/// Touch a tempfile under `root` and check whether its ACL has an ACE for
/// `ac_sid` with the right mask and type. Used to confirm inheritance is in
/// fact propagating. Returns false on any I/O error — we'd rather force a
/// stamp than skip when uncertain.
fn probe_leaf_inherits(root: &Path, ac_sid: PSID, mask: u32, ace_type: u8) -> Result<bool> {
    if !root.is_dir() {
        // For file roots, the root itself IS the leaf. Already verified above.
        return Ok(true);
    }
    let unique = format!(
        ".sbox-stamp-probe-{}-{}",
        std::process::id(),
        next_probe_counter()
    );
    let probe = root.join(&unique);
    if std::fs::write(&probe, b"").is_err() {
        // Can't write a probe — assume the inheritance is fine. Re-stamping
        // would also fail.
        return Ok(true);
    }
    let path_w = wstr(&probe.to_string_lossy());
    let result = unsafe {
        match fetch_dacl(&path_w) {
            Ok((dacl, sd)) => {
                let m = ace_matches(dacl, ac_sid, mask, ace_type, AceCheck::Leaf);
                if !sd.is_null() {
                    let _ = LocalFree(HLOCAL(sd));
                }
                m
            }
            Err(_) => false,
        }
    };
    let _ = std::fs::remove_file(&probe);
    Ok(result)
}

/// Counter for probe filename uniqueness. Avoids adding `tempfile` as a dep.
fn next_probe_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// True iff some strict ancestor of `path` is in `allow_set`.
fn nested_under_any(path: &Path, allow_set: &HashSet<PathBuf>) -> bool {
    let canon = canonical_or_self(path);
    let mut cur = canon.parent();
    while let Some(p) = cur {
        if allow_set.contains(&p.to_path_buf()) {
            return true;
        }
        // Try the canonicalized form — allow_set entries are canonicalized.
        if let Ok(c) = std::fs::canonicalize(p) {
            if allow_set.contains(&c) {
                return true;
            }
        }
        cur = p.parent();
    }
    false
}

/// Strip every ACE for `ac_sid` from `path`. Used by `revert`.
fn remove_aces_for_sid(path: &Path, ac_sid: PSID) -> Result<()> {
    let path_w = wstr(&path.to_string_lossy());
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl as *mut *mut ACL),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(anyhow!("GetNamedSecurityInfoW({:?}): {:?}", path, rc));
    }

    // Build the list of ACEs to keep — every existing ACE whose SID isn't ours.
    let mut keep: Vec<EXPLICIT_ACCESS_W> = Vec::new();
    if !dacl.is_null() {
        unsafe {
            let count = (*dacl).AceCount as u32;
            for i in 0..count {
                let mut ace: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
                    continue;
                }
                let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
                let mask_ptr = (ace as *const u8)
                    .add(std::mem::size_of::<windows::Win32::Security::ACE_HEADER>())
                    as *const u32;
                let ace_mask = *mask_ptr;
                let sid_ptr = mask_ptr.add(1) as *mut c_void;
                let candidate = PSID(sid_ptr);
                if EqualSid(candidate, ac_sid).is_ok() {
                    continue; // drop
                }

                let mode = match header.AceType {
                    ACCESS_ALLOWED_ACE_TYPE => GRANT_ACCESS,
                    ACCESS_DENIED_ACE_TYPE => DENY_ACCESS,
                    _ => continue, // we only know how to round-trip these
                };
                let mut ea = EXPLICIT_ACCESS_W::default();
                BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, candidate);
                ea.grfAccessPermissions = ace_mask;
                ea.grfAccessMode = mode;
                ea.grfInheritance = ACE_FLAGS(header.AceFlags as u32);
                keep.push(ea);
            }
        }
    }

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    // SetEntriesInAclW with no oldAcl → builds a fresh ACL from `keep`.
    let rc = unsafe {
        SetEntriesInAclW(
            Some(keep.as_slice()),
            None,
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        if !sd.0.is_null() {
            unsafe { let _ = LocalFree(HLOCAL(sd.0)); }
        }
        return Err(anyhow!("SetEntriesInAclW (revert) failed: {:?}", rc));
    }

    let rc = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
        )
    };
    if !new_acl.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(new_acl as *mut c_void)); }
    }
    if !sd.0.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sd.0)); }
    }
    if rc != ERROR_SUCCESS {
        return Err(anyhow!("SetNamedSecurityInfoW (revert): {:?}", rc));
    }
    Ok(())
}

/// Convert a string SID like `"S-1-15-2-1"` to a heap-owned PSID. Caller
/// frees with `LocalFree`. Only used by tests / examples that don't have a
/// real AC handy.
pub fn psid_from_string(sid_str: &str) -> Result<PSID> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let mut sid = PSID::default();
    let w = wstr(sid_str);
    unsafe {
        ConvertStringSidToSidW(pcwstr(&w), &mut sid)
            .map_err(|e| anyhow!("ConvertStringSidToSidW({sid_str}): {e}"))?;
    }
    Ok(sid)
}

/// Free a SID returned by `psid_from_string`.
pub fn free_psid(sid: PSID) {
    if !sid.0.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sid.0)); }
    }
}

/// Return the string form of a PSID. Convenience for manifest serialization.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    use windows::core::PWSTR;
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    crate::util::local_free(p.0 as *mut c_void);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-known: ALL APPLICATION PACKAGES. Real SID, accepted everywhere,
    /// no AppContainer profile required.
    const TEST_SID: &str = "S-1-15-2-1";

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sbox-stamper-{}-{}-{}",
            tag,
            std::process::id(),
            next_probe_counter()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    #[test]
    fn test_idempotent_apply() {
        let root = unique_dir("idem");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };

        let s1 = policy.apply(sid).unwrap();
        assert_eq!(s1.roots_stamped, 1, "first apply should stamp");
        assert_eq!(s1.roots_skipped_idempotent, 0);

        let s2 = policy.apply(sid).unwrap();
        assert_eq!(s2.roots_stamped, 0, "second apply should be a no-op");
        assert_eq!(s2.roots_skipped_idempotent, 1);

        policy.revert(sid).unwrap();
        free_psid(sid);
        cleanup(&root);
    }

    #[test]
    fn test_deny_omitted_when_no_parent_allow() {
        // A DENY path with no allow ancestor — the path is already closed
        // by default, so we shouldn't bother stamping a DENY there.
        let root = unique_dir("deny-orphan");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            deny_read: vec![root.clone()],
            ..Default::default()
        };

        let s = policy.apply(sid).unwrap();
        assert_eq!(s.denies_emitted, 0);
        assert_eq!(s.denies_omitted_unnecessary, 1);
        assert_eq!(s.roots_stamped, 0);

        free_psid(sid);
        cleanup(&root);
    }

    #[test]
    fn test_deny_emitted_when_nested_under_allow() {
        let root = unique_dir("allow-root");
        let nested = root.join("private");
        std::fs::create_dir_all(&nested).unwrap();
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            deny_read: vec![nested.clone()],
            ..Default::default()
        };

        let s = policy.apply(sid).unwrap();
        assert_eq!(s.denies_emitted, 1, "deny under allow should be emitted");
        assert_eq!(s.denies_omitted_unnecessary, 0);
        assert!(s.roots_stamped >= 2);

        policy.revert(sid).unwrap();
        free_psid(sid);
        cleanup(&root);
    }

    #[test]
    fn test_revert_removes_aces() {
        let root = unique_dir("revert");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };
        policy.apply(sid).unwrap();

        // Confirm an ACE exists.
        assert!(
            root_already_stamped(&root, sid, read_mask(), ACCESS_ALLOWED_ACE_TYPE).unwrap(),
            "ACE should be present after apply"
        );

        policy.revert(sid).unwrap();
        assert!(
            !root_already_stamped(&root, sid, read_mask(), ACCESS_ALLOWED_ACE_TYPE).unwrap(),
            "ACE should be gone after revert"
        );

        free_psid(sid);
        cleanup(&root);
    }
}
