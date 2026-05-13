//! Phase 5C — ACL-stamp helpers for the share-mode-0 fallback path.
//!
//! `share_mode.rs` falls back here when `CreateFileW(share=0)` returns
//! `ERROR_SHARING_VIOLATION`. We rewrite the file's DACL to a known
//! "broker-only" shape, capture the original so we can put it back, and
//! persist both in `acl_snapshots`.
//!
//! Replacement DACL (in order):
//!   1. `ALLOW winsbox-allowed FILE_ALL_ACCESS` — broker reaches its
//!      access via the group (enabled in broker token).
//!   2. `ALLOW SYSTEM FILE_ALL_ACCESS` — SYSTEM-owned tools must still
//!      manage the file.
//!   3. `ALLOW BUILTIN\Administrators FILE_ALL_ACCESS` — admin shells.
//!   4. `ALLOW OWNER_RIGHTS (S-1-3-4) 0` — **load-bearing**. Replaces
//!      the implicit `READ_CONTROL | WRITE_DAC` that the kernel hands
//!      the file owner with a zero-access mask. Without this the
//!      sandbox child (running as the same user that owns the file)
//!      would walk through our DACL via owner-implicit.
//!
//! Set with `PROTECTED_DACL_SECURITY_INFORMATION` so inherited ACEs
//! don't grant access from parent directories.
//!
//! Restoration uses the self-relative SECURITY_DESCRIPTOR bytes
//! captured before the stamp (DACL + Owner + Group). On Drop we
//! compare the *current* DACL bytes against the bytes we wrote: a
//! match means nobody else has touched it and we restore; a mismatch
//! means another tool has edited it (rare; user with `icacls`), and
//! we log a warning and leave it alone.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AddAccessAllowedAce, GetAce, GetLengthSid, GetSecurityDescriptorDacl,
    GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    InitializeAcl, ACE_HEADER, ACL, ACL_REVISION,
    ACL_SIZE_INFORMATION, AclSizeInformation, GetAclInformation,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

use crate::sid::{free_psid, psid_from_string};
use crate::util::wstr;

/// OWNER_RIGHTS well-known SID. ACE for this SID replaces the kernel's
/// implicit `READ_CONTROL | WRITE_DAC` grant to the file owner.
pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";
/// LocalSystem.
pub const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators alias.
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// Returned by `capture_full_sd` — a self-relative SECURITY_DESCRIPTOR
/// covering DACL + Owner + Group, stored as bytes.
///
/// The bytes are heap-owned and freed when `Self::Drop` runs.
pub struct CapturedSd {
    bytes: Vec<u8>,
}

impl CapturedSd {
    #[allow(dead_code)]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Capture DACL + Owner + Group as a self-relative SECURITY_DESCRIPTOR.
/// The returned bytes are suitable for storage in the `acl_snapshots`
/// table and for round-tripping back into `SetNamedSecurityInfoW`.
pub fn capture_full_sd(path: &Path) -> Result<CapturedSd> {
    let w = wstr(&path.display().to_string());
    let info = DACL_SECURITY_INFORMATION
        | OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // The other out-params can be ignored — psd points at a self-
    // relative SECURITY_DESCRIPTOR allocated by LocalAlloc.
    unsafe {
        let r = GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut psd as *mut PSECURITY_DESCRIPTOR,
        );
        if r.is_err() {
            return Err(anyhow!(
                "GetNamedSecurityInfoW({}) WIN32_ERROR=0x{:08x}",
                path.display(),
                r.0
            ));
        }
    }

    // Serialize psd into a byte vector. The kernel guarantees that the
    // returned SD is self-relative — its size is recoverable by walking
    // the embedded structure. windows-rs doesn't expose
    // GetSecurityDescriptorLength via an easy import in this feature
    // set, but it lives in the same DLL and is trivially callable.
    use windows::Win32::Security::GetSecurityDescriptorLength;
    let len = unsafe { GetSecurityDescriptorLength(psd) } as usize;
    if len == 0 {
        unsafe { let _ = LocalFree(HLOCAL(psd.0)); }
        return Err(anyhow!(
            "GetSecurityDescriptorLength({}) returned 0",
            path.display()
        ));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(psd.0 as *const u8, len).to_vec()
    };
    unsafe { let _ = LocalFree(HLOCAL(psd.0)); }
    Ok(CapturedSd { bytes })
}

/// Capture just the DACL as the raw ACL bytes (no SD envelope). Used
/// for the "did anyone else modify the file's DACL between our stamp
/// and our release?" check.
pub fn capture_dacl_bytes(path: &Path) -> Result<Vec<u8>> {
    let w = wstr(&path.display().to_string());
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        let r = GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd as *mut PSECURITY_DESCRIPTOR,
        );
        if r.is_err() {
            return Err(anyhow!(
                "GetNamedSecurityInfoW(DACL only, {}) WIN32_ERROR=0x{:08x}",
                path.display(),
                r.0
            ));
        }

        // Extract the DACL pointer from inside the SD.
        let mut present = windows::Win32::Foundation::BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = windows::Win32::Foundation::BOOL(0);
        let g = GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted);
        if g.is_err() {
            let _ = LocalFree(HLOCAL(psd.0));
            return Err(anyhow!(
                "GetSecurityDescriptorDacl({}): {g:?}",
                path.display()
            ));
        }
        if !present.as_bool() || dacl.is_null() {
            let _ = LocalFree(HLOCAL(psd.0));
            // A NULL DACL is a valid kernel state ("everyone full
            // access"). Represent it as a zero-length byte slice — the
            // compare will only succeed if the stamped state is also
            // NULL, which we'd never write.
            return Ok(Vec::new());
        }

        // The ACL's total size is in its 2nd u16 field (AclSize). Use
        // GetAclInformation for clarity instead of poking offsets.
        let mut info = ACL_SIZE_INFORMATION::default();
        let r2 = GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );
        if r2.is_err() {
            let _ = LocalFree(HLOCAL(psd.0));
            return Err(anyhow!(
                "GetAclInformation({}): {r2:?}",
                path.display()
            ));
        }
        // AclBytesInUse covers header + every ACE.
        let total = info.AclBytesInUse as usize;
        let bytes =
            std::slice::from_raw_parts(dacl as *const u8, total).to_vec();
        let _ = LocalFree(HLOCAL(psd.0));
        Ok(bytes)
    }
}

/// Build the replacement DACL (heap-owned byte buffer) for one file.
/// Caller owns the buffer; pass it to `apply_stamp_with_acl_bytes`.
///
/// Layout: ACL header + four ACCESS_ALLOWED_ACEs in this order:
///   1. winsbox-allowed   FILE_ALL_ACCESS
///   2. SYSTEM            FILE_ALL_ACCESS
///   3. Administrators    FILE_ALL_ACCESS
///   4. OWNER_RIGHTS      0
fn build_stamp_dacl(allowed_sid_str: &str) -> Result<(Vec<u8>, [PSID; 4])> {
    let allowed = psid_from_string(allowed_sid_str)
        .context("psid_from_string(winsbox-allowed)")?;
    let system = psid_from_string(SID_LOCAL_SYSTEM)
        .context("psid_from_string(SYSTEM)")?;
    let admins = psid_from_string(SID_BUILTIN_ADMINS)
        .context("psid_from_string(Admins)")?;
    let owner_rights = psid_from_string(SID_OWNER_RIGHTS)
        .context("psid_from_string(OWNER_RIGHTS)")?;
    let owned = [allowed, system, admins, owner_rights];

    // ACL header + Σ ACE size. ACCESS_ALLOWED_ACE fixed prefix is 8
    // bytes (4 header + 4 mask); SidStart is the first DWORD of the
    // SID so total on-disk size is 8 + sid_len. Round to DWORD.
    const ACE_FIXED: usize = 8;
    let mut total: usize = std::mem::size_of::<ACL>();
    for s in &owned {
        let len = unsafe { GetLengthSid(*s) } as usize;
        if len == 0 {
            for s in owned {
                free_psid(s);
            }
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        total += ACE_FIXED + len;
    }
    total = (total + 3) & !3;
    let mut buf = vec![0u8; total];
    unsafe {
        let acl = buf.as_mut_ptr() as *mut ACL;
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl(stamp DACL)")?;
        // ACE 1: winsbox-allowed FILE_ALL_ACCESS.
        AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, allowed)
            .context("AddAccessAllowedAce(winsbox-allowed)")?;
        // ACE 2: SYSTEM FILE_ALL_ACCESS.
        AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, system)
            .context("AddAccessAllowedAce(SYSTEM)")?;
        // ACE 3: Administrators FILE_ALL_ACCESS.
        AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, admins)
            .context("AddAccessAllowedAce(Admins)")?;
        // ACE 4: OWNER_RIGHTS mask=0. This is the load-bearing ACE —
        // it replaces the kernel's implicit owner grant.
        AddAccessAllowedAce(acl, ACL_REVISION, 0, owner_rights)
            .context("AddAccessAllowedAce(OWNER_RIGHTS=0)")?;
    }
    Ok((buf, owned))
}

/// Write the stamp DACL onto `path`. Returns the ACL bytes we just
/// wrote (so the caller can persist them in `stamped_dacl` for later
/// "is this still ours?" comparison) and the resulting DACL bytes
/// fetched back from the kernel (which may differ — Windows can
/// re-order, canonicalize, normalize).
pub fn apply_stamp(path: &Path, allowed_sid_str: &str) -> Result<Vec<u8>> {
    let (acl_buf, owned_sids) = build_stamp_dacl(allowed_sid_str)?;
    let w = wstr(&path.display().to_string());
    let r = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(acl_buf.as_ptr() as *const ACL),
            None,
        )
    };
    for s in owned_sids {
        free_psid(s);
    }
    if r.is_err() {
        return Err(anyhow!(
            "SetNamedSecurityInfoW(stamp DACL, {}) WIN32_ERROR=0x{:08x}",
            path.display(),
            r.0
        ));
    }
    // Round-trip the DACL back so we get the canonical form the kernel
    // settled on. This is what we'll compare against during release.
    let canonical = capture_dacl_bytes(path)
        .context("capture_dacl_bytes after stamp")?;
    Ok(canonical)
}

/// Restore the file's DACL from a previously-captured full SD blob
/// (DACL + Owner + Group, self-relative bytes).
///
/// Special case: if every ACE in the captured DACL has the
/// `INHERITED_ACE` flag set, the file had no explicit DACL of its own
/// — its effective DACL came entirely from parent-directory
/// inheritance. To preserve that, we restore by clearing the explicit
/// DACL (empty ACL + UNPROTECTED_DACL_SECURITY_INFORMATION) so the
/// kernel re-derives the effective DACL from the parent. Round-
/// tripping the inherited ACEs directly would persist them as
/// EXPLICIT ACEs on the file, switching protection state from
/// `D:AI(...)` to `D:PAI(...)` and decoupling the file from any
/// future parent-DACL changes.
///
/// Safety: `sd_bytes` must be a valid self-relative SECURITY_DESCRIPTOR
/// — typically captured by `capture_full_sd`.
pub fn restore_full_sd(path: &Path, sd_bytes: &[u8]) -> Result<()> {
    if sd_bytes.is_empty() {
        return Err(anyhow!(
            "restore_full_sd({}): empty SD bytes",
            path.display()
        ));
    }
    let psd = PSECURITY_DESCRIPTOR(sd_bytes.as_ptr() as *mut c_void);
    let mut present = windows::Win32::Foundation::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::Win32::Foundation::BOOL(0);
    let mut owner = PSID::default();
    let mut owner_def = windows::Win32::Foundation::BOOL(0);
    let mut group = PSID::default();
    let mut group_def = windows::Win32::Foundation::BOOL(0);
    unsafe {
        // Pull pointers into the SD bytes.
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| anyhow!("GetSecurityDescriptorDacl(restore): {e}"))?;
        let _ = GetSecurityDescriptorOwner(psd, &mut owner, &mut owner_def);
        let _ = GetSecurityDescriptorGroup(psd, &mut group, &mut group_def);

        let all_inherited = present.as_bool()
            && !dacl.is_null()
            && dacl_is_purely_inherited(dacl);

        let mut info = DACL_SECURITY_INFORMATION;
        if !owner.0.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        if !group.0.is_null() {
            info |= GROUP_SECURITY_INFORMATION;
        }
        // If the captured DACL was purely inherited, restore by going
        // back to "no explicit DACL, inheritance ON" — empty ACL +
        // UNPROTECTED flag. Otherwise round-trip the bytes faithfully.
        let empty_acl: Vec<u8>;
        let (dacl_ptr, extra_info): (Option<*const ACL>, u32) = if all_inherited {
            empty_acl = build_empty_acl()?;
            info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
            (Some(empty_acl.as_ptr() as *const ACL), 0)
        } else if present.as_bool() && !dacl.is_null() {
            (Some(dacl as *const ACL), 0)
        } else {
            (None, 0)
        };
        let _ = extra_info;

        let w = wstr(&path.display().to_string());
        let r = SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            if owner.0.is_null() { PSID::default() } else { owner },
            if group.0.is_null() { PSID::default() } else { group },
            dacl_ptr,
            None,
        );
        if r.is_err() {
            return Err(anyhow!(
                "SetNamedSecurityInfoW(restore, {}) WIN32_ERROR=0x{:08x}",
                path.display(),
                r.0
            ));
        }
    }
    Ok(())
}

/// True if every ACE in `dacl` has the `INHERITED_ACE` flag set (and
/// the DACL is non-empty). Used by `restore_full_sd` to detect the
/// "file had no explicit DACL" case and restore via inheritance
/// instead of round-tripping explicit ACEs.
unsafe fn dacl_is_purely_inherited(dacl: *mut ACL) -> bool {
    const INHERITED_ACE: u8 = 0x10;
    let mut info = ACL_SIZE_INFORMATION::default();
    let r = GetAclInformation(
        dacl,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );
    if r.is_err() || info.AceCount == 0 {
        return false;
    }
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace_ptr).is_err() || ace_ptr.is_null() {
            return false;
        }
        let hdr = ace_ptr as *const ACE_HEADER;
        if (*hdr).AceFlags & INHERITED_ACE == 0 {
            return false;
        }
    }
    true
}

/// Build a self-contained zero-ACE ACL buffer. Used by `restore_full_sd`
/// to clear the file's explicit DACL while re-enabling inheritance.
fn build_empty_acl() -> Result<Vec<u8>> {
    let total = std::mem::size_of::<ACL>();
    let mut buf = vec![0u8; total];
    unsafe {
        InitializeAcl(buf.as_mut_ptr() as *mut ACL, total as u32, ACL_REVISION)
            .context("InitializeAcl(empty restore ACL)")?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_dacl_builds_for_well_known_sid() {
        // BUILTIN\Users — pick anything that resolves so InitializeAcl
        // / AddAccessAllowedAce don't trip in the test.
        let (bytes, sids) = build_stamp_dacl("S-1-5-32-545").expect("build");
        for s in sids {
            free_psid(s);
        }
        assert!(bytes.len() >= std::mem::size_of::<ACL>());
        // ACL revision is byte 0; should be 2.
        assert_eq!(bytes[0], 2);
    }
}
