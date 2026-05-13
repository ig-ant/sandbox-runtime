//! Phase 4.5 v3 Layer 5 — broker self-protection.
//!
//! Rewrites the broker process's kernel-object DACL so the sandbox
//! child cannot `OpenProcess(broker_pid, PROCESS_VM_*|CREATE_THREAD)`
//! against it. The DACL is replaced with an explicit ALLOW list
//! scoped to SIDs the sandbox does NOT have enabled in its token:
//!
//!   - `winsbox-allowed`            (sandbox has it deny-only)
//!   - `S-1-5-18`  (LocalSystem)    (sandbox doesn't carry it)
//!   - `S-1-5-32-544` (BUILTIN\Admins) (sandbox has it deny-only)
//!
//! `PROTECTED_DACL_SECURITY_INFORMATION` is required: without it the
//! inherited "user has full access to their own process" ACE remains
//! and the rewrite is a no-op for same-user sandbox children.
//!
//! Documented residual: at Medium IL with the same user, ANOTHER
//! non-sandbox process belonging to the same user (e.g. Explorer)
//! still has `winsbox-allowed` enabled and can therefore open the
//! broker. This is intentional — the threat model is the sandbox
//! child, not the rest of the user's session.
//!
//! Gated on `WINSBOX_BROKER_PROTECT` (defaults to ON; set to "0" to
//! disable, e.g. for a diagnostic harness that needs to OpenProcess
//! the broker from outside the sandbox).

use anyhow::{anyhow, Context, Result};
use std::mem::size_of;
use windows::Win32::Security::Authorization::{
    SetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    AddAccessAllowedAce, GetLengthSid, InitializeAcl, ACL, ACL_REVISION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
};
use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_ALL_ACCESS};

use crate::sid::{free_psid, psid_from_string};
use crate::wfp;

/// Rewrite the current (broker) process's DACL to deny the sandbox
/// child OpenProcess. Idempotent — safe to call once per broker
/// invocation. Returns `Ok(false)` when gated off by env.
pub fn install_broker_dacl() -> Result<bool> {
    if std::env::var_os("WINSBOX_BROKER_PROTECT")
        .map(|v| v == "0")
        .unwrap_or(false)
    {
        return Ok(false);
    }

    // Resolve the three principals we want to allow.
    //
    // `winsbox-allowed` comes from the marker file (its SID is the
    // discriminator the sandbox token has marked deny-only). If the
    // marker is absent we can't safely rewrite — abort silently. The
    // launch path will surface the "filters not installed" error
    // separately.
    let marker = match wfp::read_install_marker()? {
        Some(m) => m,
        None => return Ok(false),
    };

    let allowed_sid = psid_from_string(&marker.group_sid)
        .context("psid_from_string(winsbox-allowed)")?;
    let system_sid = psid_from_string("S-1-5-18")
        .context("psid_from_string(SYSTEM)")?;
    let admins_sid = psid_from_string("S-1-5-32-544")
        .context("psid_from_string(Admins)")?;

    // Bracket all the unsafe FFI so that any early return still
    // frees the three PSIDs at the end.
    let result = unsafe { install_inner(allowed_sid, system_sid, admins_sid) };

    free_psid(allowed_sid);
    free_psid(system_sid);
    free_psid(admins_sid);

    result.map(|_| true)
}

unsafe fn install_inner(
    allowed: PSID,
    system: PSID,
    admins: PSID,
) -> Result<()> {
    let sids = [allowed, system, admins];

    // ACL size = header + Σ(ACCESS_ALLOWED_ACE_size - sizeof(DWORD) + sid_len).
    // The fixed prefix of ACCESS_ALLOWED_ACE is 8 bytes (Header 4 +
    // Mask 4); `SidStart` is the first DWORD of the SID body, so the
    // total per-ACE on-disk size is 8 + sid_len.
    const ACE_FIXED: usize = 8;
    let mut total: usize = size_of::<ACL>();
    for s in &sids {
        let len = GetLengthSid(*s) as usize;
        if len == 0 {
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        total += ACE_FIXED + len;
    }
    // Round up to DWORD alignment, just in case.
    total = (total + 3) & !3;

    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    InitializeAcl(acl, total as u32, ACL_REVISION).context("InitializeAcl")?;

    let mask = PROCESS_ALL_ACCESS.0;
    for s in &sids {
        AddAccessAllowedAce(acl, ACL_REVISION, mask, *s)
            .context("AddAccessAllowedAce")?;
    }

    // PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs —
    // critical, otherwise the user SID's default "full access to own
    // process" inherited grant fires and the rewrite is a no-op.
    let r = SetSecurityInfo(
        GetCurrentProcess(),
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(acl as *const ACL),
        None,
    );
    if r.is_err() {
        return Err(anyhow!(
            "SetSecurityInfo(broker process DACL): WIN32_ERROR=0x{:08x}",
            r.0
        ));
    }

    // `buf` lifetime: SetSecurityInfo copies the ACL into the kernel-
    // object's SECURITY_DESCRIPTOR — we can drop the heap copy on
    // return. The DACL persists on the kernel object until the
    // process exits.
    drop(buf);
    Ok(())
}
