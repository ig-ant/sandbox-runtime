// Cribbed: SID-string helpers from acl_stamper.rs in winsbox-msys2-iter.
//! Deterministic per-machine SANDBOX_SID for the WFP+SID network sandbox.
//!
//! Phase 2 responsibilities:
//!   - Read `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` and SHA-256
//!     it to derive 4 u32 subauthorities.
//!   - Build the SID via `AllocateAndInitializeSid` with identifier
//!     authority `SECURITY_RESOURCE_MANAGER_AUTHORITY` (9) and five
//!     subauthorities ending in a fixed RID of `1` so the same machine
//!     can mint variant SIDs later by changing only the RID.
//!   - Cache the result in a `OnceLock` so callers can hold static refs.

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::PSID;

use crate::util::{from_pwstr, pcwstr, wstr};

/// Convert a string SID like `"S-1-15-2-1"` to a heap-owned PSID.
/// Caller frees with `free_psid` / `LocalFree`.
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

/// Return the string form of a PSID. Convenience for marker-file
/// serialization and logging.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    crate::util::local_free(p.0 as *mut c_void);
    Ok(s)
}

/// Return the deterministic per-machine SANDBOX_SID as raw PSID bytes.
/// Cached for process lifetime.
pub fn sandbox_sid() -> Result<&'static [u8]> {
    todo!("phase 2: MachineGuid → SHA256 → SID via AllocateAndInitializeSid, cache in OnceLock")
}

/// Return the SDDL string form of `sandbox_sid()`. Cached for process
/// lifetime.
pub fn sandbox_sid_string() -> Result<&'static str> {
    todo!("phase 2: ConvertSidToStringSidW of sandbox_sid()")
}
