//! PSID + SID-string helpers and per-user / per-group SID lookups.
//!
//! Used by `wfp.rs`, `install.rs`, `launch.rs`, `token.rs`. The earlier
//! deterministic-machine-SID logic (sha256 of MachineGuid → custom
//! SECURITY_RESOURCE_MANAGER_AUTHORITY SID) is gone — empirical work
//! (`Y:\synthetic-sid-probe.md`) showed `CreateRestrictedToken` cannot
//! inject SIDs that aren't already in the source token, so the
//! discriminator must be a real local group.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, TokenGroups,
    TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::SystemServices::{
    SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::util::{from_pwstr, pcwstr, wstr};

/// Convert a string SID like `"S-1-5-32-544"` to a heap-owned PSID.
/// Caller frees with `free_psid` / `LocalFree`.
pub fn psid_from_string(sid_str: &str) -> Result<PSID> {
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
        unsafe {
            let _ = LocalFree(HLOCAL(sid.0));
        }
    }
}

/// Return the string form of a PSID. Convenience for marker-file
/// serialization and logging.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    crate::util::local_free(p.0 as *mut c_void);
    Ok(s)
}

/// Resolve the SID of a local-machine account (user or group). Calls
/// `LookupAccountNameW` with a `NULL` system name, which restricts the
/// resolution to the local SAM. Returns the SID in string form.
pub fn lookup_local_account_sid(name: &str) -> Result<String> {
    unsafe {
        let mut cb_sid: u32 = 0;
        let mut cch_dom: u32 = 0;
        let mut use_: SID_NAME_USE = SID_NAME_USE::default();
        let name_w = wstr(name);
        // First call to size the buffer. Returns ERROR_INSUFFICIENT_BUFFER.
        let _ = LookupAccountNameW(
            windows::core::PCWSTR::null(),
            pcwstr(&name_w),
            PSID::default(),
            &mut cb_sid,
            PWSTR::null(),
            &mut cch_dom,
            &mut use_,
        );
        if cb_sid == 0 {
            return Err(anyhow!("LookupAccountNameW({name}): zero size"));
        }
        let mut sid_buf = vec![0u8; cb_sid as usize];
        let mut dom_buf = vec![0u16; cch_dom as usize];
        LookupAccountNameW(
            windows::core::PCWSTR::null(),
            pcwstr(&name_w),
            PSID(sid_buf.as_mut_ptr() as *mut c_void),
            &mut cb_sid,
            PWSTR(dom_buf.as_mut_ptr()),
            &mut cch_dom,
            &mut use_,
        )
        .map_err(|e| anyhow!("LookupAccountNameW({name}): {e}"))?;
        let psid = PSID(sid_buf.as_mut_ptr() as *mut c_void);
        psid_to_string(psid)
    }
}

/// Return the current process token user's SID in string form.
pub fn current_user_sid() -> Result<String> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        // Size query.
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let r = GetTokenInformation(
            tok,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenUser)")?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        psid_to_string(tu.User.Sid)
    }
}

/// State of a SID inside the current process's `TokenGroups`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// SID is in TokenGroups and the `SE_GROUP_ENABLED` bit is set.
    Enabled,
    /// SID is in TokenGroups but marked deny-only
    /// (`SE_GROUP_USE_FOR_DENY_ONLY`).
    DenyOnly,
    /// SID is in TokenGroups but neither enabled nor deny-only — caller
    /// can decide whether to treat it as missing.
    Present,
    /// SID isn't in TokenGroups at all.
    Absent,
}

/// Inspect the current process token to see how `target_sid` (string
/// form) appears in `TokenGroups`. Used by the broker to verify that
/// the user has logged out + back in after install (`Absent`) and to
/// distinguish a fresh broker invocation (`Enabled`) from a stale token
/// (`DenyOnly`).
pub fn group_state_for_self(target_sid: &str) -> Result<GroupState> {
    let target = psid_from_string(target_sid)?;
    let state = group_state_inner(target);
    free_psid(target);
    state
}

fn group_state_inner(target: PSID) -> Result<GroupState> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, TokenGroups, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let r = GetTokenInformation(
            tok,
            TokenGroups,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenGroups)")?;
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let arr = std::slice::from_raw_parts(
            tg.Groups.as_ptr(),
            tg.GroupCount as usize,
        );
        for g in arr {
            if windows::Win32::Security::EqualSid(target, g.Sid).is_ok() {
                let attrs = g.Attributes as i32;
                if attrs & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                    return Ok(GroupState::DenyOnly);
                }
                if attrs & SE_GROUP_ENABLED != 0 {
                    return Ok(GroupState::Enabled);
                }
                return Ok(GroupState::Present);
            }
        }
        Ok(GroupState::Absent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psid_string_round_trip() {
        // Well-known Everyone SID.
        let p = psid_from_string("S-1-1-0").expect("from_string");
        let s = psid_to_string(p).expect("to_string");
        assert_eq!(s, "S-1-1-0");
        free_psid(p);
    }

    #[test]
    fn psid_lookup_local_users_group() {
        // BUILTIN\Users is universally present; this also confirms
        // `LookupAccountNameW(NULL, ...)` works in our shim.
        let s = lookup_local_account_sid("BUILTIN\\Users").expect("BUILTIN\\Users");
        assert_eq!(s, "S-1-5-32-545");
    }
}
