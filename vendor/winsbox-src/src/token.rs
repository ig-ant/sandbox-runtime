//! Restricted-token construction for Mode::Broker.
//!
//! Phase-0 P5 finding (`SeTokenCanImpersonate`): the initial
//! impersonation token must match the lockdown primary on three
//! axes — restricted-flag, integrity level, and AppContainer — or
//! the kernel silently downgrades it to Identification and the
//! loader exits 0xC00000A5. So `make_initial` builds a
//! USER_RESTRICTED_SAME_ACCESS token (every group SID + user SID in
//! the restricting list — flagged restricted, identical effective
//! access), sets its IL to match lockdown, and the caller lowbox-
//! wraps it iff the primary is lowbox-wrapped.

use crate::util::{pcwstr, wstr};
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx, FreeSid,
    GetLengthSid, GetTokenInformation, LookupPrivilegeValueW, SecurityImpersonation,
    SetTokenInformation, TokenGroups, TokenImpersonation, TokenIntegrityLevel,
    TokenPrimary, TokenPrivileges, TokenUser, CREATE_RESTRICTED_TOKEN_FLAGS,
    LUID_AND_ATTRIBUTES, PSID, SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY,
    TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
    TOKEN_USER,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const IL_UNTRUSTED: u32 = 0x0000;
pub const IL_LOW: u32 = 0x1000;

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateLowBoxToken(
        token: *mut HANDLE, existing: HANDLE, access: u32,
        oa: *mut OBJECT_ATTRIBUTES, package_sid: PSID,
        capability_count: u32, capabilities: *mut c_void,
        handle_count: u32, handles: *mut HANDLE,
    ) -> NTSTATUS;
}

pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Lockdown primary: deny-only on every group except the Logon SID,
/// restricting SID = NULL SID, all privileges deleted except
/// SeChangeNotify. IL is set by the caller (Low for launch; the entry
/// trampoline can drop it to Untrusted post-init in a later commit).
pub fn make_lockdown(base: HANDLE, il_rid: u32) -> Result<HANDLE> {
    unsafe {
        let groups_buf = get_token_info(base, TokenGroups)?;
        let groups = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
        let garr = std::slice::from_raw_parts(
            groups.Groups.as_ptr(), groups.GroupCount as usize);
        let deny: Vec<SID_AND_ATTRIBUTES> = garr.iter()
            .filter(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) == 0)
            .map(|g| SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 })
            .collect();

        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

        let null_auth = SID_IDENTIFIER_AUTHORITY { Value: [0,0,0,0,0,0] };
        let mut null_sid = PSID::default();
        AllocateAndInitializeSid(&null_auth, 1, 0,0,0,0,0,0,0,0, &mut null_sid)?;
        let restrict = [SID_AND_ATTRIBUTES { Sid: null_sid, Attributes: 0 }];

        let mut out = HANDLE::default();
        CreateRestrictedToken(
            base, CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&deny),
            if to_delete.is_empty() { None } else { Some(&to_delete) },
            Some(&restrict),
            &mut out,
        ).context("CreateRestrictedToken(lockdown)")?;
        FreeSid(null_sid);
        set_il(out, il_rid)?;
        Ok(out)
    }
}

/// Initial impersonation: USER_RESTRICTED_SAME_ACCESS — restricting
/// list = user SID + every enabled group SID. Same effective access
/// as `base`, but flagged restricted so SeTokenCanImpersonate accepts
/// it on a thread whose process token is the lockdown primary.
pub fn make_initial(base: HANDLE, il_rid: u32) -> Result<HANDLE> {
    unsafe {
        let user_buf = get_token_info(base, TokenUser)?;
        let user = &*(user_buf.as_ptr() as *const TOKEN_USER);
        let groups_buf = get_token_info(base, TokenGroups)?;
        let groups = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
        let garr = std::slice::from_raw_parts(
            groups.Groups.as_ptr(), groups.GroupCount as usize);

        let mut restrict: Vec<SID_AND_ATTRIBUTES> = Vec::with_capacity(garr.len() + 1);
        restrict.push(SID_AND_ATTRIBUTES { Sid: user.User.Sid, Attributes: 0 });
        for g in garr {
            // Skip the integrity-label and deny-only groups.
            if g.Attributes & 0x20 != 0 { continue; } // SE_GROUP_INTEGRITY
            if g.Attributes & 0x10 != 0 { continue; } // SE_GROUP_USE_FOR_DENY_ONLY
            restrict.push(SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 });
        }
        // Drop privileges here too so the main thread (which keeps
        // this impersonation token until the entry trampoline lands
        // in a follow-up) already shows only SeChangeNotify.
        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

        let mut restricted = HANDLE::default();
        CreateRestrictedToken(
            base, CREATE_RESTRICTED_TOKEN_FLAGS(0),
            None,
            if to_delete.is_empty() { None } else { Some(&to_delete) },
            Some(&restrict), &mut restricted,
        ).context("CreateRestrictedToken(initial)")?;
        set_il(restricted, il_rid)?;

        let mut out = HANDLE::default();
        DuplicateTokenEx(
            restricted, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenImpersonation, &mut out,
        ).context("DuplicateTokenEx(initial)")?;
        let _ = CloseHandle(restricted);
        Ok(out)
    }
}

pub fn make_lowbox(token: HANDLE, package_sid: PSID) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        let st = NtCreateLowBoxToken(
            &mut out, token, 0x02000000 /* MAXIMUM_ALLOWED */,
            &mut oa, package_sid, 0, std::ptr::null_mut(),
            0, std::ptr::null_mut(),
        );
        anyhow::ensure!(st.0 >= 0, "NtCreateLowBoxToken: {:#x}", st.0);
        Ok(out)
    }
}

/// Duplicate `token` to a primary token (CreateProcessAsUser needs a
/// primary, and NtCreateLowBoxToken returns whatever type it got).
pub fn to_primary(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenPrimary, &mut out,
        ).context("DuplicateTokenEx(primary)")?;
        Ok(out)
    }
}

fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY { Value: [0,0,0,0,0,16] };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(&ml_auth, 1, rid, 0,0,0,0,0,0,0, &mut sid)?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: 0x20 },
        };
        SetTokenInformation(
            tok, TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        ).context("SetTokenInformation(IL)")?;
        FreeSid(sid);
        Ok(())
    }
}

fn get_token_info(
    tok: HANDLE,
    cls: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, cls, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(tok, cls, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len)
            .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }
}

fn privileges_except(base: HANDLE, keep: &[&str]) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    unsafe {
        let keep_luids: Vec<LUID> = keep.iter().filter_map(|n| {
            let mut l = LUID::default();
            LookupPrivilegeValueW(None, pcwstr(&wstr(n)), &mut l).ok()?;
            Some(l)
        }).collect();
        let buf = get_token_info(base, TokenPrivileges)?;
        let privs = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(
            privs.Privileges.as_ptr(), privs.PrivilegeCount as usize);
        Ok(arr.iter()
            .filter(|p| !keep_luids.iter().any(|k|
                k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart))
            .map(|p| LUID_AND_ATTRIBUTES { Luid: p.Luid, Attributes: Default::default() })
            .collect())
    }
}
