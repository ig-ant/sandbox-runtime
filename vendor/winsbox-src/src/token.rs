// Cribbed from `winsbox-msys2-iter` branch, lowbox/AC paths removed.
//! Restricted-token construction for the WFP+SID network sandbox.
//!
//! The donor branch built a two-phase token (USER_LIMITED restricted
//! primary, then a lowbox/AC wrapper on top). Here we keep only the
//! USER_LIMITED restricted primary — the lowbox/AC layer is gone, and
//! the WFP key (SANDBOX_SID) is added to the restricting-SID set by
//! the caller in `launch.rs`.

use crate::util::{pcwstr, wstr};
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
#[allow(unused_imports)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx, FreeSid,
    GetLengthSid, GetTokenInformation, LookupPrivilegeValueW, SecurityImpersonation,
    SetTokenInformation, TokenGroups, TokenImpersonation, TokenIntegrityLevel,
    TokenPrimary, TokenPrivileges, CREATE_RESTRICTED_TOKEN_FLAGS,
    LUID_AND_ATTRIBUTES, PSID, SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY,
    TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const IL_UNTRUSTED: u32 = 0x0000;
pub const IL_LOW: u32 = 0x1000;
/// Medium integrity level (`SECURITY_MANDATORY_MEDIUM_RID`). The
/// WFP+SID design runs the child at Medium IL — same as normal user
/// processes — so Schannel / LSA / registry edge cases don't fire.
pub const IL_MEDIUM: u32 = 0x2000;

/// Token shape for `make_lockdown_with`. `keep_enabled` lists the
/// group SIDs (string form) that stay enabled; every other group
/// goes deny-only (the Logon SID and the integrity-label group are
/// always exempt). The restricting list is built as
/// `keep_enabled ∪ {Logon SID, RESTRICTED, extra restricting SIDs}`.
#[derive(Clone, Debug)]
pub struct LockdownSpec {
    pub keep_enabled: &'static [&'static str],
    /// Additional SIDs (string form) to add to the restricting list
    /// beyond `keep_enabled ∪ {Logon SID, RESTRICTED}`. Phase 2 will
    /// use this for the WFP key (SANDBOX_SID).
    pub extra_restricting: Vec<String>,
}

pub const USER_LIMITED_KEEP: &[&str] = &["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];

pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Build the USER_LIMITED-style restricted primary token. Deny-only on
/// admin/elevated groups, keep Users/Everyone/AuthUsers enabled, drop
/// every privilege except SeChangeNotify. Caller is expected to add
/// the SANDBOX_SID via `spec.extra_restricting` (Phase 2).
pub fn make_lockdown_with(
    base: HANDLE, il_rid: u32, spec: &LockdownSpec,
) -> Result<HANDLE> {
    unsafe {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        let str_sid = |s: &str| -> Option<PSID> {
            let mut sid = PSID::default();
            ConvertStringSidToSidW(pcwstr(&wstr(s)), &mut sid).ok()?;
            Some(sid)
        };
        let groups_buf = get_token_info(base, TokenGroups)?;
        let groups = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
        let garr = std::slice::from_raw_parts(
            groups.Groups.as_ptr(), groups.GroupCount as usize);

        let keep_sids: Vec<PSID> =
            spec.keep_enabled.iter().filter_map(|s| str_sid(s)).collect();
        let deny: Vec<SID_AND_ATTRIBUTES> = garr.iter()
            .filter(|g| {
                if g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0 { return false; }
                if g.Attributes & 0x20 /*INTEGRITY*/ != 0 { return false; }
                !keep_sids.iter().any(|k|
                    windows::Win32::Security::EqualSid(*k, g.Sid).is_ok())
            })
            .map(|g| SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 })
            .collect();

        let logon_sid = garr.iter()
            .find(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0)
            .map(|g| g.Sid);
        let mut owned_restrict: Vec<PSID> = Vec::new();
        let restrict: Vec<SID_AND_ATTRIBUTES> = {
            let mut v: Vec<SID_AND_ATTRIBUTES> = keep_sids.iter()
                .map(|s| SID_AND_ATTRIBUTES { Sid: *s, Attributes: 0 }).collect();
            if let Some(l) = logon_sid {
                v.push(SID_AND_ATTRIBUTES { Sid: l, Attributes: 0 });
            }
            if let Some(r) = str_sid("S-1-5-12") {
                owned_restrict.push(r);
                v.push(SID_AND_ATTRIBUTES { Sid: r, Attributes: 0 });
            }
            for extra in &spec.extra_restricting {
                if let Some(s) = str_sid(extra) {
                    owned_restrict.push(s);
                    v.push(SID_AND_ATTRIBUTES { Sid: s, Attributes: 0 });
                }
            }
            v
        };

        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

        let mut out = HANDLE::default();
        CreateRestrictedToken(
            base, CREATE_RESTRICTED_TOKEN_FLAGS(0),
            if deny.is_empty() { None } else { Some(&deny) },
            if to_delete.is_empty() { None } else { Some(&to_delete) },
            Some(&restrict),
            &mut out,
        ).with_context(|| format!("CreateRestrictedToken({spec:?})"))?;
        for s in keep_sids { FreeSid(s); }
        for s in owned_restrict { FreeSid(s); }
        set_il(out, il_rid)?;
        if let Err(e) = set_default_dacl(out, garr) {
            eprintln!("[sbox-exec] set_default_dacl: {e:#}");
        }
        Ok(out)
    }
}

pub fn set_default_dacl(tok: HANDLE, groups: &[SID_AND_ATTRIBUTES]) -> Result<()> {
    use windows::Win32::Security::{
        InitializeAcl, AddAccessAllowedAce, TokenDefaultDacl,
        TOKEN_DEFAULT_DACL, ACL_REVISION,
    };
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    unsafe {
        let mut sids: Vec<PSID> = Vec::new();
        for s in ["S-1-5-18" /*SYSTEM*/, "S-1-5-12" /*RESTRICTED*/] {
            let mut p = PSID::default();
            if ConvertStringSidToSidW(pcwstr(&wstr(s)), &mut p).is_ok() { sids.push(p); }
        }
        for g in groups {
            if g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0 { sids.push(g.Sid); }
        }
        let mut buf = vec![0u8; 1024];
        let acl = buf.as_mut_ptr() as *mut windows::Win32::Security::ACL;
        InitializeAcl(acl, buf.len() as u32, ACL_REVISION).context("InitializeAcl")?;
        for s in &sids {
            AddAccessAllowedAce(acl, ACL_REVISION, 0x10000000 /*GENERIC_ALL*/, *s)
                .context("AddAccessAllowedAce")?;
        }
        let tdd = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        SetTokenInformation(
            tok, TokenDefaultDacl, &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        ).context("SetTokenInformation(DefaultDacl)")?;
        Ok(())
    }
}

pub fn to_impersonation(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenImpersonation, &mut out,
        ).context("DuplicateTokenEx(impersonation)")?;
        Ok(out)
    }
}

/// Duplicate `token` to a primary token (CreateProcessAsUser needs a
/// primary).
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

pub fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
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
