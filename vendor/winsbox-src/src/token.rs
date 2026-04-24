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

/// Restricting-SID list shape for `make_lockdown_with`.
#[derive(Clone, Copy, Debug)]
pub enum Restricting {
    /// `keep_enabled` ∪ {Logon SID, RESTRICTED}. Current Phase-2
    /// production shape — broad enough that the loader can read
    /// system files via raw syscall.
    Keep,
    /// {Logon SID, RESTRICTED} only.
    LogonAndRestricted,
    /// {S-1-0-0}. Chromium USER_LOCKDOWN — every access check
    /// fails the restricting pass unless the object's DACL grants
    /// NULL SID (effectively never).
    Null,
}

#[derive(Clone, Copy, Debug)]
pub struct LockdownSpec {
    /// Group SIDs (string form) that stay enabled; every other
    /// group goes deny-only. The Logon SID and the integrity-label
    /// group are always exempt from deny-only regardless.
    pub keep_enabled: &'static [&'static str],
    pub restricting: Restricting,
}

pub const USER_LIMITED: LockdownSpec = LockdownSpec {
    keep_enabled: &["S-1-1-0", "S-1-5-11", "S-1-5-32-545"],
    restricting: Restricting::Keep,
};
pub const USER_LOCKDOWN: LockdownSpec = LockdownSpec {
    keep_enabled: &[],
    restricting: Restricting::Null,
};

/// `WINSBOX_TOKEN=lockdown` → (USER_LOCKDOWN, Untrusted IL).
/// Anything else → (USER_LIMITED, Low IL). The IL is returned so
/// `build_broker_tokens` can apply the same level to the initial
/// impersonation token (SeTokenCanImpersonate requires they match).
pub fn spec_from_env() -> (LockdownSpec, u32) {
    match std::env::var("WINSBOX_TOKEN").as_deref() {
        Ok("lockdown") => (USER_LOCKDOWN, IL_UNTRUSTED),
        _ => (USER_LIMITED, IL_LOW),
    }
}

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

// TODO(phase-2b): cmd /c <ext.exe> under this primary still fails
// "Access is denied" even with jobwatch re-impersonation and the
// default DACL below. ProcMon on a real box is needed to isolate
// which object/access fails; candidates are conhost ALPC port,
// BaseNamedObjects, or csrss section. Chromium's recipe additionally
// (a) creates an alternate-window-station/desktop whose DACL grants
// the restricted SID, and (b) sets the lowbox token's saved-handle
// list so the AC directory objects are pre-created — one of those
// is likely the missing piece.

/// Phase-2 primary token. Defaults to USER_LIMITED (deny-only on
/// admin/elevated groups, keep Users/Everyone/AuthUsers, drop
/// every privilege except SeChangeNotify) so brokered children
/// can still read system files via raw syscall while the
/// confused-deputy hardening lands. `WINSBOX_TOKEN=lockdown`
/// switches to USER_LOCKDOWN (deny-all + NULL restricting SID) for
/// step-0 retesting and CI bisection.
pub fn make_lockdown(base: HANDLE, il_rid: u32) -> Result<HANDLE> {
    let (spec, _) = spec_from_env();
    make_lockdown_with(base, il_rid, spec)
}

pub fn make_lockdown_with(
    base: HANDLE, il_rid: u32, spec: LockdownSpec,
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

        // Restricting list. RESTRICTED (S-1-5-12) is the canonical
        // "restricted code" SID; the broker also grants it on
        // allowRead/allowWrite so those paths pass the restricting
        // check on the lockdown primary after RevertToSelf.
        // AppContainer package SIDs are not valid restricting SIDs
        // — CreateRestrictedToken returns ERROR_INVALID_PARAMETER.
        let logon_sid = garr.iter()
            .find(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0)
            .map(|g| g.Sid);
        let mut owned_restrict: Vec<PSID> = Vec::new();
        let restrict: Vec<SID_AND_ATTRIBUTES> = match spec.restricting {
            Restricting::Keep => {
                let mut v: Vec<SID_AND_ATTRIBUTES> = keep_sids.iter()
                    .map(|s| SID_AND_ATTRIBUTES { Sid: *s, Attributes: 0 }).collect();
                if let Some(l) = logon_sid {
                    v.push(SID_AND_ATTRIBUTES { Sid: l, Attributes: 0 });
                }
                if let Some(r) = str_sid("S-1-5-12") {
                    owned_restrict.push(r);
                    v.push(SID_AND_ATTRIBUTES { Sid: r, Attributes: 0 });
                }
                v
            }
            Restricting::LogonAndRestricted => {
                let mut v = Vec::new();
                if let Some(l) = logon_sid {
                    v.push(SID_AND_ATTRIBUTES { Sid: l, Attributes: 0 });
                }
                if let Some(r) = str_sid("S-1-5-12") {
                    owned_restrict.push(r);
                    v.push(SID_AND_ATTRIBUTES { Sid: r, Attributes: 0 });
                }
                v
            }
            Restricting::Null => {
                let n = str_sid("S-1-0-0").expect("S-1-0-0");
                owned_restrict.push(n);
                vec![SID_AND_ATTRIBUTES { Sid: n, Attributes: 0 }]
            }
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
        let _ = AllocateAndInitializeSid; // keep import
        let _ = SID_IDENTIFIER_AUTHORITY { Value: [0;6] };
        set_il(out, il_rid)?;
        // Without an explicit default DACL, objects (including child
        // processes) created under this token get a DACL that csrss/
        // conhost can't open, so cmd's CreateProcess fails. Grant
        // SYSTEM + the user's logon SID + RESTRICTED.
        if let Err(e) = set_default_dacl(out, garr) {
            eprintln!("[sbox-exec] set_default_dacl: {e:#}");
        }
        Ok(out)
    }
}

fn set_default_dacl(tok: HANDLE, groups: &[SID_AND_ATTRIBUTES]) -> Result<()> {
    use windows::Win32::Security::{
        InitializeAcl, AddAccessAllowedAce, SetTokenInformation, TokenDefaultDacl,
        TOKEN_DEFAULT_DACL, ACL_REVISION,
    };
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    unsafe {
        let mut sids: Vec<PSID> = Vec::new();
        for s in ["S-1-5-18" /*SYSTEM*/, "S-1-5-12" /*RESTRICTED*/] {
            let mut p = PSID::default();
            if ConvertStringSidToSidW(pcwstr(&wstr(s)), &mut p).is_ok() { sids.push(p); }
        }
        // Logon SID from the base groups.
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

        // Return the PRIMARY restricted token; the caller lowbox-wraps
        // it (NtCreateLowBoxToken needs a primary input) and then dups
        // the lowbox result to impersonation for SetThreadToken.
        Ok(restricted)
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
