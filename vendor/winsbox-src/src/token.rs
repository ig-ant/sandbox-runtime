//! Restricted-token construction for the deny-only-group WFP+SID
//! sandbox.
//!
//! Phase 4 (May 2026) re-spec — moved away from USER_LIMITED:
//!   - No restricting-SIDs array (it breaks Schannel; see
//!     `Y:\schannel-probe.md`).
//!   - `SidsToDisable = [winsbox-allowed group SID, BUILTIN\Administrators]`
//!     flips them deny-only without touching the restricting list.
//!   - `LUA_TOKEN` flag (so the token looks like a normal limited-user
//!     token to NT components).
//!   - All privileges except `SeChangeNotifyPrivilege` deleted.
//!   - Integrity Level set to Medium (same as a normal user process).
//!
//! WFP's `ALE_USER_ID` AccessCheck honors `SE_GROUP_USE_FOR_DENY_ONLY`,
//! so the SDDL ACE `(A;;CC;;;<group_sid>)` matches only when the group
//! is enabled — i.e. on the broker, never on sandbox children.

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
    TokenPrimary, TokenPrivileges, LUA_TOKEN, LUID_AND_ATTRIBUTES, PSID,
    SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[allow(dead_code)]
pub const IL_LOW: u32 = 0x1000;
/// Medium integrity level (`SECURITY_MANDATORY_MEDIUM_RID`). Sandbox
/// child runs at Medium IL — same as normal user processes — so
/// Schannel / LSA / registry edge cases don't fire.
pub const IL_MEDIUM: u32 = 0x2000;

/// Built-in Administrators alias (`BUILTIN\Administrators`). Always
/// added to `sids_to_disable` so an elevated broker still produces a
/// non-admin child.
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// Token shape for `make_sandbox_token`. The deny-only-group fence
/// design moves the load-bearing SID from `RestrictingSids` to
/// `SidsToDisable`; the restricting list is always empty.
#[derive(Clone, Debug)]
pub struct LockdownSpec {
    /// SIDs (string form) to flip to `SE_GROUP_USE_FOR_DENY_ONLY`. The
    /// caller supplies the winsbox-allowed group SID here; we also
    /// implicitly add `BUILTIN\Administrators`.
    pub sids_to_disable: Vec<String>,
}

pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Build the deny-only-group restricted primary token shape.
///
/// Returns a non-primary token; the caller is expected to
/// `DuplicateTokenEx` it into a primary via `to_primary`.
pub fn make_sandbox_token(
    base: HANDLE,
    il_rid: u32,
    spec: &LockdownSpec,
) -> Result<HANDLE> {
    unsafe {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        let str_sid = |s: &str| -> Option<PSID> {
            let mut sid = PSID::default();
            ConvertStringSidToSidW(pcwstr(&wstr(s)), &mut sid).ok()?;
            Some(sid)
        };

        // Resolve every SID we'll need to disable. We must keep the
        // backing storage alive for the FreeSid call below; build a
        // parallel Vec<PSID>.
        let mut owned: Vec<PSID> = Vec::new();
        let mut disable_list: Vec<SID_AND_ATTRIBUTES> = Vec::new();

        // Always start with BUILTIN\Administrators.
        if let Some(s) = str_sid(SID_BUILTIN_ADMINS) {
            owned.push(s);
            disable_list.push(SID_AND_ATTRIBUTES {
                Sid: s,
                Attributes: 0,
            });
        }
        // Caller-supplied (the winsbox-allowed group SID).
        for s_str in &spec.sids_to_disable {
            // Skip duplicates (BUILTIN\Administrators may be in the list
            // already if caller wants to be explicit).
            if s_str == SID_BUILTIN_ADMINS {
                continue;
            }
            if let Some(s) = str_sid(s_str) {
                owned.push(s);
                disable_list.push(SID_AND_ATTRIBUTES {
                    Sid: s,
                    Attributes: 0,
                });
            } else {
                return Err(anyhow::anyhow!(
                    "ConvertStringSidToSidW({s_str}) failed"
                ));
            }
        }

        // Privileges to delete: everything except SeChangeNotify.
        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

        let mut out = HANDLE::default();
        CreateRestrictedToken(
            base,
            LUA_TOKEN,
            if disable_list.is_empty() {
                None
            } else {
                Some(&disable_list)
            },
            if to_delete.is_empty() {
                None
            } else {
                Some(&to_delete)
            },
            None,
            &mut out,
        )
        .with_context(|| format!("CreateRestrictedToken({spec:?})"))?;

        for s in owned {
            FreeSid(s);
        }

        set_il(out, il_rid)?;

        // Default DACL: include SYSTEM + the logon SID so the broker
        // can later open process handles, debug, etc. We don't add
        // RESTRICTED (S-1-5-12) anymore — there's no restricting list.
        let groups_buf = get_token_info(base, TokenGroups)?;
        let groups = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
        let garr = std::slice::from_raw_parts(
            groups.Groups.as_ptr(),
            groups.GroupCount as usize,
        );
        if let Err(e) = set_default_dacl(out, garr) {
            eprintln!("[sbox-exec] set_default_dacl: {e:#}");
        }
        Ok(out)
    }
}

pub fn set_default_dacl(tok: HANDLE, groups: &[SID_AND_ATTRIBUTES]) -> Result<()> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{
        AddAccessAllowedAce, InitializeAcl, TokenDefaultDacl, ACL_REVISION,
        TOKEN_DEFAULT_DACL,
    };
    unsafe {
        let mut sids: Vec<PSID> = Vec::new();
        for s in ["S-1-5-18" /*SYSTEM*/] {
            let mut p = PSID::default();
            if ConvertStringSidToSidW(pcwstr(&wstr(s)), &mut p).is_ok() {
                sids.push(p);
            }
        }
        for g in groups {
            if g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0 {
                sids.push(g.Sid);
            }
        }
        let mut buf = vec![0u8; 1024];
        let acl = buf.as_mut_ptr() as *mut windows::Win32::Security::ACL;
        InitializeAcl(acl, buf.len() as u32, ACL_REVISION).context("InitializeAcl")?;
        for s in &sids {
            AddAccessAllowedAce(
                acl,
                ACL_REVISION,
                0x10000000, /*GENERIC_ALL*/
                *s,
            )
            .context("AddAccessAllowedAce")?;
        }
        let tdd = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        SetTokenInformation(
            tok,
            TokenDefaultDacl,
            &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .context("SetTokenInformation(DefaultDacl)")?;
        Ok(())
    }
}

#[allow(dead_code)]
pub fn to_impersonation(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut out,
        )
        .context("DuplicateTokenEx(impersonation)")?;
        Ok(out)
    }
}

/// Duplicate `token` to a primary token (CreateProcessAsUser needs a
/// primary).
pub fn to_primary(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut out,
        )
        .context("DuplicateTokenEx(primary)")?;
        Ok(out)
    }
}

pub fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(&ml_auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid)?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0x20,
            },
        };
        SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        )
        .context("SetTokenInformation(IL)")?;
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
        GetTokenInformation(
            tok,
            cls,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }
}

fn privileges_except(base: HANDLE, keep: &[&str]) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    unsafe {
        let keep_luids: Vec<LUID> = keep
            .iter()
            .filter_map(|n| {
                let mut l = LUID::default();
                LookupPrivilegeValueW(None, pcwstr(&wstr(n)), &mut l).ok()?;
                Some(l)
            })
            .collect();
        let buf = get_token_info(base, TokenPrivileges)?;
        let privs = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(
            privs.Privileges.as_ptr(),
            privs.PrivilegeCount as usize,
        );
        Ok(arr
            .iter()
            .filter(|p| {
                !keep_luids
                    .iter()
                    .any(|k| k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart)
            })
            .map(|p| LUID_AND_ATTRIBUTES {
                Luid: p.Luid,
                Attributes: Default::default(),
            })
            .collect())
    }
}
