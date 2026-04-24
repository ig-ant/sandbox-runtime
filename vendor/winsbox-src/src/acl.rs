use crate::util::{pcwstr, wstr};
use anyhow::{bail, Result};
use std::ffi::c_void;
use std::ptr::null_mut;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    NO_MULTIPLE_TRUSTEE, GRANT_ACCESS, DENY_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_GROUP, TRUSTEE_W, ACCESS_MODE,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE,
};

pub const READ_EXECUTE: u32 = 0x1200A9; // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
pub const MODIFY: u32       = 0x1301BF; // GENERIC_READ|WRITE|EXECUTE minus WRITE_DAC/OWNER

/// Tracks every ACE we add so they can be reverted on exit (and via
/// `--cleanup` after a crash).
#[derive(Default)]
pub struct AclJournal {
    entries: Vec<(String, String)>, // (path, sid_string)
}

impl AclJournal {
    pub fn grant(&mut self, path: &str, sid: PSID, sid_str: &str, mask: u32) -> Result<()> {
        // GRANT_ACCESS (additive) — SET_ACCESS would discard any
        // existing deny ACE for this trustee when propagation reaches
        // a denyRead subtree.
        apply_ace(path, sid, mask, GRANT_ACCESS)?;
        self.entries.push((path.to_string(), sid_str.to_string()));
        Ok(())
    }
    pub fn deny(&mut self, path: &str, sid: PSID, sid_str: &str, mask: u32) -> Result<()> {
        // Deny the per-instance package SID *and* ALL APPLICATION
        // PACKAGES (S-1-15-2-1) — an AppContainer token carries both,
        // so denying only the package SID lets the read through via
        // an inherited ALL_APP_PACKAGES allow.
        apply_ace(path, sid, mask, DENY_ACCESS)?;
        self.entries.push((path.to_string(), sid_str.to_string()));
        if let Ok(all_ac) = well_known_all_app_packages() {
            apply_ace(path, all_ac, mask, DENY_ACCESS)?;
            self.entries.push((path.to_string(), "S-1-15-2-1".to_string()));
            unsafe { let _ = LocalFree(HLOCAL(all_ac.0)); }
        }
        Ok(())
    }
    pub fn revert_all(&mut self) {
        for (path, sid_str) in self.entries.drain(..) {
            let _ = remove_aces_for_sid(&path, &sid_str);
        }
    }
}

impl Drop for AclJournal {
    fn drop(&mut self) { self.revert_all(); }
}

fn apply_ace(path: &str, sid: PSID, mask: u32, mode: ACCESS_MODE) -> Result<()> {
    unsafe {
        let p = wstr(path);
        let mut old_dacl: *mut ACL = null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(
            pcwstr(&p), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            None, None, Some(&mut old_dacl), None, &mut sd,
        );
        if r.is_err() { bail!("GetNamedSecurityInfoW({path}): {:?}", r); }

        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: mode,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(sid.0 as *mut u16),
            },
        };
        let mut new_dacl: *mut ACL = null_mut();
        let r = SetEntriesInAclW(Some(&[ea]), Some(old_dacl), &mut new_dacl);
        let _ = LocalFree(HLOCAL(sd.0));
        if r.is_err() { bail!("SetEntriesInAclW({path}): {:?}", r); }

        let r = SetNamedSecurityInfoW(
            pcwstr(&p), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            None, None, Some(new_dacl), None,
        );
        let _ = LocalFree(HLOCAL(new_dacl as *mut c_void));
        if r.is_err() { bail!("SetNamedSecurityInfoW({path}): {:?}", r); }
        Ok(())
    }
}

/// Remove every ACE that names `sid_str` from `path`'s DACL. Used for
/// revert; cheaper than tracking the exact ACE we added.
fn well_known_all_app_packages() -> Result<PSID> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let mut sid = PSID::default();
    unsafe { ConvertStringSidToSidW(pcwstr(&wstr("S-1-15-2-1")), &mut sid)?; }
    Ok(sid)
}

/// Diagnostic: dump the effective DACL of `path` via icacls.
pub fn dump(path: &str) -> String {
    std::process::Command::new("icacls").arg(path)
        .output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn remove_aces_for_sid(path: &str, sid_str: &str) -> Result<()> {
    use windows::Win32::Security::Authorization::{ConvertStringSidToSidW, REVOKE_ACCESS};
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(pcwstr(&wstr(sid_str)), &mut sid)?;
        let r = apply_ace(path, sid, 0, REVOKE_ACCESS);
        let _ = LocalFree(HLOCAL(sid.0));
        r
    }
}
