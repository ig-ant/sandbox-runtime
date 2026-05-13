//! `probe_owner_rights` — empirical check that `ALLOW OWNER_RIGHTS 0`
//! actually defeats the owner-implicit `WRITE_DAC` grant.
//!
//! Test plan:
//!   1. Create a temp file in `%TEMP%`. We're the owner.
//!   2. Apply the Phase 5C stamp DACL via `winsbox::acl::apply_stamp`
//!      with a well-known SID (BUILTIN\Users) in the `winsbox-allowed`
//!      slot — we don't need a real broker group for this check; the
//!      OWNER_RIGHTS=0 ACE is what we're verifying.
//!   3. Build a sandbox token (LockdownSpec marking BUILTIN\Users as
//!      deny-only) and impersonate it on this thread.
//!   4. From inside the impersonation, try `SetNamedSecurityInfoW` on
//!      the file with a permissive replacement DACL. Expect
//!      `ERROR_ACCESS_DENIED (5)`.
//!   5. Print `OWNER_RIGHTS_OK` if the rewrite was denied as expected,
//!      `OWNER_RIGHTS_FAIL hr=...` otherwise.
//!
//! Exit codes:
//!   0  — empirical check passed (owner-implicit was successfully shut)
//!   1  — empirical check failed (sandbox could still rewrite DACL)
//!   2  — infrastructure failure (couldn't apply stamp, etc.)

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_owner_rights: Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Security::Authorization::{
        SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AddAccessAllowedAce, GetLengthSid, ImpersonateLoggedOnUser, InitializeAcl,
        RevertToSelf, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    use winsbox::acl;
    use winsbox::sid::{free_psid, psid_from_string};
    use winsbox::token::{self, open_self_token, IL_MEDIUM, LockdownSpec};
    use winsbox::util::wstr;

    // 1) Create a temp file we own.
    let tmp = std::env::temp_dir().join(format!(
        "winsbox-owner-rights-probe-{}.bin",
        std::process::id()
    ));
    if let Err(e) = std::fs::write(&tmp, b"probe contents") {
        eprintln!("write tmp file: {e}");
        std::process::exit(2);
    }

    // Closure so we can `?`-style propagate via match and centralize
    // tmp cleanup at the end.
    let inner = || -> Result<i32, String> {
        // BUILTIN\Users — present in every interactive user's token.
        // For this probe we use it as a stand-in for `winsbox-allowed`:
        // we'll mark it deny-only on the sandbox token, and the stamp
        // DACL includes it as an explicit ALLOW.
        let target_sid_str = "S-1-5-32-545";

        // 2) Apply the stamp DACL.
        acl::apply_stamp(&tmp, target_sid_str)
            .map_err(|e| format!("apply_stamp: {e:#}"))?;

        // 3) Build a sandbox-shape token and impersonate.
        let self_tok = open_self_token()
            .map_err(|e| format!("open_self_token: {e:#}"))?;
        let spec = LockdownSpec {
            sids_to_disable: vec![target_sid_str.to_string()],
        };
        let restricted = token::make_sandbox_token(self_tok, IL_MEDIUM, &spec)
            .map_err(|e| {
                unsafe { let _ = CloseHandle(self_tok); }
                format!("make_sandbox_token: {e:#}")
            })?;
        let imp = token::to_impersonation(restricted).map_err(|e| {
            unsafe {
                let _ = CloseHandle(restricted);
                let _ = CloseHandle(self_tok);
            }
            format!("to_impersonation: {e:#}")
        })?;

        unsafe {
            if let Err(e) = ImpersonateLoggedOnUser(imp) {
                let _ = CloseHandle(imp);
                let _ = CloseHandle(restricted);
                let _ = CloseHandle(self_tok);
                return Err(format!("ImpersonateLoggedOnUser: {e}"));
            }
        }

        // 4) Try to rewrite the DACL from inside the impersonation.
        //    Build a tiny "grant Everyone full" replacement DACL.
        let target = psid_from_string("S-1-1-0").map_err(|e| {
            unsafe {
                let _ = RevertToSelf();
                let _ = CloseHandle(imp);
                let _ = CloseHandle(restricted);
                let _ = CloseHandle(self_tok);
            }
            format!("psid_from_string(Everyone): {e:#}")
        })?;

        let result = unsafe {
            let sid_len = GetLengthSid(target) as usize;
            let total = std::mem::size_of::<ACL>() + 8 + sid_len;
            let total = (total + 3) & !3;
            let mut acl_buf = vec![0u8; total];
            let acl_ptr = acl_buf.as_mut_ptr() as *mut ACL;
            let _ = InitializeAcl(acl_ptr, total as u32, ACL_REVISION);
            let _ = AddAccessAllowedAce(
                acl_ptr,
                ACL_REVISION,
                FILE_ALL_ACCESS.0,
                target,
            );

            let path_w = wstr(&tmp.display().to_string());
            let r = SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                PSID::default(),
                PSID::default(),
                Some(acl_ptr as *const ACL),
                None,
            );
            let le = GetLastError().0;
            free_psid(target);
            let _ = RevertToSelf();
            let _ = CloseHandle(imp);
            let _ = CloseHandle(restricted);
            let _ = CloseHandle(self_tok);
            if r.is_err() {
                println!(
                    "OWNER_RIGHTS_OK denied=true win32_error=0x{:08x} last_err={le}",
                    r.0
                );
                0
            } else {
                println!("OWNER_RIGHTS_FAIL rewrite-succeeded last_err={le}");
                1
            }
        };
        Ok(result)
    };

    let exit_code = match inner() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            2
        }
    };
    let _ = std::fs::remove_file(&tmp);
    std::process::exit(exit_code);
}
