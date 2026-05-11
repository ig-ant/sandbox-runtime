//! `probe_token` — dumps the current process token contents for
//! verification (used by Group A of the test matrix).

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_token: Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::ffi::c_void;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{
        GetTokenInformation, LookupPrivilegeNameW, TokenGroups, TokenIntegrityLevel,
        TokenPrivileges, TokenRestrictedSids, TokenUser, PSID,
        TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe fn sid_to_string(p: PSID) -> String {
        let mut out = PWSTR::null();
        if ConvertSidToStringSidW(p, &mut out).is_err() {
            return "<bad sid>".to_string();
        }
        let mut len = 0usize;
        while *out.0.add(len) != 0 { len += 1; }
        let slice = std::slice::from_raw_parts(out.0, len);
        let s = String::from_utf16_lossy(slice);
        let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(out.0 as *mut c_void));
        s
    }

    unsafe fn get_info(tok: HANDLE, cls: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> anyhow::Result<Vec<u8>> {
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, cls, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(tok, cls, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len)
            .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }

    unsafe fn priv_name(luid: LUID) -> String {
        let mut len: u32 = 0;
        let _ = LookupPrivilegeNameW(windows::core::PCWSTR::null(), &luid, PWSTR::null(), &mut len);
        if len == 0 {
            return format!("LUID({:x}:{:x})", luid.HighPart, luid.LowPart);
        }
        let mut buf = vec![0u16; len as usize];
        if LookupPrivilegeNameW(
            windows::core::PCWSTR::null(),
            &luid,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        ).is_err() {
            return "<lookup err>".to_string();
        }
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        s
    }

    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;

        // TokenUser
        let buf = get_info(tok, TokenUser)?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        println!("TokenUser: {}", sid_to_string(tu.User.Sid));

        // TokenGroups
        let buf = get_info(tok, TokenGroups)?;
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let groups = std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize);
        println!("TokenGroups ({}):", groups.len());
        for g in groups {
            println!("  {} attrs=0x{:08x}", sid_to_string(g.Sid), g.Attributes);
        }

        // TokenRestrictedSids
        let buf = get_info(tok, TokenRestrictedSids)?;
        let tr = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let r = std::slice::from_raw_parts(tr.Groups.as_ptr(), tr.GroupCount as usize);
        println!("TokenRestrictedSids ({}):", r.len());
        for g in r {
            println!("  {} attrs=0x{:08x}", sid_to_string(g.Sid), g.Attributes);
        }

        // TokenIntegrityLevel
        let buf = get_info(tok, TokenIntegrityLevel)?;
        let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let s = sid_to_string(tml.Label.Sid);
        // Extract RID (last subauthority) for the readable IL.
        let rid: u32 = s.rsplit('-').next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let il_name = match rid {
            0x0000 => "Untrusted",
            0x1000 => "Low",
            0x2000 => "Medium",
            0x2100 => "MediumPlus",
            0x3000 => "High",
            0x4000 => "System",
            _ => "?",
        };
        println!("TokenIntegrityLevel: 0x{rid:x} ({il_name}) sid={s}");

        // TokenPrivileges
        let buf = get_info(tok, TokenPrivileges)?;
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let privs = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        println!("TokenPrivileges ({}):", privs.len());
        for p in privs {
            println!("  {} attrs=0x{:08x}", priv_name(p.Luid), p.Attributes.0);
        }

        let _ = CloseHandle(tok);
    }
    Ok(())
}
