//! P11: which lowbox capability (if any) re-opens LSA RPC enough
//! for `AcquireCredentialsHandle(Schannel)` and
//! `LookupPrivilegeName` to succeed, without re-opening outbound
//! network?
//!
//! Parent: for each variant, builds the token, spawns itself with
//! `--child` under it, captures the child's one-line report.
//! Child: directly calls the two LSA-backed APIs and prints
//! `schannel=OK|<err>  lookup=OK|<err>  net=BLOCKED|OPEN`.
//!
//! `net` is a `connect()` to 1.1.1.1:80 — we want a row where
//! schannel/lookup are OK and net stays BLOCKED.

#[cfg(not(windows))]
fn main() { eprintln!("windows only"); std::process::exit(2); }

#[cfg(windows)] #[path = "../util.rs"] mod util;
#[cfg(windows)] #[path = "../appcontainer.rs"] mod appcontainer;
#[cfg(windows)] #[path = "../token.rs"] mod token;
#[cfg(windows)] #[path = "../acl.rs"] mod acl;

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        return child();
    }
    parent();
}

// ─── child: probe LSA-backed APIs under whatever token we got ─────

#[cfg(windows)]
fn child() {
    use std::mem::zeroed;
    use util::wstr;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, FreeCredentialsHandle, SECPKG_CRED_OUTBOUND,
    };
    use windows::Win32::Security::Credentials::SecHandle;
    use windows::Win32::Security::{LookupPrivilegeNameW, LookupPrivilegeValueW};

    // ── Schannel
    let schannel = unsafe {
        let mut cred: SecHandle = zeroed();
        let mut expiry = 0i64;
        let mut pkg = wstr("Microsoft Unified Security Protocol Provider");
        let r = AcquireCredentialsHandleW(
            None, PWSTR(pkg.as_mut_ptr()),
            SECPKG_CRED_OUTBOUND, None, None, None, None,
            &mut cred, Some(&mut expiry),
        );
        match r {
            Ok(()) => { let _ = FreeCredentialsHandle(&cred); "OK".to_string() }
            Err(e) => format!("{:#x}", e.code().0),
        }
    };

    // ── LookupPrivilegeName (for SeChangeNotifyPrivilege's LUID)
    let lookup = unsafe {
        let mut luid = LUID::default();
        let mut name = [0u16; 64];
        let mut len = name.len() as u32;
        let r = LookupPrivilegeValueW(
            None, windows::core::PCWSTR(wstr("SeChangeNotifyPrivilege").as_ptr()),
            &mut luid,
        ).and_then(|_| LookupPrivilegeNameW(
            None, &luid, PWSTR(name.as_mut_ptr()), &mut len,
        ));
        match r {
            Ok(()) => "OK".to_string(),
            Err(e) => format!("{:#x}", e.code().0),
        }
    };

    // ── Outbound TCP (must stay blocked for any acceptable variant)
    let net = match std::net::TcpStream::connect_timeout(
        &"1.1.1.1:80".parse().unwrap(),
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => "OPEN",
        Err(_) => "BLOCKED",
    };

    println!("schannel={schannel}  lookup={lookup}  net={net}");
}

// ─── parent: build token variants, spawn --child under each ───────

#[cfg(windows)]
fn parent() {
    use std::ffi::c_void;
    use std::io::Read;
    use std::mem::{size_of, zeroed};
    use util::wstr;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DeriveCapabilitySidsFromName, PSID, SID_AND_ATTRIBUTES,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, SetThreadToken,
        WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW, STARTF_USESTDHANDLES,
    };

    let self_exe = std::env::current_exe().unwrap();
    let outfile = std::env::temp_dir().join(format!("p11-{}.txt", std::process::id()));

    struct V { name: &'static str, lowbox: bool, restricted: bool, caps: &'static [&'static str] }
    let variants = [
        V { name: "restricted only (no lowbox)",
            lowbox: false, restricted: true, caps: &[] },
        V { name: "lowbox only (no restricted)",
            lowbox: true, restricted: false, caps: &[] },
        V { name: "restricted+lowbox baseline (= broker today)",
            lowbox: true, restricted: true, caps: &[] },
        V { name: "+ internetClient (control: should OPEN net)",
            lowbox: true, restricted: true, caps: &["internetClient"] },
        V { name: "+ lpacCryptoServices",
            lowbox: true, restricted: true, caps: &["lpacCryptoServices"] },
        V { name: "+ lpacCom",
            lowbox: true, restricted: true, caps: &["lpacCom"] },
        V { name: "+ lpacIdentityServices",
            lowbox: true, restricted: true, caps: &["lpacIdentityServices"] },
        V { name: "+ lpacAppExperience",
            lowbox: true, restricted: true, caps: &["lpacAppExperience"] },
        V { name: "+ lpacCryptoServices + lpacCom",
            lowbox: true, restricted: true,
            caps: &["lpacCryptoServices", "lpacCom"] },
        V { name: "+ lpacCryptoServices + lpacIdentityServices",
            lowbox: true, restricted: true,
            caps: &["lpacCryptoServices", "lpacIdentityServices"] },
        V { name: "+ registryRead",
            lowbox: true, restricted: true, caps: &["registryRead"] },
        V { name: "+ all lpac* above",
            lowbox: true, restricted: true,
            caps: &["lpacCryptoServices", "lpacCom",
                    "lpacIdentityServices", "lpacAppExperience",
                    "registryRead"] },
    ];

    println!("# P11 LSA-under-lowbox capability matrix\n");
    println!("| variant | schannel | lookup | net | exit |");
    println!("|---|---|---|---|---|");

    for (i, v) in variants.iter().enumerate() {
        let _ = std::fs::remove_file(&outfile);
        let r: anyhow::Result<(u32, String)> = (|| unsafe {
            let ac = appcontainer::AppContainer::create(&format!("p11v{i}"))?;
            // Resolve capability SIDs.
            let mut cap_sids: Vec<PSID> = Vec::new();
            for c in v.caps {
                let w = wstr(c);
                let mut grp_sids: *mut PSID = std::ptr::null_mut();
                let mut grp_n = 0u32;
                let mut sid_arr: *mut PSID = std::ptr::null_mut();
                let mut sid_n = 0u32;
                DeriveCapabilitySidsFromName(
                    PCWSTR(w.as_ptr()),
                    &mut grp_sids, &mut grp_n,
                    &mut sid_arr, &mut sid_n,
                )?;
                for j in 0..sid_n {
                    cap_sids.push(*sid_arr.add(j as usize));
                }
            }
            let cap_attrs: Vec<SID_AND_ATTRIBUTES> = cap_sids.iter()
                .map(|s| SID_AND_ATTRIBUTES { Sid: *s, Attributes: 4 /*SE_GROUP_ENABLED*/ })
                .collect();

            // Tokens
            let base = token::open_self_token()?;
            let il = token::IL_UNTRUSTED;
            let lock = if v.restricted {
                token::make_lockdown_with(base, il, token::USER_LIMITED)?
            } else {
                let mut p = HANDLE::default();
                windows::Win32::Security::DuplicateTokenEx(
                    base, windows::Win32::Security::TOKEN_ALL_ACCESS, None,
                    windows::Win32::Security::SecurityImpersonation,
                    windows::Win32::Security::TokenPrimary, &mut p,
                )?;
                p
            };
            let init = token::make_initial(base, il)?;
            let _ = CloseHandle(base);

            let (primary, initial) = if v.lowbox {
                let lp = make_lowbox_caps(lock, ac.sid, &cap_attrs)?;
                let li = make_lowbox_caps(init, ac.sid, &cap_attrs)?;
                let _ = CloseHandle(lock); let _ = CloseHandle(init);
                (token::to_primary(lp)?, token::to_impersonation(li)?)
            } else {
                (token::to_primary(lock)?, token::to_impersonation(init)?)
            };

            // Spawn the child DIRECTLY (cmd /c can't spawn under
            // lockdown — that's P10). Redirect stdout/stderr to a
            // file via STARTF_USESTDHANDLES; the file is opened by
            // the parent (full token) and inherited.
            let mut acls = acl::AclJournal::default();
            if v.lowbox {
                acls.grant(
                    self_exe.parent().unwrap().to_str().unwrap(),
                    &ac.sid_string, acl::READ_EXECUTE,
                )?;
            }
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                FILE_GENERIC_WRITE, FILE_SHARE_READ,
            };
            use windows::Win32::Security::SECURITY_ATTRIBUTES;
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: true.into(),
            };
            let outpath = wstr(outfile.to_str().unwrap());
            let h_out = CreateFileW(
                PCWSTR(outpath.as_ptr()), FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ, Some(&sa), CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, None,
            )?;
            let mut clw = wstr(&format!(r#""{}" --child"#, self_exe.display()));
            let mut si: STARTUPINFOW = zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = h_out;
            si.hStdError = h_out;
            let mut pi: PROCESS_INFORMATION = zeroed();
            CreateProcessAsUserW(
                primary, None, PWSTR(clw.as_mut_ptr()), None, None, true,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                None, None, &si, &mut pi,
            )?;
            let _ = CloseHandle(h_out);
            let _ = SetThreadToken(Some(&pi.hThread), initial);
            ResumeThread(pi.hThread);
            let r = WaitForSingleObject(pi.hProcess, 15_000);
            let mut code = 0u32;
            if r == windows::Win32::Foundation::WAIT_TIMEOUT {
                let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 999);
                code = 999;
            } else {
                let _ = GetExitCodeProcess(pi.hProcess, &mut code);
            }
            let _ = CloseHandle(pi.hThread); let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(primary); let _ = CloseHandle(initial);
            let mut out = String::new();
            let _ = std::fs::File::open(&outfile)
                .and_then(|mut f| f.read_to_string(&mut out));
            Ok((code, out))
        })();
        match r {
            Ok((code, out)) => {
                let line = out.lines().find(|l| l.contains("schannel="))
                    .unwrap_or("schannel=?  lookup=?  net=?");
                let g = |k: &str| line.split_whitespace()
                    .find(|p| p.starts_with(k))
                    .map(|p| &p[k.len()..]).unwrap_or("?");
                println!("| {} | {} | {} | {} | {code:#x} |",
                    v.name, g("schannel="), g("lookup="), g("net="));
            }
            Err(e) => println!("| {} | ERR | ERR | ERR | `{}` |", v.name,
                format!("{e}").chars().take(40).collect::<String>()),
        }
    }
    let _ = std::fs::remove_file(&outfile);
}

#[cfg(windows)]
fn make_lowbox_caps(
    tok: windows::Win32::Foundation::HANDLE,
    sid: windows::Win32::Security::PSID,
    caps: &[windows::Win32::Security::SID_AND_ATTRIBUTES],
) -> anyhow::Result<windows::Win32::Foundation::HANDLE> {
    use std::mem::{size_of, zeroed};
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{HANDLE, NTSTATUS};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateLowBoxToken(out: *mut HANDLE, existing: HANDLE, access: u32,
            oa: *mut OBJECT_ATTRIBUTES, sid: windows::Win32::Security::PSID,
            cap_count: u32, caps: *const windows::Win32::Security::SID_AND_ATTRIBUTES,
            handle_count: u32, handles: *mut HANDLE) -> NTSTATUS;
    }
    unsafe {
        let mut out = HANDLE::default();
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        let st = NtCreateLowBoxToken(
            &mut out, tok, 0x02000000, &mut oa, sid,
            caps.len() as u32,
            if caps.is_empty() { std::ptr::null() } else { caps.as_ptr() },
            0, std::ptr::null_mut(),
        );
        anyhow::ensure!(st.0 >= 0, "NtCreateLowBoxToken: {:#x}", st.0);
        Ok(out)
    }
}
