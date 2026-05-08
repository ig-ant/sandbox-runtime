//! P10: which token-recipe delta lets a restricted+lowbox process
//! spawn an external exe via `cmd /c`?
//!
//! Each variant builds the token pair, CreateProcessAsUser's
//! `cmd /c whoami /priv`, SetThreadToken's the initial impersonation,
//! resumes, and reports the grandchild's exit + whether stdout
//! contained the privilege table. The variant matrix toggles one
//! candidate fix at a time so the answer is unambiguous.

#[cfg(not(windows))]
fn main() { eprintln!("windows only"); std::process::exit(2); }

#[cfg(windows)]
#[path = "../util.rs"] mod util;
#[cfg(windows)]
#[path = "../appcontainer.rs"] mod appcontainer;
#[cfg(windows)]
#[path = "../token.rs"] mod token;
#[cfg(windows)]
#[path = "../acl.rs"] mod acl;

#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use util::wstr;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::SECURITY_CAPABILITIES;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, ResumeThread, SetThreadToken,
        UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NEW_CONSOLE,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
    };

    #[derive(Clone, Copy)]
    struct Variant {
        name: &'static str,
        use_lowbox: bool,
        use_sec_caps_attr: bool,
        extra_flags: PROCESS_CREATION_FLAGS,
        lowbox_handles: bool,
        ac_acl_on_winsta: bool,
        skip_restricted: bool,
        /// Lowbox-wrap the initial impersonation token even when
        /// `use_lowbox` is false. Tests the SECCAPS-asymmetric case:
        /// SECCAPS lowboxes the *primary* internally, so the initial
        /// must be lowboxed by hand to satisfy SeTokenCanImpersonate.
        lowbox_initial: bool,
    }
    const ZERO: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0);
    const D: Variant = Variant {
        name: "",
        use_lowbox: false, use_sec_caps_attr: false, extra_flags: ZERO,
        lowbox_handles: false, ac_acl_on_winsta: false,
        skip_restricted: false, lowbox_initial: false,
    };
    #[allow(clippy::needless_update)]
    let variants = [
        Variant { name: "baseline (restricted+lowbox, no extras)",
                  use_lowbox: true, ..D },
        Variant { name: "+ SECURITY_CAPABILITIES attr (double-AC)",
                  use_lowbox: true, use_sec_caps_attr: true, ..D },
        Variant { name: "+ CREATE_NEW_CONSOLE",
                  use_lowbox: true, extra_flags: CREATE_NEW_CONSOLE, ..D },
        Variant { name: "+ DETACHED_PROCESS (no conhost)",
                  use_lowbox: true, extra_flags: DETACHED_PROCESS, ..D },
        Variant { name: "+ CREATE_NO_WINDOW",
                  use_lowbox: true, extra_flags: CREATE_NO_WINDOW, ..D },
        Variant { name: "+ lowbox saved-handle list (AC dirs)",
                  use_lowbox: true, lowbox_handles: true, ..D },
        Variant { name: "+ grant AC SID on WinSta0+Default desktop",
                  use_lowbox: true, ac_acl_on_winsta: true, ..D },
        Variant { name: "restricted-only (no lowbox, no AC)", ..D },
        Variant { name: "lowbox-only (no CreateRestrictedToken)",
                  use_lowbox: true, skip_restricted: true, ..D },
        Variant { name: "restricted + SECCAPS (no manual lowbox)",
                  use_sec_caps_attr: true, ..D },
        Variant { name: "restricted + SECCAPS + CREATE_NO_WINDOW",
                  use_sec_caps_attr: true, extra_flags: CREATE_NO_WINDOW, ..D },
        Variant { name: "unrestricted + SECCAPS (= Phase-1 via AsUser)",
                  use_sec_caps_attr: true, skip_restricted: true, ..D },
        Variant { name: "+ lowbox handles + CREATE_NO_WINDOW",
                  use_lowbox: true, extra_flags: CREATE_NO_WINDOW,
                  lowbox_handles: true, ..D },
        // ── Asymmetric lowbox: SECCAPS lowboxes the primary inside
        // CreateProcessInternalW; lowbox only the initial so
        // SeTokenCanImpersonate's AC-match check is satisfied. If
        // this passes, the broker can drop NtCreateLowBoxToken on
        // the primary and get SECCAPS' AC-env setup for free →
        // grandchildren spawn without a hook.
        Variant { name: "restricted + SECCAPS + lowbox(initial only)",
                  use_sec_caps_attr: true, lowbox_initial: true, ..D },
        Variant { name: "restricted + SECCAPS + lowbox(initial) + NO_WINDOW",
                  use_sec_caps_attr: true, lowbox_initial: true,
                  extra_flags: CREATE_NO_WINDOW, ..D },
        Variant { name: "unrestricted + SECCAPS + lowbox(initial only)",
                  use_sec_caps_attr: true, lowbox_initial: true,
                  skip_restricted: true, ..D },
        // ── Restricted-only deltas: if any of these work, the
        // network boundary would have to come from elsewhere but
        // brokered-spawn becomes unnecessary.
        Variant { name: "restricted-only + DETACHED_PROCESS",
                  extra_flags: DETACHED_PROCESS, ..D },
        Variant { name: "restricted-only + CREATE_NO_WINDOW",
                  extra_flags: CREATE_NO_WINDOW, ..D },
    ];

    // Output redirected to a file the broker can always read.
    let outfile = std::env::temp_dir().join(format!("p10-{}.txt", std::process::id()));
    let outfile_s = outfile.to_string_lossy().to_string();
    let cmd_line = format!(r#"cmd.exe /d /s /c "whoami.exe /priv > "{outfile_s}" 2>&1""#);

    println!("# P10 grandchild-under-restricted-lowbox matrix\n");
    println!("| variant | exit | grandchild ran? | output head |");
    println!("|---|---|---|---|");

    for (i, v) in variants.iter().copied().enumerate() {
        let _ = std::fs::remove_file(&outfile);
        let r = (|| -> anyhow::Result<(u32, String)> {
            let ac = appcontainer::AppContainer::create(&format!("p10v{i}"))?;
            let mut acls = acl::AclJournal::default();
            // The AC must be able to read the temp dir to write outfile,
            // and read System32 (already ALL APP PACKAGES).
            acls.grant(outfile.parent().unwrap().to_str().unwrap(),
                       &ac.sid_string, acl::MODIFY)?;
            if v.ac_acl_on_winsta {
                grant_winsta_desktop(&ac.sid_string);
            }

            let base = token::open_self_token()?;
            let il = token::IL_UNTRUSTED;
            let (lock, init) = if v.skip_restricted {
                let mut p = HANDLE::default();
                unsafe {
                    windows::Win32::Security::DuplicateTokenEx(
                        base, windows::Win32::Security::TOKEN_ALL_ACCESS, None,
                        windows::Win32::Security::SecurityImpersonation,
                        windows::Win32::Security::TokenPrimary, &mut p,
                    )?;
                }
                (p, token::make_initial(base, il)?)
            } else {
                (token::make_lockdown_with(base, il, token::USER_LIMITED)?,
                 token::make_initial(base, il)?)
            };
            unsafe { let _ = CloseHandle(base); }

            let primary_src = if v.use_lowbox {
                let lb = if v.lowbox_handles {
                    make_lowbox_with_handles(lock, ac.sid, &ac.sid_string)?
                } else {
                    token::make_lowbox(lock, ac.sid, &[])?
                };
                unsafe { let _ = CloseHandle(lock); }
                lb
            } else { lock };
            let initial_src = if v.use_lowbox || v.lowbox_initial {
                let lb = token::make_lowbox(init, ac.sid, &[])?;
                unsafe { let _ = CloseHandle(init); }
                lb
            } else { init };
            let (primary, initial) =
                (token::to_primary(primary_src)?, token::to_impersonation(initial_src)?);

            let mut size = 0usize;
            unsafe {
                let _ = InitializeProcThreadAttributeList(
                    LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
            }
            let mut attr_buf = vec![0u8; size.max(1)];
            let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
            let mut si: STARTUPINFOEXW = unsafe { zeroed() };
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            let caps = SECURITY_CAPABILITIES {
                AppContainerSid: ac.sid, Capabilities: std::ptr::null_mut(),
                CapabilityCount: 0, Reserved: 0,
            };
            let mut flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | v.extra_flags;
            if v.use_sec_caps_attr {
                unsafe {
                    InitializeProcThreadAttributeList(attrs, 1, 0, &mut size)?;
                    UpdateProcThreadAttribute(
                        attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                        Some(&caps as *const _ as *const c_void),
                        size_of::<SECURITY_CAPABILITIES>(), None, None,
                    )?;
                }
                si.lpAttributeList = attrs;
                flags |= EXTENDED_STARTUPINFO_PRESENT;
            }

            let mut clw = wstr(&cmd_line);
            let cwd = wstr(std::env::temp_dir().to_str().unwrap());
            let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
            let code = unsafe {
                CreateProcessAsUserW(
                    primary, None, PWSTR(clw.as_mut_ptr()), None, None, true,
                    flags, None, PCWSTR(cwd.as_ptr()), &si.StartupInfo, &mut pi,
                )?;
                let _ = SetThreadToken(Some(&pi.hThread), initial);
                ResumeThread(pi.hThread);
                let r = WaitForSingleObject(pi.hProcess, 15_000);
                let mut c = 0u32;
                if r == windows::Win32::Foundation::WAIT_TIMEOUT {
                    let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 999);
                    c = 999;
                } else {
                    let _ = GetExitCodeProcess(pi.hProcess, &mut c);
                }
                if v.use_sec_caps_attr { DeleteProcThreadAttributeList(attrs); }
                let _ = CloseHandle(pi.hThread); let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(primary); let _ = CloseHandle(initial);
                c
            };
            let out = std::fs::read_to_string(&outfile).unwrap_or_default();
            Ok((code, out))
        })();
        match r {
            Ok((code, out)) => {
                let ran = out.to_lowercase().contains("sechangenotify")
                       || out.to_lowercase().contains("privilege name");
                let head = out.lines().next().unwrap_or("").chars().take(60).collect::<String>();
                println!("| {} | {code:#x} | {} | `{}` |",
                    v.name, if ran { "YES" } else { "no" },
                    head.replace('|', "\\|"));
            }
            Err(e) => println!("| {} | ERR | - | `{}` |", v.name,
                format!("{e}").replace('|', "\\|")),
        }
    }
    let _ = std::fs::remove_file(&outfile);
}

#[cfg(windows)]
fn grant_winsta_desktop(_sid_str: &str) {
    // Marker only — if every other variant fails and this one is
    // the candidate, it gets a real SetSecurityInfo impl.
}

#[cfg(windows)]
fn make_lowbox_with_handles(
    tok: windows::Win32::Foundation::HANDLE,
    sid: windows::Win32::Security::PSID,
    sid_str: &str,
) -> anyhow::Result<windows::Win32::Foundation::HANDLE> {
    use std::mem::{size_of, zeroed};
    use util::wstr;
    use windows::core::PCWSTR;
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
    // Pre-create the AC's named-object directories so the lowbox
    // token's saved-handle list references them — Chromium's
    // app_container_base.cc does this so BaseGetNamedObjectDirectory
    // inside the child can open \Sessions\N\AppContainerNamedObjects\<SID>.
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateDirectoryObject(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES) -> NTSTATUS;
        fn NtCreateLowBoxToken(out: *mut HANDLE, existing: HANDLE, access: u32,
            oa: *mut OBJECT_ATTRIBUTES, sid: windows::Win32::Security::PSID,
            cap_count: u32, caps: *mut std::ffi::c_void,
            handle_count: u32, handles: *mut HANDLE) -> NTSTATUS;
        fn RtlInitUnicodeString(dst: *mut UNICODE_STRING, src: PCWSTR);
    }
    unsafe {
        let session = std::env::var("SESSIONNAME").ok();
        let _ = session;
        let sess_id = windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId();
        let paths = [
            format!(r"\Sessions\{sess_id}\AppContainerNamedObjects\{sid_str}"),
            format!(r"\Sessions\{sess_id}\AppContainerNamedObjects\{sid_str}\RPC Control"),
        ];
        let mut handles: Vec<HANDLE> = Vec::new();
        for p in &paths {
            let wp = wstr(p);
            let mut us: UNICODE_STRING = zeroed();
            RtlInitUnicodeString(&mut us, PCWSTR(wp.as_ptr()));
            let oa = OBJECT_ATTRIBUTES {
                Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: HANDLE::default(),
                ObjectName: &us as *const _ as *mut _,
                Attributes: 0x40 | 0x80, // OBJ_CASE_INSENSITIVE | OBJ_OPENIF
                SecurityDescriptor: std::ptr::null_mut(),
                SecurityQualityOfService: std::ptr::null_mut(),
            };
            let mut h = HANDLE::default();
            let st = NtCreateDirectoryObject(&mut h, 0x000F000F, &oa);
            if st.0 >= 0 { handles.push(h); }
            std::mem::forget(wp);
        }
        let mut out = HANDLE::default();
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        let st = NtCreateLowBoxToken(
            &mut out, tok, 0x02000000, &mut oa, sid, 0, std::ptr::null_mut(),
            handles.len() as u32,
            if handles.is_empty() { std::ptr::null_mut() } else { handles.as_mut_ptr() },
        );
        anyhow::ensure!(st.0 >= 0, "NtCreateLowBoxToken(handles): {:#x}", st.0);
        Ok(out)
    }
}
