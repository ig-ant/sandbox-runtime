//! P12: which delta from USER_LIMITED → USER_LOCKDOWN breaks an
//! external exe under restricted+lowbox?
//!
//! P10 already proved a lockdown'd process can't spawn a child
//! UNAIDED, so brokered spawn is mandatory. With brokered spawn
//! the broker `CreateProcessAsUserW`'s every external exe itself,
//! so the remaining question is: under which token does an exe's
//! loader (running under the lowbox initial impersonation) plus
//! its post-RevertToSelf runtime survive?
//!
//! For each variant this probe builds {lockdown, initial} per the
//! variant's spec, lowbox-wraps both with the same AC SID, and
//! spawns two payloads DIRECTLY (no `cmd /c` nesting — stdout
//! redirected via `STARTUPINFOW.hStdOutput` so no shell needed):
//!   - `cmd.exe /d /c echo ok` — cmd's loader + a builtin only
//!   - `whoami.exe /priv`      — a plain external exe
//! and reports `exit | gle | output-head`. The first row where a
//! payload flips 0→nonzero names the SID/IL the failing object's
//! DACL is keyed on (Logon SID → desktop/winstation; Users →
//! BaseNamedObjects; Everyone/IL → conhost ALPC; NULL restricting
//! → KnownDlls section).

#[cfg(not(windows))]
fn main() { eprintln!("windows only"); std::process::exit(2); }

#[cfg(windows)] #[path = "../util.rs"] mod util;
#[cfg(windows)] #[path = "../appcontainer.rs"] mod appcontainer;
#[cfg(windows)] #[path = "../token.rs"] mod token;
#[cfg(windows)] #[path = "../acl.rs"] mod acl;

#[cfg(windows)]
fn main() {
    use std::mem::{size_of, zeroed};
    use token::{LockdownSpec, Restricting, IL_LOW, IL_UNTRUSTED};
    use util::{pcwstr, wstr};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_ALWAYS, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, SetThreadToken,
        TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW,
    };

    struct Variant {
        name: &'static str,
        spec: LockdownSpec,
        il: u32,
    }
    macro_rules! var {
        ($name:expr, [$($k:expr),*], $r:expr, $il:expr) => {
            Variant {
                name: $name,
                spec: LockdownSpec {
                    keep_enabled: { const K: &[&str] = &[$($k),*]; K },
                    restricting: $r,
                },
                il: $il,
            }
        };
    }
    const EVERYONE: &str = "S-1-1-0";
    const AUTH_USERS: &str = "S-1-5-11";
    const USERS: &str = "S-1-5-32-545";
    const RESTRICTED_SID: &str = "S-1-5-12";

    let variants = [
        var!("baseline USER_LIMITED, IL=Low",
             [EVERYONE, AUTH_USERS, USERS], Restricting::Keep, IL_LOW),
        // ── enabled-group bisection
        var!("- Everyone",
             [AUTH_USERS, USERS], Restricting::Keep, IL_LOW),
        var!("- AuthUsers",
             [EVERYONE, USERS], Restricting::Keep, IL_LOW),
        var!("- Users",
             [EVERYONE, AUTH_USERS], Restricting::Keep, IL_LOW),
        var!("- all three (Logon SID only enabled)",
             [], Restricting::Keep, IL_LOW),
        // ── restricting-list bisection
        var!("restricting = {Logon, RESTRICTED}",
             [EVERYONE, AUTH_USERS, USERS],
             Restricting::LogonAndRestricted, IL_LOW),
        var!("restricting = {S-1-0-0}",
             [EVERYONE, AUTH_USERS, USERS], Restricting::Null, IL_LOW),
        // ── IL bisection
        var!("IL = Untrusted",
             [EVERYONE, AUTH_USERS, USERS], Restricting::Keep, IL_UNTRUSTED),
        // ── combined
        var!("USER_LOCKDOWN (deny-all + Null + Untrusted)",
             [], Restricting::Null, IL_UNTRUSTED),
        var!("USER_LOCKDOWN but restricting = {Logon, RESTRICTED}",
             [], Restricting::LogonAndRestricted, IL_UNTRUSTED),
    ];

    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let sys32 = format!(r"{sysroot}\System32");
    struct Payload { tag: &'static str, cmdline: String, ok: &'static str }
    let payloads = [
        Payload {
            tag: "cmd-builtin",
            cmdline: format!(r#"{sys32}\cmd.exe /d /c echo ok"#),
            ok: "ok",
        },
        Payload {
            tag: "ext-exe",
            cmdline: format!(r#"{sys32}\whoami.exe /priv"#),
            ok: "sechangenotify",
        },
    ];

    let outfile = std::env::temp_dir().join(format!("p12-{}.txt", std::process::id()));
    // The lowbox initial token reads System32 via ALL APPLICATION
    // PACKAGES, but the lockdown primary's *restricting* list
    // governs post-RevertToSelf access. Grant RESTRICTED on
    // System32 + outfile-dir so the {Logon, RESTRICTED} variants
    // can resolve. (Null variants can't be helped by ACLs.)
    let mut pre_acls = acl::AclJournal::default();
    let _ = pre_acls.grant(&sys32, RESTRICTED_SID, acl::READ_EXECUTE);
    let _ = pre_acls.grant(
        outfile.parent().unwrap().to_str().unwrap(),
        RESTRICTED_SID, acl::MODIFY,
    );

    println!("# P12 USER_LIMITED → USER_LOCKDOWN bisection\n");
    println!("| variant | payload | exit | gle | ran? | head |");
    println!("|---|---|---|---|---|---|");

    for (i, var) in variants.iter().enumerate() {
        let ac = match appcontainer::AppContainer::create(&format!("p12v{i}")) {
            Ok(a) => a,
            Err(e) => {
                println!("| {} | - | ERR | - | - | `{e}` |", var.name);
                continue;
            }
        };
        let mut acls = acl::AclJournal::default();
        let _ = acls.grant(
            outfile.parent().unwrap().to_str().unwrap(),
            &ac.sid_string, acl::MODIFY,
        );
        let _ = acls.grant(&sys32, &ac.sid_string, acl::READ_EXECUTE);

        let toks = (|| -> anyhow::Result<(HANDLE, HANDLE)> {
            let base = token::open_self_token()?;
            let lock = token::make_lockdown_with(base, var.il, var.spec)?;
            let init = token::make_initial(base, var.il)?;
            unsafe { let _ = CloseHandle(base); }
            let lock_lb = token::make_lowbox(lock, ac.sid)?;
            let init_lb = token::make_lowbox(init, ac.sid)?;
            unsafe { let _ = CloseHandle(lock); let _ = CloseHandle(init); }
            let primary = token::to_primary(lock_lb)?;
            let initial = token::to_impersonation(init_lb)?;
            unsafe { let _ = CloseHandle(lock_lb); let _ = CloseHandle(init_lb); }
            Ok((primary, initial))
        })();
        let (primary, initial) = match toks {
            Ok(t) => t,
            Err(e) => {
                println!("| {} | - | ERR | - | - | `{}` |",
                    var.name, format!("{e:#}").replace('|', "\\|"));
                continue;
            }
        };

        for p in &payloads {
            let _ = std::fs::remove_file(&outfile);
            // Inheritable file handle for stdout/stderr so the
            // payload can be spawned directly without a shell.
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: true.into(),
            };
            let hout = unsafe {
                CreateFileW(
                    pcwstr(&wstr(outfile.to_str().unwrap())),
                    FILE_GENERIC_WRITE.0, FILE_SHARE_READ, Some(&sa),
                    CREATE_ALWAYS, Default::default(), None,
                )
            };
            let hout = match hout {
                Ok(h) => h,
                Err(e) => {
                    println!("| {} | {} | ERR | - | - | `outfile: {e}` |",
                        var.name, p.tag);
                    continue;
                }
            };
            let mut clw = wstr(&p.cmdline);
            let cwd = wstr(std::env::temp_dir().to_str().unwrap());
            let mut si: STARTUPINFOW = unsafe { zeroed() };
            si.cb = size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = hout;
            si.hStdError = hout;
            let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
            let (code, gle) = unsafe {
                match CreateProcessAsUserW(
                    primary, None, PWSTR(clw.as_mut_ptr()), None, None, true,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    None, PCWSTR(cwd.as_ptr()), &si, &mut pi,
                ) {
                    Ok(()) => {
                        let _ = SetThreadToken(Some(&pi.hThread), initial);
                        ResumeThread(pi.hThread);
                        let r = WaitForSingleObject(pi.hProcess, 15_000);
                        let mut c = 0u32;
                        if r == WAIT_TIMEOUT {
                            let _ = TerminateProcess(pi.hProcess, 0xDEAD);
                            c = 0xDEAD;
                        } else {
                            let _ = GetExitCodeProcess(pi.hProcess, &mut c);
                        }
                        let _ = CloseHandle(pi.hThread);
                        let _ = CloseHandle(pi.hProcess);
                        (c, 0u32)
                    }
                    Err(_) => (0xFFFF_FFFF, GetLastError().0),
                }
            };
            unsafe { let _ = CloseHandle(hout); }
            let out = std::fs::read_to_string(&outfile).unwrap_or_default();
            let ran = out.to_lowercase().contains(p.ok);
            let head = out.lines().next().unwrap_or("")
                .chars().take(48).collect::<String>().replace('|', "\\|");
            println!("| {} | {} | {code:#x} | {gle} | {} | `{head}` |",
                var.name, p.tag, if ran { "YES" } else { "no" });
        }
        unsafe { let _ = CloseHandle(primary); let _ = CloseHandle(initial); }
    }
    let _ = std::fs::remove_file(&outfile);
}
