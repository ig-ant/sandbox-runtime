//! P13: how does Git-for-Windows MSYS2 bash fare in a vanilla
//! network-only AppContainer (no broker hooks, no FS mediation,
//! no CPW interception)?
//!
//! Each row builds a fresh AC, spawns `bash -c "<probe>"` directly
//! under the AC's primary token (lowbox-wrapped lockdown SID = no
//! capabilities = no `internetClient`), captures stdout+stderr to
//! a parent-owned file, prints exit code + first stderr line.
//!
//! The probes ladder from "does the loader survive AC at all" up
//! through fork-emulation pipelines — exactly the cases the broker
//! currently has to special-case (lpReserved2 forwarding, named-pipe
//! installation-key matching, BNO redirection).

#[cfg(not(windows))]
fn main() { eprintln!("windows only"); std::process::exit(2); }

#[cfg(windows)] #[path = "../util.rs"] mod util;
#[cfg(windows)] #[path = "../appcontainer.rs"] mod appcontainer;
#[cfg(windows)] #[path = "../token.rs"] mod token;

#[cfg(windows)]
const BASH: &str = r"C:\Program Files\Git\usr\bin\bash.exe";

#[cfg(windows)]
struct Probe {
    name: &'static str,
    exe: &'static str,
    args: &'static str,
    /// false → AC only (no restricted/lockdown layer). Exposes whether
    /// the failure is the AC kernel boundary or our restricting list.
    lockdown: bool,
}

#[cfg(windows)]
const PROBES: &[Probe] = &[
    // — baselines: native PE, no MSYS layer —
    Probe { name: "cmd /c echo (AC+lockdown)",        exe: r"C:\Windows\System32\cmd.exe", args: "/c echo hello", lockdown: true },
    Probe { name: "cmd /c echo (AC only)",            exe: r"C:\Windows\System32\cmd.exe", args: "/c echo hello", lockdown: false },
    Probe { name: "cmd /c dir C:\\ (AC only)",        exe: r"C:\Windows\System32\cmd.exe", args: "/c dir C:\\", lockdown: false },
    Probe { name: "powershell echo (AC only)",        exe: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", args: "-NoProfile -Command Write-Output hi", lockdown: false },
    // — Git-for-Windows MSYS2 bash, varying args —
    Probe { name: "bash --version (AC+lockdown)",     exe: BASH, args: "--version", lockdown: true },
    Probe { name: "bash --version (AC only)",         exe: BASH, args: "--version", lockdown: false },
    Probe { name: "bash -c 'echo' (AC only)",         exe: BASH, args: "-c \"echo hello\"", lockdown: false },
    Probe { name: "bash -c 'for' (AC only)",          exe: BASH, args: "-c \"for i in 1 2 3; do echo $i; done\"", lockdown: false },
    Probe { name: "bash -c 'ls' (AC only)",           exe: BASH, args: "-c \"ls /\"", lockdown: false },
    Probe { name: "bash -c 'ls|head' (AC only)",      exe: BASH, args: "-c \"ls /usr/bin | head -3\"", lockdown: false },
    Probe { name: "bash -c 'true;true' (AC only)",    exe: BASH, args: "-c \"true; true; true; echo done\"", lockdown: false },
    Probe { name: "bash -c 'git --version' (AC only)", exe: BASH, args: "-c \"git --version\"", lockdown: false },
    // — invoke Git's bin/bash.exe (the launcher wrapper) —
    Probe { name: "bin/bash --version (AC only)",     exe: r"C:\Program Files\Git\bin\bash.exe", args: "--version", lockdown: false },
    // — native PE git.exe (separate from MSYS bash) —
    Probe { name: "Git cmd/git.exe --version",        exe: r"C:\Program Files\Git\cmd\git.exe", args: "--version", lockdown: false },
    // — other MSYS-linked tools, to confirm the failure is generic to msys-2.0.dll —
    Probe { name: "MSYS ls.exe --version",            exe: r"C:\Program Files\Git\usr\bin\ls.exe", args: "--version", lockdown: false },
    Probe { name: "MSYS uname.exe",                   exe: r"C:\Program Files\Git\usr\bin\uname.exe", args: "-a", lockdown: false },
    Probe { name: "MSYS sh.exe -c echo",              exe: r"C:\Program Files\Git\usr\bin\sh.exe", args: "-c \"echo hi\"", lockdown: false },
];

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") { unreachable!(); }
    parent();
}

#[cfg(windows)]
fn parent() {
    use std::io::Read;
    use std::mem::{size_of, zeroed};
    use util::wstr;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::Security::{PSID, SID_AND_ATTRIBUTES, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
        FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, SetThreadToken,
        WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW, STARTF_USESTDHANDLES,
    };

    if !std::path::Path::new(BASH).exists() {
        eprintln!("bash not found at {BASH}"); std::process::exit(1);
    }
    println!("# P13 — Git-for-Windows bash inside a vanilla AppContainer (no hooks, no caps)\n");
    println!("bash: `{BASH}`\n");
    println!("| probe | exit | stdout (1st 80c) | stderr (1st 80c) |");
    println!("|---|---|---|---|");

    for (i, p) in PROBES.iter().enumerate() {
        let outfile = std::env::temp_dir().join(format!("p13-{}-{}.txt", std::process::id(), i));
        let _ = std::fs::remove_file(&outfile);
        let r: anyhow::Result<(u32, String)> = (|| unsafe {
            // — fresh AC per probe so prior child object handles can't
            //   poison the namespace —
            let ac = appcontainer::AppContainer::create(&format!("p13_{i}"))?;
            let no_caps: Vec<SID_AND_ATTRIBUTES> = vec![];

            // Two paths:
            //   lockdown=true  → CreateRestrictedToken + lowbox (= production)
            //   lockdown=false → just lowbox over the parent token (vanilla AC)
            let base = token::open_self_token()?;
            let il = token::IL_UNTRUSTED;
            let (lock, init) = if p.lockdown {
                (token::make_lockdown_with(base, il, token::USER_LIMITED)?,
                 token::make_initial(base, il)?)
            } else {
                let mut a = HANDLE::default();
                let mut b = HANDLE::default();
                DuplicateTokenEx(base, TOKEN_ALL_ACCESS, None,
                    SecurityImpersonation, TokenPrimary, &mut a)?;
                DuplicateTokenEx(base, TOKEN_ALL_ACCESS, None,
                    SecurityImpersonation, TokenPrimary, &mut b)?;
                (a, b)
            };
            let _ = CloseHandle(base);
            let lp = make_lowbox(lock, ac.sid, &no_caps)?;
            let li = make_lowbox(init, ac.sid, &no_caps)?;
            let _ = CloseHandle(lock); let _ = CloseHandle(init);
            let primary = to_primary(lp)?;
            let initial = to_impersonation(li)?;

            // Inheritable file for stdout/stderr.
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

            let cmdline = format!(r#""{}" {}"#, p.exe, p.args);
            let mut clw = wstr(&cmdline);
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
            let r = WaitForSingleObject(pi.hProcess, 10_000);
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
            Ok((code, mut out)) => {
                // Combined stdout+stderr (we merged handles). Show first
                // line + truncated, escaping pipes/newlines for the table.
                let combined = out.replace('\r', "");
                let first = combined.lines().next().unwrap_or("").to_string();
                let trim = |s: &str, n: usize| {
                    let s = s.replace('|', r"\|");
                    if s.chars().count() > n {
                        s.chars().take(n).collect::<String>() + "…"
                    } else { s }
                };
                out.clear();
                println!("| {} | {:#x} | {} |  |",
                    p.name, code, trim(&first, 80));
            }
            Err(e) => println!("| {} | ERR | `{}` |  |",
                p.name,
                format!("{e}").chars().take(60).collect::<String>().replace('|', r"\|")),
        }
        let _ = std::fs::remove_file(&outfile);
    }
}

// — same lowbox helper as p11/p12 —
#[cfg(windows)]
fn make_lowbox(
    tok: windows::Win32::Foundation::HANDLE,
    sid: windows::Win32::Security::PSID,
    caps: &[windows::Win32::Security::SID_AND_ATTRIBUTES],
) -> anyhow::Result<windows::Win32::Foundation::HANDLE> {
    use std::mem::{size_of, zeroed};
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{HANDLE, NTSTATUS};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateLowBoxToken(
            out: *mut HANDLE, existing: HANDLE, access: u32,
            oa: *mut OBJECT_ATTRIBUTES, sid: windows::Win32::Security::PSID,
            cap_count: u32, caps: *const windows::Win32::Security::SID_AND_ATTRIBUTES,
            handle_count: u32, handles: *mut HANDLE,
        ) -> NTSTATUS;
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

#[cfg(windows)]
fn to_primary(t: windows::Win32::Foundation::HANDLE)
    -> anyhow::Result<windows::Win32::Foundation::HANDLE>
{
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
    };
    unsafe {
        let mut p = HANDLE::default();
        DuplicateTokenEx(t, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenPrimary, &mut p)?;
        let _ = CloseHandle(t);
        Ok(p)
    }
}
#[cfg(windows)]
fn to_impersonation(t: windows::Win32::Foundation::HANDLE)
    -> anyhow::Result<windows::Win32::Foundation::HANDLE>
{
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_ALL_ACCESS,
    };
    unsafe {
        let mut p = HANDLE::default();
        DuplicateTokenEx(t, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenImpersonation, &mut p)?;
        let _ = CloseHandle(t);
        Ok(p)
    }
}
