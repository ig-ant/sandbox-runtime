//! Task 2 — vanilla AC bash probe.
//!
//! Smallest-possible AC sandbox that we can wrap around bash:
//!   1. `CreateAppContainerProfile` for a stable AC profile + SID.
//!   2. `OpenProcessToken(self)` → duplicate to primary.
//!   3. `NtCreateLowBoxToken` with EMPTY restricting-SID list, EMPTY
//!      capabilities, EMPTY saved-handle list. No `CreateRestrictedToken`,
//!      no integrity-level lowering, no USER_LIMITED, no DACL fiddling.
//!   4. `CreateProcessAsUserW` with `STARTF_USESTDHANDLES` + redirected
//!      stdout/stderr pipes. CWD = `%TEMP%`. ENV = inherited.
//!   5. Wait for exit; print exit code + stdout + stderr.
//!
//! No cdylib, no IPC, no policy stamping, no hooks, no manual map.
//! This isolates "does Windows allow x64 bash to bootstrap in a bare
//! AC on this host" from everything our broker adds.
//!
//! Run:
//!   ./probe_vanilla_ac.exe                # uses Git's bash by default
//!   ./probe_vanilla_ac.exe <path-to-exe>  # overrides bash path
//!
//! Built as an example so it picks up `sbox-exec`'s `appcontainer` /
//! `token` modules without duplicating their setup.

#[cfg(not(windows))]
fn main() {
    eprintln!("probe_vanilla_ac: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::path::PathBuf;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
        SECURITY_ATTRIBUTES,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::Win32::Foundation::{HANDLE_FLAGS, SetHandleInformation};
    const HANDLE_FLAG_INHERIT: HANDLE_FLAGS = HANDLE_FLAGS(1);

    use sbox_exec::appcontainer::AppContainer;
    use sbox_exec::token::make_lowbox;

    macro_rules! say { ($($a:tt)*) => { eprintln!("[probe-vanilla-ac] {}", format!($($a)*)) } }

    let bash = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\Git\usr\bin\bash.exe"));
    if !bash.exists() {
        say!("FAIL: bash not found at {} (set argv[1] to override)", bash.display());
        std::process::exit(1);
    }
    say!("bash = {}", bash.display());

    // 1. AC profile.
    let ac = AppContainer::create("vanac")
        .unwrap_or_else(|e| { say!("FAIL: CreateAppContainerProfile: {e:#}"); std::process::exit(1); });
    say!("AC sid={} folder={}", ac.sid_string, ac.folder.display());

    // 2. Self token → primary duplicate.
    let primary = unsafe {
        let mut tok = HANDLE::default();
        if let Err(e) = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut tok) {
            say!("FAIL: OpenProcessToken: {e:#}");
            std::process::exit(1);
        }
        let mut dup = HANDLE::default();
        if let Err(e) = DuplicateTokenEx(
            tok, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenPrimary, &mut dup,
        ) {
            say!("FAIL: DuplicateTokenEx(primary): {e:#}");
            std::process::exit(1);
        }
        let _ = CloseHandle(tok);
        dup
    };

    // 3. Lowbox-wrap with empty caps + empty saved-handles + empty
    //    restricting list. `make_lowbox` is exactly this.
    let lowbox = match make_lowbox(primary, ac.sid, &[]) {
        Ok(h) => h,
        Err(e) => { say!("FAIL: make_lowbox: {e:#}"); std::process::exit(1); }
    };
    say!("lowbox token built (NtCreateLowBoxToken, no caps, no restricting SIDs)");

    // 4. CreateProcessAsUserW with stdout/stderr pipes.
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: windows::Win32::Foundation::BOOL(1),
    };
    let mut stdout_r = HANDLE::default();
    let mut stdout_w = HANDLE::default();
    let mut stderr_r = HANDLE::default();
    let mut stderr_w = HANDLE::default();
    unsafe {
        if let Err(e) = CreatePipe(&mut stdout_r, &mut stdout_w, Some(&inheritable), 0) {
            say!("FAIL: CreatePipe(stdout): {e:#}");
            std::process::exit(1);
        }
        if let Err(e) = CreatePipe(&mut stderr_r, &mut stderr_w, Some(&inheritable), 0) {
            say!("FAIL: CreatePipe(stderr): {e:#}");
            std::process::exit(1);
        }
        // Don't let the read ends be inherited.
        let _ = SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(stderr_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
    }

    // Build the command line: bash -c "echo hello".
    let cmdline = format!("\"{}\" -c \"echo hello\"", bash.display());
    let mut cmd_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
    let cwd_w: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = HANDLE(std::ptr::null_mut());
    si.hStdOutput = stdout_w;
    si.hStdError = stderr_w;

    use windows::Win32::System::Threading::{CREATE_SUSPENDED, ResumeThread};
    use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
    let pause_for_debugger = std::env::var("WINSBOX_PAUSE_FOR_DEBUGGER").as_deref() == Ok("1");
    let create_flags = if pause_for_debugger {
        CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
    } else {
        CREATE_UNICODE_ENVIRONMENT
    };
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            lowbox, None, PWSTR(cmd_w.as_mut_ptr()),
            None, None, true,
            create_flags,
            None,
            windows::core::PCWSTR(cwd_w.as_ptr()),
            &si, &mut pi,
        )
    };
    if let Err(e) = ok {
        let last = unsafe { GetLastError() };
        say!("FAIL: CreateProcessAsUserW: {e:#} (GetLastError={:#x})", last.0);
        std::process::exit(1);
    }
    say!("target pid={}", pi.dwProcessId);
    if pause_for_debugger {
        say!("WINSBOX_PAUSE_FOR_DEBUGGER=1: target SUSPENDED at PID {}; attach with `cdb -pv -pn bash.exe` or `cdb -p {0}`", pi.dwProcessId);
        say!("polling for debugger attach…");
        loop {
            let mut is_debugged = windows::Win32::Foundation::BOOL(0);
            let _ = unsafe { CheckRemoteDebuggerPresent(pi.hProcess, &mut is_debugged) };
            if is_debugged.as_bool() {
                say!("debugger attached; resuming");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        unsafe { ResumeThread(pi.hThread); }
    }

    // Close our copy of the write ends so EOF propagates when child exits.
    unsafe {
        let _ = CloseHandle(stdout_w);
        let _ = CloseHandle(stderr_w);
    }

    // Drain stdout and stderr concurrently while waiting for exit.
    use std::os::windows::io::FromRawHandle;
    use std::io::Read;
    // Wrap the raw HANDLE pointer so the closures are Send.
    struct SendHandle(usize);
    unsafe impl Send for SendHandle {}
    let stdout_r_send = SendHandle(stdout_r.0 as usize);
    let stderr_r_send = SendHandle(stderr_r.0 as usize);
    let t_out = std::thread::spawn(move || -> Vec<u8> {
        let h = stdout_r_send.0 as *mut c_void;
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        buf
    });
    let t_err = std::thread::spawn(move || -> Vec<u8> {
        let h = stderr_r_send.0 as *mut c_void;
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        buf
    });

    let wait = unsafe { WaitForSingleObject(pi.hProcess, 30_000) };
    if wait != WAIT_OBJECT_0 {
        say!("WARN: WaitForSingleObject != WAIT_OBJECT_0 ({:#x})", wait.0);
    }
    let mut exit_code = 0u32;
    let _ = unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };

    let stdout_bytes = t_out.join().unwrap_or_default();
    let stderr_bytes = t_err.join().unwrap_or_default();
    let stdout_s = String::from_utf8_lossy(&stdout_bytes);
    let stderr_s = String::from_utf8_lossy(&stderr_bytes);

    say!("exit code = {:#x} ({})", exit_code, exit_code as i32);
    say!("--- stdout ({} bytes) ---", stdout_bytes.len());
    eprintln!("{}", stdout_s);
    say!("--- stderr ({} bytes) ---", stderr_bytes.len());
    eprintln!("{}", stderr_s);
    say!("--- end ---");

    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(lowbox);
        let _ = CloseHandle(primary);
    }

    // Diagnostic: classify outcome.
    if exit_code == 0 && stdout_s.contains("hello") {
        say!("OUTCOME: bare-AC bash WORKS — our broker is adding the extra that breaks it");
        std::process::exit(0);
    } else if exit_code == 0xC0000005 {
        say!("OUTCOME: bare-AC bash AVs (0xC0000005) — OS-level bug (Cygwin x64 in AC on this ARM64 host)");
        std::process::exit(2);
    } else {
        say!("OUTCOME: bare-AC bash failed non-AV ({:#x}) — see stderr above", exit_code);
        std::process::exit(2);
    }
}
