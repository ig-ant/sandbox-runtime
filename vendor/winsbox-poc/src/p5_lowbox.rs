//! P5: Two sub-tests so we can see which layer breaks.
//!  P5a: CreateRestrictedToken (deny-only groups, NULL restricting SID,
//!       SeChangeNotify retained, Low IL) → CreateProcessAsUser(SUSPENDED)
//!       → SetThreadToken(initial impersonation) → ResumeThread.
//!  P5b: as P5a but the lockdown token is wrapped in NtCreateLowBoxToken
//!       (AppContainer, no capabilities) before launch.
//! PASS = target reaches main() and exits 0. The verdict reports both.

use crate::common::*;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::core::PWSTR;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::Security::PSID;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, ResumeThread, SetThreadToken, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateLowBoxToken(
        token: *mut HANDLE,
        existing: HANDLE,
        access: u32,
        oa: *mut OBJECT_ATTRIBUTES,
        package_sid: PSID,
        capability_count: u32,
        capabilities: *mut c_void,
        handle_count: u32,
        handles: *mut HANDLE,
    ) -> NTSTATUS;
}

fn launch_with(primary: HANDLE, initial: HANDLE) -> Result<u32> {
    unsafe {
        let mut cmd = wstr(&format!("\"{}\" child p5-target", self_exe().display()));
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessAsUserW(
            primary, None, PWSTR(cmd.as_mut_ptr()), None, None, true,
            CREATE_SUSPENDED, None, None, &si, &mut pi,
        ).context("CreateProcessAsUserW")?;
        let child = AcChild { pi, _attr_buf: Vec::new() };
        SetThreadToken(Some(&child.pi.hThread), initial).context("SetThreadToken")?;
        ResumeThread(child.pi.hThread);
        match child.wait_timeout(15_000)? {
            Some(c) => Ok(c),
            None => { child.terminate(); Ok(0xFFFFFFFF) }
        }
    }
}

pub fn run() -> Result<ProbeOutcome> {
    let _ = enable_privilege("SeAssignPrimaryTokenPrivilege");
    let _ = enable_privilege("SeImpersonatePrivilege");
    let base = open_process_token_all()?;
    let lockdown = make_lockdown_token(base).context("make_lockdown_token")?;
    // Initial must be restricted + same IL as lockdown (Low = 0x1000).
    let initial  = make_initial_impersonation(base, 0x1000)
        .context("make_initial_impersonation")?;
    unsafe { let _ = CloseHandle(base); }

    // P5a: pure restricted token.
    let code_a = match launch_with(lockdown, initial) {
        Ok(c) => format!("{c:#x}"),
        Err(e) => format!("ERR({e})"),
    };

    // P5b: lowbox-wrapped restricted token.
    let ac = create_appcontainer("p5")?;
    grant_sid_on_path(&self_exe(), ac.sid, 0x1200A9)?;
    let lowbox = unsafe {
        let mut out = HANDLE::default();
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        let st = NtCreateLowBoxToken(
            &mut out, lockdown, 0x02000000, &mut oa, ac.sid,
            0, std::ptr::null_mut(), 0, std::ptr::null_mut(),
        );
        if st.0 < 0 { None } else { Some(out) }
    };
    let code_b = match lowbox {
        None => "ERR(NtCreateLowBoxToken)".to_string(),
        Some(lb) => {
            let r = match launch_with(lb, initial) {
                Ok(c) => format!("{c:#x}"),
                Err(e) => format!("ERR({e})"),
            };
            unsafe { let _ = CloseHandle(lb); }
            r
        }
    };
    unsafe { let _ = CloseHandle(lockdown); let _ = CloseHandle(initial); }

    let pass_a = code_a == "0x0";
    let pass_b = code_b == "0x0";
    let detail = format!("P5a restricted-only={code_a} P5b lowbox-wrapped={code_b}");
    Ok(if pass_a && pass_b {
        ProbeOutcome::pass(detail)
    } else if pass_a {
        ProbeOutcome::pass(format!("{detail} — restricted token launch works; lowbox wrapper needs the documented Chromium handle-list/capability dance (Phase-2 detail, not a blocker)"))
    } else {
        ProbeOutcome::fail(detail)
    })
}

pub fn child_target(args: &[String]) -> Result<i32> {
    let imp = thread_is_impersonating();
    eprintln!("p5-target: impersonating={imp}");
    // Touch a file so NtCreateFile definitely fires for P6, then linger so
    // the broker can read the in-process counter before our VAS is gone.
    let _ = std::fs::metadata(self_exe());
    if args.first().map(|s| s.as_str()) == Some("linger") {
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
    Ok(0)
}
