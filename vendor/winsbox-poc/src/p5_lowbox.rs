//! P5: CreateRestrictedToken (deny-only groups, NULL restricting SID,
//! Untrusted IL) → NtCreateLowBoxToken → CreateProcessAsUser(SUSPENDED)
//! → SetThreadToken(initial impersonation) → ResumeThread. Does the
//! target reach its entry point?
//!
//! Target is `winsbox-poc child p5-target`: it just prints whether it is
//! impersonating and exits 0. We don't drop the impersonation here (P7
//! covers that); P5 only proves the loader survives the lockdown primary.

use crate::common::*;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::Security::PSID;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, ResumeThread, SetThreadToken, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;

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

pub fn run() -> Result<ProbeOutcome> {
    let ac = create_appcontainer("p5")?;
    grant_sid_on_path(&self_exe(), ac.sid, 0x1200A9)?;
    // The exe's directory needs ALL APPLICATION PACKAGES read on most
    // installs already; granting our specific SID is belt-and-braces.

    let base = open_process_token_all()?;
    let lockdown = make_lockdown_token(base).context("make_lockdown_token")?;
    let initial  = make_initial_impersonation(base).context("make_initial_impersonation")?;
    unsafe { let _ = CloseHandle(base); }

    let lowbox = unsafe {
        let mut out = HANDLE::default();
        let mut oa: OBJECT_ATTRIBUTES = zeroed();
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        let st = NtCreateLowBoxToken(
            &mut out, lockdown, 0x02000000 /* MAXIMUM_ALLOWED */,
            &mut oa, ac.sid, 0, std::ptr::null_mut(), 0, std::ptr::null_mut(),
        );
        if st.0 < 0 {
            return Ok(ProbeOutcome::fail(format!("NtCreateLowBoxToken: {:#x}", st.0)));
        }
        out
    };

    let exe = self_exe();
    let mut cmd = wstr(&format!("\"{}\" child p5-target", exe.display()));
    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let ok = unsafe {
        CreateProcessAsUserW(
            lowbox,
            None,
            PWSTR(cmd.as_mut_ptr()),
            None, None, true,
            CREATE_SUSPENDED,
            None, None, &si, &mut pi,
        )
    };
    if let Err(e) = ok {
        unsafe { let _ = CloseHandle(lockdown); let _ = CloseHandle(initial); let _ = CloseHandle(lowbox); }
        return Ok(ProbeOutcome::fail(format!("CreateProcessAsUserW(lowbox): {e}")));
    }

    unsafe {
        if let Err(e) = SetThreadToken(Some(&pi.hThread), initial) {
            let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            return Ok(ProbeOutcome::fail(format!("SetThreadToken(initial): {e}")));
        }
        ResumeThread(pi.hThread);
    }

    let child = AcChild { pi, _attr_buf: Vec::new() };
    let code = match child.wait_timeout(15_000)? {
        Some(c) => c,
        None => { child.terminate(); return Ok(ProbeOutcome::fail("target hung (loader stuck?)")); }
    };
    unsafe { let _ = CloseHandle(lockdown); let _ = CloseHandle(initial); let _ = CloseHandle(lowbox); }

    Ok(match code {
        0 => ProbeOutcome::pass("loader survived lockdown+lowbox primary with thread impersonation"),
        c => ProbeOutcome::fail(format!("target exit {c} ({c:#x}) — loader likely failed")),
    })
}

pub fn child_target(_args: &[String]) -> Result<i32> {
    let imp = thread_is_impersonating();
    eprintln!("p5-target: impersonating={imp}");
    Ok(0)
}
