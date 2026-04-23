use crate::policy::{Mode, Policy};
use anyhow::{Context, Result};
use std::mem::{size_of, zeroed};
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOW,
};

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a Win32 environment block (`KEY=VAL\0...\0\0`) from the parent's
/// environment overlaid with `extra`.
fn build_env_block(extra: &[(String, String)]) -> Vec<u16> {
    let mut map: std::collections::BTreeMap<String, String> =
        std::env::vars().collect();
    for (k, v) in extra {
        map.insert(k.clone(), v.clone());
    }
    let mut out = Vec::<u16>::new();
    for (k, v) in map {
        out.extend(k.encode_utf16());
        out.push(b'=' as u16);
        out.extend(v.encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

pub fn run(pol: &Policy) -> Result<u32> {
    match pol.mode {
        Mode::Stub => run_stub(pol),
        Mode::AppContainer | Mode::Broker => {
            anyhow::bail!("mode {:?} not implemented in this build (Phase 0.5 stub)", pol.mode)
        }
    }
}

fn run_stub(pol: &Policy) -> Result<u32> {
    unsafe {
        let mut cmd = wstr(&pol.command_line);
        let cwd_w = pol.cwd.as_deref().map(wstr);
        let cwd_ptr = cwd_w
            .as_ref()
            .map(|w| windows::core::PCWSTR(w.as_ptr()))
            .unwrap_or(windows::core::PCWSTR::null());
        let mut env = build_env_block(&pol.env);
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(
            None,
            PWSTR(cmd.as_mut_ptr()),
            None,
            None,
            true,
            windows::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT,
            Some(env.as_mut_ptr() as *mut std::ffi::c_void),
            cwd_ptr,
            &si,
            &mut pi,
        )
        .with_context(|| format!("CreateProcessW({})", pol.command_line))?;
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut code = 0u32;
        GetExitCodeProcess(pi.hProcess, &mut code).context("GetExitCodeProcess")?;
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        Ok(code)
    }
}
