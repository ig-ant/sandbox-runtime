//! Top-level run-mode entry point: build the restricted token, create
//! the job, build the env (including `HTTP_PROXY`/`HTTPS_PROXY`/
//! `ALL_PROXY`), spawn the target suspended, assign to job, start the
//! proxy, resume, wait for exit.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use crate::job::Job;
use crate::policy::Policy;
use crate::token::{
    self, open_self_token, to_primary, LockdownSpec, IL_MEDIUM, USER_LIMITED_KEEP,
};
use crate::util::{pcwstr, wstr};
use crate::{proxy, sid, wfp};

fn build_env(pol: &Policy, proxy_port: u16) -> Vec<u16> {
    let mut env: HashMap<String, String> =
        std::env::vars().filter(|(k, _)| {
            !matches!(
                k.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        }).collect();
    let proxy_url = format!("socks5h://127.0.0.1:{proxy_port}");
    env.insert("HTTP_PROXY".into(), proxy_url.clone());
    env.insert("HTTPS_PROXY".into(), proxy_url.clone());
    env.insert("ALL_PROXY".into(), proxy_url.clone());
    env.insert("NO_PROXY".into(), String::new());
    // Lowercase variants for tools that look at them.
    env.insert("http_proxy".into(), proxy_url.clone());
    env.insert("https_proxy".into(), proxy_url.clone());
    env.insert("all_proxy".into(), proxy_url.clone());
    env.insert("no_proxy".into(), String::new());

    for (k, v) in &pol.env_extra {
        env.insert(k.clone(), v.clone());
    }

    // Serialize as UTF-16 KEY=VALUE\0KEY=VALUE\0\0
    let mut out: Vec<u16> = Vec::new();
    for (k, v) in env {
        let mut s = String::new();
        s.push_str(&k);
        s.push('=');
        s.push_str(&v);
        for u in s.encode_utf16() {
            out.push(u);
        }
        out.push(0);
    }
    out.push(0);
    out
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty()
        && !a.contains(' ')
        && !a.contains('\t')
        && !a.contains('"')
        && !a.contains('\\')
    {
        return a.to_string();
    }
    // CommandLineToArgvW reversal — minimal escaping.
    let mut out = String::with_capacity(a.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in a.chars() {
        if c == '\\' {
            backslashes += 1;
            out.push(c);
            continue;
        }
        if c == '"' {
            // Double the run of backslashes preceding the quote, then escape the quote.
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push('\\');
            out.push('"');
        } else {
            out.push(c);
        }
        backslashes = 0;
    }
    // Trailing backslashes get doubled before closing quote.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

fn build_cmdline(exe: &std::path::Path, args: &[String]) -> String {
    let mut s = quote_arg(&exe.display().to_string());
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg(a));
    }
    s
}

/// Run a policy and return the child's exit code.
pub fn run(pol: &Policy) -> Result<u32> {
    let proxy_port = wfp::is_installed()
        .context("wfp::is_installed")?
        .ok_or_else(|| anyhow!(
            "WFP filters not installed; run `sbox-exec install` as administrator"
        ))?;

    // Token.
    let self_tok = open_self_token()?;
    let spec = LockdownSpec {
        keep_enabled: USER_LIMITED_KEEP,
        extra_restricting: vec![sid::sandbox_sid_string()?.to_string()],
    };
    let restricted = token::make_lockdown_with(self_tok, IL_MEDIUM, &spec)
        .context("make_lockdown_with")?;
    // make_lockdown_with already calls set_il and set_default_dacl.
    let primary = to_primary(restricted).context("to_primary")?;

    // Job.
    let job = Job::new().context("Job::new")?;

    // Env block.
    let mut env = build_env(pol, proxy_port);

    // Command line.
    let cmdline = build_cmdline(&pol.target_exe, &pol.target_args);
    let mut cmdline_w = wstr(&cmdline);

    // Working dir.
    let cwd_w: Option<Vec<u16>> = pol.cwd.as_ref()
        .map(|p| wstr(&p.display().to_string()));

    // Application name = target_exe.
    let app_w = wstr(&pol.target_exe.display().to_string());

    // Startup info.
    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let cwd_pcwstr = cwd_w.as_ref().map(|v| pcwstr(v))
        .unwrap_or(windows::core::PCWSTR::null());

    unsafe {
        CreateProcessAsUserW(
            primary,
            pcwstr(&app_w),
            PWSTR(cmdline_w.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            Some(env.as_mut_ptr() as *const c_void),
            cwd_pcwstr,
            &si,
            &mut pi,
        )
        .with_context(|| format!("CreateProcessAsUserW({})", pol.target_exe.display()))?;
    }

    // Assign to job.
    job.assign(pi.hProcess).context("AssignProcessToJobObject")?;

    // Start proxy.
    let _proxy = proxy::start(proxy_port, Box::new(proxy::DirectDialer))
        .context("proxy::start")?;

    // Resume.
    unsafe { ResumeThread(pi.hThread) };

    // Wait.
    let rc = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    if rc != WAIT_OBJECT_0 {
        eprintln!("[sbox-exec] WaitForSingleObject returned 0x{:x}", rc.0);
    }
    let mut code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut code).context("GetExitCodeProcess")?;
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(primary);
        let _ = CloseHandle(restricted);
        let _ = CloseHandle(self_tok);
    }
    Ok(code)
}
