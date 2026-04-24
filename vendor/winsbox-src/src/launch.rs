use crate::policy::{Mode, Policy};
use crate::util::{pcwstr, wstr};
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::io::{BufRead, BufReader};
use std::mem::{size_of, zeroed};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::SECURITY_CAPABILITIES;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::acl::{AclJournal, MODIFY, READ_EXECUTE};
use crate::appcontainer::AppContainer;
use crate::desktop::AltDesktop;
use crate::job::Job;
use crate::netbridge;

pub fn run(pol: &Policy) -> Result<u32> {
    match pol.mode {
        Mode::Stub => run_stub(pol),
        Mode::AppContainer => run_appcontainer(pol),
        Mode::Broker => bail!("mode broker not implemented in this build"),
    }
}

fn build_env_block(extra: &[(String, String)]) -> Vec<u16> {
    let mut map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    for (k, v) in extra { map.insert(k.clone(), v.clone()); }
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

fn run_stub(pol: &Policy) -> Result<u32> {
    unsafe {
        let mut cmd = wstr(&pol.command_line);
        let cwd_w = pol.cwd.as_deref().map(wstr);
        let cwd = cwd_w.as_ref().map(|w| pcwstr(w)).unwrap_or(PCWSTR::null());
        let mut env = build_env_block(&pol.env);
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(
            None, PWSTR(cmd.as_mut_ptr()), None, None, true,
            CREATE_UNICODE_ENVIRONMENT, Some(env.as_mut_ptr() as *mut c_void),
            cwd, &si, &mut pi,
        ).with_context(|| format!("CreateProcessW({})", pol.command_line))?;
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut code = 0u32;
        GetExitCodeProcess(pi.hProcess, &mut code)?;
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        Ok(code)
    }
}

fn run_appcontainer(pol: &Policy) -> Result<u32> {
    let ac = AppContainer::create("ac")?;
    let job = Job::new()?;
    let desktop = if pol.use_alternate_desktop { Some(AltDesktop::new()?) } else { None };
    let mut acls = AclJournal::default();

    // The AC needs to read+execute this binary (for the inside relay)
    // and the directories of whatever the user's command will load.
    let self_exe = std::env::current_exe()?;
    acls.grant(self_exe.to_str().unwrap(), ac.sid, &ac.sid_string, READ_EXECUTE)?;
    if let Some(dir) = self_exe.parent() {
        acls.grant(dir.to_str().unwrap(), ac.sid, &ac.sid_string, READ_EXECUTE).ok();
    }

    // Filesystem policy → ACEs.
    for p in &pol.allow_read {
        if std::path::Path::new(p).exists() {
            acls.grant(p, ac.sid, &ac.sid_string, READ_EXECUTE).ok();
        }
    }
    for p in &pol.allow_write {
        std::fs::create_dir_all(p).ok();
        acls.grant(p, ac.sid, &ac.sid_string, MODIFY).ok();
    }
    for p in &pol.deny_read {
        if std::path::Path::new(p).exists() {
            acls.deny(p, ac.sid, &ac.sid_string, READ_EXECUTE).ok();
        }
    }
    for p in &pol.deny_write {
        if std::path::Path::new(p).exists() {
            acls.deny(p, ac.sid, &ac.sid_string, MODIFY).ok();
        }
    }

    // Network bridge: only if the policy carries proxy ports.
    let mut extra_env = pol.env.clone();
    let mut relay_pi: Option<PROCESS_INFORMATION> = None;
    if let (Some(hp), sp) = (pol.network.http_proxy_port, pol.network.socks_proxy_port) {
        let (sock_dir, needs_acl) = netbridge::socket_dir(&ac.folder);
        if needs_acl {
            acls.grant(sock_dir.to_str().unwrap(), ac.sid, &ac.sid_string, MODIFY).ok();
        }
        let http_sock = sock_dir.join("h.sock");
        let socks_sock = sock_dir.join("s.sock");
        netbridge::spawn_outside_relay(http_sock.clone(), hp)?;
        if let Some(spp) = sp {
            netbridge::spawn_outside_relay(socks_sock.clone(), spp)?;
        }
        // Spawn the inside relay inside the AC, in this Job, and read
        // back the loopback ports it bound.
        let (pi, mut child_stdout) = spawn_in_ac_capture(
            &ac, &job, desktop.as_ref(),
            &self_exe.to_string_lossy(),
            &["--relay-inside",
              http_sock.to_str().unwrap(),
              if sp.is_some() { socks_sock.to_str().unwrap() } else { "" }],
        )?;
        let mut ports = Vec::<u16>::new();
        for line in BufReader::new(&mut child_stdout).lines() {
            let line = line?;
            if let Ok(p) = line.trim().parse::<u16>() { ports.push(p); }
            if ports.len() >= if sp.is_some() { 2 } else { 1 } { break; }
        }
        relay_pi = Some(pi);
        if let Some(p) = ports.first() {
            for k in ["HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy"] {
                extra_env.push((k.into(), format!("http://127.0.0.1:{p}")));
            }
        }
        if let (Some(_), Some(p)) = (sp, ports.get(1)) {
            for k in ["ALL_PROXY","all_proxy"] {
                extra_env.push((k.into(), format!("socks5h://127.0.0.1:{p}")));
            }
        }
    }

    // Launch the real target inside the AC + Job (+ alternate desktop).
    let pi = spawn_in_ac(&ac, &job, desktop.as_ref(), &pol.command_line,
                         pol.cwd.as_deref(), &extra_env)?;
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut code)?; }
    unsafe { let _ = CloseHandle(pi.hThread); let _ = CloseHandle(pi.hProcess); }

    if let Some(rpi) = relay_pi {
        unsafe {
            let _ = TerminateProcess(rpi.hProcess, 0);
            let _ = CloseHandle(rpi.hThread);
            let _ = CloseHandle(rpi.hProcess);
        }
    }
    drop(acls); // revert before AC profile delete (Drop on `ac`)
    drop(desktop);
    drop(job);
    Ok(code)
}

/// CreateProcessW into the AppContainer with the given Job + desktop.
/// `command_line` is the full Win32 command line (already shell-wrapped
/// by the TS side).
fn spawn_in_ac(
    ac: &AppContainer,
    job: &Job,
    desktop: Option<&AltDesktop>,
    command_line: &str,
    cwd: Option<&str>,
    env: &[(String, String)],
) -> Result<PROCESS_INFORMATION> {
    unsafe {
        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
        let mut attr_buf = vec![0u8; size];
        let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
        InitializeProcThreadAttributeList(attrs, 1, 0, &mut size)?;
        let caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac.sid, Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0, Reserved: 0,
        };
        UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&caps as *const _ as *const c_void),
            size_of::<SECURITY_CAPABILITIES>(), None, None,
        )?;

        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attrs;
        let desk_w;
        if let Some(d) = desktop {
            desk_w = wstr(&d.qualified_name());
            si.StartupInfo.lpDesktop = PWSTR(desk_w.as_ptr() as *mut u16);
        }

        let mut cmd = wstr(command_line);
        let cwd_w = cwd.map(wstr);
        let cwd_p = cwd_w.as_ref().map(|w| pcwstr(w)).unwrap_or(PCWSTR::null());
        let mut envb = build_env_block(env);

        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(
            None, PWSTR(cmd.as_mut_ptr()), None, None, true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(envb.as_mut_ptr() as *mut c_void), cwd_p, &si.StartupInfo, &mut pi,
        ).with_context(|| format!("CreateProcessW(AC, {command_line})"))?;
        DeleteProcThreadAttributeList(attrs);

        job.assign(pi.hProcess)?;
        ResumeThread(pi.hThread);
        Ok(pi)
    }
}

/// Spawn a helper inside the AC with stdout captured (for reading the
/// relay-inside ports). Uses std::process for the pipe plumbing, then
/// re-launches via Win32 with SECURITY_CAPABILITIES — but std::process
/// can't set proc-thread attributes, so we go via Win32 with anonymous
/// pipe handles.
fn spawn_in_ac_capture(
    ac: &AppContainer,
    job: &Job,
    desktop: Option<&AltDesktop>,
    exe: &str,
    args: &[&str],
) -> Result<(PROCESS_INFORMATION, std::fs::File)> {
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{STARTF_USESTDHANDLES};
    use windows::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use std::os::windows::io::FromRawHandle;
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        let mut rd = HANDLE::default();
        let mut wr = HANDLE::default();
        CreatePipe(&mut rd, &mut wr, Some(&sa), 0).context("CreatePipe")?;
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT.0, Default::default())?;

        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut size);
        let mut attr_buf = vec![0u8; size];
        let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
        InitializeProcThreadAttributeList(attrs, 1, 0, &mut size)?;
        let caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac.sid, Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0, Reserved: 0,
        };
        UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&caps as *const _ as *const c_void),
            size_of::<SECURITY_CAPABILITIES>(), None, None,
        )?;

        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attrs;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdOutput = wr;
        si.StartupInfo.hStdError = wr;
        let desk_w;
        if let Some(d) = desktop {
            desk_w = wstr(&d.qualified_name());
            si.StartupInfo.lpDesktop = PWSTR(desk_w.as_ptr() as *mut u16);
        }

        let mut cl = format!("\"{exe}\"");
        for a in args { if !a.is_empty() { cl.push(' '); cl.push('"'); cl.push_str(a); cl.push('"'); } }
        let mut clw = wstr(&cl);

        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessW(
            None, PWSTR(clw.as_mut_ptr()), None, None, true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, None, PCWSTR::null(),
            &si.StartupInfo, &mut pi,
        ).with_context(|| format!("CreateProcessW(relay-inside, {cl})"))?;
        DeleteProcThreadAttributeList(attrs);
        job.assign(pi.hProcess)?;
        ResumeThread(pi.hThread);
        let _ = CloseHandle(wr);

        let stdout = std::fs::File::from_raw_handle(rd.0 as *mut _);
        Ok((pi, stdout))
    }
}

