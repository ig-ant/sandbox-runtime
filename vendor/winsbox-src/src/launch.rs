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
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    GetExitCodeProcess, InitializeProcThreadAttributeList, ResumeThread,
    SetThreadToken, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTUPINFOEXW, STARTUPINFOW,
};

use crate::acl::{AclJournal, FULL, MODIFY, READ_EXECUTE};
use crate::appcontainer::AppContainer;
use crate::desktop::AltDesktop;
use crate::job::Job;
use crate::netbridge;
use crate::token;

/// Pair of tokens for Mode::Broker. `primary` is the lowbox-wrapped
/// lockdown token used for CreateProcessAsUser; `initial` is the
/// matched impersonation token set on the main thread for loader init.
struct BrokerTokens { primary: HANDLE, initial: HANDLE }
impl Drop for BrokerTokens {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.primary); let _ = CloseHandle(self.initial); }
    }
}

pub fn run(pol: &Policy) -> Result<u32> {
    match pol.mode {
        Mode::Stub => run_stub(pol),
        Mode::AppContainer | Mode::Broker => run_confined(pol),
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

macro_rules! log { ($($a:tt)*) => { eprintln!("[sbox-exec] {}", format!($($a)*)) } }

fn build_broker_tokens(ac: &AppContainer) -> Result<BrokerTokens> {
    let base = token::open_self_token()?;
    // Phase-2a: launch at Low IL; the entry trampoline (Phase-2b)
    // will drop to Untrusted post-loader-init. Both tokens MUST be
    // at the same IL and lowbox-wrapped or SeTokenCanImpersonate
    // downgrades the impersonation to Identification (PoC P5).
    let il = token::IL_LOW;
    let lockdown = token::make_lockdown(base, il)?;
    let initial_r = token::make_initial(base, il)?;
    unsafe { let _ = CloseHandle(base); }

    // NtCreateLowBoxToken needs a primary input and yields a primary;
    // dup the initial-side result to impersonation for SetThreadToken.
    let lock_lb = token::make_lowbox(lockdown, ac.sid)?;
    let init_lb = token::make_lowbox(initial_r, ac.sid)?;
    unsafe { let _ = CloseHandle(lockdown); let _ = CloseHandle(initial_r); }

    let primary = token::to_primary(lock_lb)?;
    let initial = token::to_impersonation(init_lb)?;
    unsafe { let _ = CloseHandle(lock_lb); let _ = CloseHandle(init_lb); }
    log!("broker tokens built (lockdown+lowbox primary, USER_RESTRICTED_SAME_ACCESS+lowbox impersonation, IL=Low)");
    Ok(BrokerTokens { primary, initial })
}

fn run_confined(pol: &Policy) -> Result<u32> {
    log!("mode={:?}", pol.mode);
    let ac = AppContainer::create("ac")?;
    log!("AppContainer sid={} folder={}", ac.sid_string, ac.folder.display());
    let job = Job::new()?;
    log!("Job created");
    let desktop = if pol.use_alternate_desktop {
        match AltDesktop::new() {
            Ok(d) => { log!("alt desktop {}", d.qualified_name()); Some(d) }
            Err(e) => { log!("alt desktop unavailable ({e}); continuing without"); None }
        }
    } else { None };
    let mut acls = AclJournal::default();

    // The AC needs to read+execute this binary (for the inside relay).
    let self_exe = std::env::current_exe()?;
    acls.grant(self_exe.to_str().unwrap(), &ac.sid_string, READ_EXECUTE)?;
    if let Some(dir) = self_exe.parent() {
        if let Err(e) = acls.grant(dir.to_str().unwrap(), &ac.sid_string, READ_EXECUTE) {
            log!("ACL grant self-dir: {e:#}");
        }
    }

    // Filesystem policy → ACEs. Allow first (icacls /grant), then
    // /deny on the deny paths — icacls always orders explicit deny
    // before allow on the same object, and deny ACEs are evaluated
    // first regardless.
    let mut acl_op = |op: &str, p: &str, perm: &str, deny: bool| {
        let r = if deny { acls.deny(p, &ac.sid_string, perm) }
                else    { acls.grant(p, &ac.sid_string, perm) };
        if let Err(e) = r { log!("ACL {op} {p}: {e:#}"); }
    };
    for p in &pol.allow_read {
        if std::path::Path::new(p).exists() { acl_op("allow-read", p, READ_EXECUTE, false); }
    }
    for p in &pol.allow_write {
        // Skip device names (NUL, CON, …) — not real filesystem objects.
        let leaf = std::path::Path::new(p).file_name()
            .map(|f| f.to_string_lossy().to_ascii_uppercase()).unwrap_or_default();
        if matches!(leaf.as_str(), "NUL" | "CON" | "PRN" | "AUX") { continue; }
        std::fs::create_dir_all(p).ok();
        acl_op("allow-write", p, MODIFY, false);
    }
    for p in &pol.deny_write {
        if std::path::Path::new(p).exists() { acl_op("deny-write", p, MODIFY, true); }
    }
    for p in &pol.deny_read {
        if std::path::Path::new(p).exists() {
            acl_op("deny-read", p, FULL, true);
            log!("icacls {p}:\n{}", crate::acl::dump(p).trim_end());
        }
    }

    log!("ACLs applied: {} grants/denies", pol.allow_read.len() + pol.allow_write.len() + pol.deny_read.len() + pol.deny_write.len());

    // Network bridge: only if the policy carries proxy ports. Failures
    // here are logged but non-fatal — the AC simply has no network,
    // which is the safe default.
    let mut extra_env = pol.env.clone();
    let mut relay_pi: Option<PROCESS_INFORMATION> = None;
    if let Some(hp) = pol.network.http_proxy_port {
        let sp = pol.network.socks_proxy_port;
        match setup_bridge(&ac, &job, desktop.as_ref(), &mut acls, &self_exe, hp, sp) {
            Ok((pi, ports)) => {
                relay_pi = Some(pi);
                log!("bridge up: ports={:?}", ports);
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
            Err(e) => log!("bridge setup failed ({e:#}); continuing without proxy"),
        }
    } else {
        log!("no proxy ports in policy; skipping bridge");
    }

    // Mode::Broker layers a restricted lowbox token on top.
    let tokens = if pol.mode == Mode::Broker {
        match build_broker_tokens(&ac) {
            Ok(t) => Some(t),
            Err(e) => {
                log!("broker token build failed ({e:#}); falling back to AppContainer-only");
                None
            }
        }
    } else { None };

    // The AC must be able to read its cwd or cmd.exe fails with "The
    // current directory is invalid". Use the first allow_write (or the
    // AC package folder) instead of the broker's cwd, which the AC
    // generally cannot reach.
    let target_cwd = pol.allow_write.iter()
        .find(|p| std::path::Path::new(p).is_dir())
        .cloned()
        .unwrap_or_else(|| ac.folder.to_string_lossy().into_owned());
    log!("launching target (cwd={}): {}", target_cwd, pol.command_line);
    let pi = spawn_in_ac(&ac, &job, desktop.as_ref(), tokens.as_ref(),
                         &pol.command_line, Some(&target_cwd), &extra_env)?;
    log!("target pid={}", pi.dwProcessId);
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut code)?; }
    log!("target exit={code:#x}");
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
    tokens: Option<&BrokerTokens>,
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
        let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;

        let mut pi: PROCESS_INFORMATION = zeroed();
        match tokens {
            Some(t) => {
                // The lowbox primary already encodes the AppContainer
                // SID, so DON'T also set SECURITY_CAPABILITIES — doing
                // both makes children inherit a token whose AC doesn't
                // match the proc-thread attribute and CreateProcess
                // for grandchildren fails ERROR_ACCESS_DENIED.
                let mut si_plain: STARTUPINFOW = zeroed();
                si_plain.cb = size_of::<STARTUPINFOW>() as u32;
                if let Some(d) = desktop {
                    let dw = wstr(&d.qualified_name());
                    si_plain.lpDesktop = PWSTR(dw.as_ptr() as *mut u16);
                    std::mem::forget(dw);
                }
                CreateProcessAsUserW(
                    t.primary, None, PWSTR(cmd.as_mut_ptr()), None, None, true,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(envb.as_mut_ptr() as *mut c_void), cwd_p,
                    &si_plain, &mut pi,
                ).with_context(|| format!("CreateProcessAsUserW(broker, {command_line})"))?;
                if let Err(e) = SetThreadToken(Some(&pi.hThread), t.initial) {
                    log!("SetThreadToken(initial) failed: {e}; loader may fail under lockdown");
                }
            }
            None => {
                CreateProcessW(
                    None, PWSTR(cmd.as_mut_ptr()), None, None, true,
                    flags, Some(envb.as_mut_ptr() as *mut c_void), cwd_p,
                    &si.StartupInfo, &mut pi,
                ).with_context(|| format!("CreateProcessW(AC, {command_line})"))?;
            }
        }
        DeleteProcThreadAttributeList(attrs);
        let _ = &caps;

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

fn setup_bridge(
    ac: &AppContainer,
    job: &Job,
    desktop: Option<&AltDesktop>,
    acls: &mut AclJournal,
    self_exe: &std::path::Path,
    http_port: u16,
    socks_port: Option<u16>,
) -> Result<(PROCESS_INFORMATION, Vec<u16>)> {
    let (sock_dir, needs_acl) = netbridge::socket_dir(&ac.folder);
    if needs_acl {
        acls.grant(sock_dir.to_str().unwrap(), &ac.sid_string, MODIFY)?;
    }
    let http_sock = sock_dir.join("h.sock");
    let socks_sock = sock_dir.join("s.sock");
    log!("bridge: outside relay http={} → {}", http_sock.display(), http_port);
    netbridge::spawn_outside_relay(http_sock.clone(), http_port)?;
    if let Some(sp) = socks_port {
        log!("bridge: outside relay socks={} → {}", socks_sock.display(), sp);
        netbridge::spawn_outside_relay(socks_sock.clone(), sp)?;
    }

    log!("bridge: spawning inside relay");
    let (pi, child_stdout) = spawn_in_ac_capture(
        ac, job, desktop,
        self_exe.to_str().unwrap(),
        &["--relay-inside",
          http_sock.to_str().unwrap(),
          if socks_port.is_some() { socks_sock.to_str().unwrap() } else { "" }],
    )?;
    log!("bridge: inside relay pid={}, reading ports", pi.dwProcessId);

    // Read ports with a watchdog — if the relay died (e.g., AC denied
    // it execute) the pipe never produces and we'd hang.
    let want = if socks_port.is_some() { 2 } else { 1 };
    let (tx, rx) = std::sync::mpsc::channel::<u16>();
    std::thread::spawn(move || {
        for line in BufReader::new(child_stdout).lines().flatten() {
            if let Ok(p) = line.trim().parse::<u16>() { let _ = tx.send(p); }
        }
    });
    let mut ports = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while ports.len() < want {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(p) => ports.push(p),
            Err(_) => {
                unsafe { let _ = TerminateProcess(pi.hProcess, 1); }
                bail!("inside relay produced {}/{} ports before timeout", ports.len(), want);
            }
        }
    }
    Ok((pi, ports))
}

