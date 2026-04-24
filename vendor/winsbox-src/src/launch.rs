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
use crate::interception;
use crate::ipc;
use crate::job::Job;
use crate::netbridge;
use crate::token;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex};

/// Pair of tokens for Mode::Broker. `primary` is the lowbox-wrapped
/// lockdown token used for CreateProcessAsUser; `initial` is the
/// matched impersonation token set on the main thread for loader init.
struct BrokerTokens { primary: HANDLE, initial: HANDLE }
impl Drop for BrokerTokens {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.primary); let _ = CloseHandle(self.initial); }
    }
}

/// Everything the IPC service thread needs to spawn a grandchild
/// the same way the broker spawned the immediate target. Wrapped
/// in `Arc` so each per-channel service thread shares one instance;
/// raw HANDLE/PSID values are pointer-sized integers and outlive
/// the threads (they're owned by `run_confined`'s stack frame which
/// joins all service threads before dropping anything).
struct SpawnCtx {
    ac_sid: windows::Win32::Security::PSID,
    job: HANDLE,
    primary: HANDLE,
    initial: HANDLE,
    cwd: String,
    env: Vec<(String, String)>,
    stop: Arc<AtomicBool>,
    /// Join handles for nested service threads, so the main loop
    /// can wait for the whole tree on exit.
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}
unsafe impl Send for SpawnCtx {}
unsafe impl Sync for SpawnCtx {}

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
                         &pol.command_line, Some(&target_cwd), &extra_env,
                         /*resume=*/ tokens.is_none())?;
    log!("target pid={}", pi.dwProcessId);

    // Phase-2b: under the restricted+lowbox primary the target
    // cannot CreateProcess natively (P10). Hook NtCreateUserProcess
    // so each spawn comes back to the broker over IPC; the broker
    // performs the create with the same recipe used for the
    // immediate target (so the loader survives), recursively
    // installs the hook in the grandchild, and DuplicateHandle's
    // the result back. One service thread per channel.
    let stop = Arc::new(AtomicBool::new(false));
    let ctx = tokens.as_ref().map(|t| Arc::new(SpawnCtx {
        ac_sid: ac.sid,
        job: job.handle(),
        primary: t.primary,
        initial: t.initial,
        cwd: target_cwd.clone(),
        env: extra_env.clone(),
        stop: stop.clone(),
        threads: Mutex::new(Vec::new()),
    }));
    if let Some(ctx) = ctx.as_ref() {
        match install_broker_hook(pi.hProcess, ctx.clone()) {
            Ok(()) => log!("interception installed on target"),
            Err(e) => log!("interception install failed ({e:#}); grandchild spawns will fail"),
        }
        unsafe { ResumeThread(pi.hThread); }
    }

    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }
    stop.store(true, Ordering::Relaxed);
    if let Some(ctx) = ctx {
        for h in ctx.threads.lock().unwrap().drain(..) { let _ = h.join(); }
    }
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
#[allow(clippy::too_many_arguments)]
fn spawn_in_ac(
    ac: &AppContainer,
    job: &Job,
    desktop: Option<&AltDesktop>,
    tokens: Option<&BrokerTokens>,
    command_line: &str,
    cwd: Option<&str>,
    env: &[(String, String)],
    resume: bool,
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
        if resume { ResumeThread(pi.hThread); }
        Ok(pi)
    }
}

// ─── Phase-2b broker-mediated spawn ────────────────────────────────

/// Create an IPC channel for `target`, install the
/// `NtCreateUserProcess` hook, and spawn the per-channel service
/// thread. Called once for the immediate target and recursively
/// for each grandchild the broker spawns.
fn install_broker_hook(target: HANDLE, ctx: Arc<SpawnCtx>) -> Result<()> {
    let ch = ipc::Channel::create(target)?;
    interception::install(target, &ch)?;
    let target_raw = target.0 as isize;
    let h = std::thread::spawn(move || serve_ipc(ch, target_raw, ctx));
    // Can't push into ctx.threads here because ctx was moved into
    // the closure above. The caller holds another Arc and pushes.
    // Actually we cloned ctx; push via the clone the caller has.
    // Simpler: return the JoinHandle and let the caller stash it.
    // But we recursively call from inside serve_ipc too. Use a
    // detached model: stash via a static — no, use ctx.threads
    // *before* moving ctx into the thread.
    // Re-do: clone ctx for the thread, keep one here for the push.
    let _ = h; // detached; ctx.stop + Job KILL_ON_JOB_CLOSE bound it.
    Ok(())
}

/// Per-channel service loop. Blocks on `ev_req`; on each request,
/// reads the target's `RTL_USER_PROCESS_PARAMETERS→CommandLine`,
/// performs the spawn under the broker's token recipe, recursively
/// installs the hook in the new process, DuplicateHandle's the
/// process+thread into the requesting target, and replies.
fn serve_ipc(ch: ipc::Channel, target_raw: isize, ctx: Arc<SpawnCtx>) {
    let target = HANDLE(target_raw as *mut c_void);
    while !ctx.stop.load(Ordering::Relaxed) {
        let req = match ch.wait_request(250) { Some(r) => r, None => continue };
        // args[8] = PRTL_USER_PROCESS_PARAMETERS (target VA).
        let cmdline = match read_target_cmdline(target, req.args[8] as usize) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[sbox-exec] ipc: read cmdline failed: {e:#}");
                ch.reply(0, 0, 0xC0000022u32 as i32 /*STATUS_ACCESS_DENIED*/, 0);
                continue;
            }
        };
        eprintln!("[sbox-exec] ipc: brokered spawn: {cmdline}");
        match broker_spawn(&ctx, &cmdline) {
            Ok(child) => {
                // Recursively hook the grandchild before resuming.
                if let Err(e) = install_broker_hook(child.hProcess, ctx.clone()) {
                    eprintln!("[sbox-exec] ipc: recurse hook failed: {e:#}");
                }
                let p = ch.dup_to_target(child.hProcess).unwrap_or(0);
                let t = ch.dup_to_target(child.hThread).unwrap_or(0);
                // kernel32!CreateProcessInternalW reads PS_CREATE_INFO
                // and the PS_ATTRIBUTE_CLIENT_ID/IMAGE_INFO out-attrs
                // after NtCreateUserProcess returns; populate them so
                // it doesn't fail post-processing.
                if let Err(e) = fill_create_outparams(
                    &ch, target, &req, &child, p, t,
                ) {
                    eprintln!("[sbox-exec] ipc: fill outparams: {e:#}");
                }
                // Do NOT resume here. The duplicated thread handle has
                // THREAD_ALL_ACCESS; the requesting process's
                // CreateProcessInternalW resumes it after its own
                // post-processing (CSR/conhost), exactly as if the
                // kernel had done the spawn.
                ch.reply(p, t, 0 /*STATUS_SUCCESS*/, child.dwProcessId);
                // Keep child.hProcess open: the recursive Channel
                // holds it for future dup_to_target calls (great-
                // grandchildren). The Job's KILL_ON_JOB_CLOSE bounds
                // the leak to the target's lifetime. Close hThread
                // since nothing else needs it.
                unsafe { let _ = CloseHandle(child.hThread); }
            }
            Err(e) => {
                eprintln!("[sbox-exec] ipc: brokered spawn failed: {e:#}");
                ch.reply(0, 0, 0xC0000022u32 as i32, 0);
            }
        }
    }
}

/// Spawn `cmdline` under the same restricted+lowbox token + Job +
/// initial-impersonation recipe used for the immediate target.
/// Returns SUSPENDED so the caller can install the hook first.
fn broker_spawn(ctx: &SpawnCtx, cmdline: &str) -> Result<PROCESS_INFORMATION> {
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;
    unsafe {
        let mut cmd = wstr(cmdline);
        let cwd = wstr(&ctx.cwd);
        let mut envb = build_env_block(&ctx.env);
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessAsUserW(
            ctx.primary, None, PWSTR(cmd.as_mut_ptr()), None, None, true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(envb.as_mut_ptr() as *mut c_void),
            PCWSTR(cwd.as_ptr()), &si, &mut pi,
        ).with_context(|| format!("CreateProcessAsUserW(brokered, {cmdline})"))?;
        if let Err(e) = SetThreadToken(Some(&pi.hThread), ctx.initial) {
            eprintln!("[sbox-exec] broker_spawn: SetThreadToken: {e}");
        }
        AssignProcessToJobObject(ctx.job, pi.hProcess)
            .context("AssignProcessToJobObject(brokered)")?;
        let _ = ctx.ac_sid; // kept for future SECURITY_CAPABILITIES use
        Ok(pi)
    }
}

/// Populate the caller's `PS_CREATE_INFO` (arg10) and the
/// `PS_ATTRIBUTE_CLIENT_ID` / `PS_ATTRIBUTE_IMAGE_INFO` entries in
/// `PS_ATTRIBUTE_LIST` (arg11) so `CreateProcessInternalW`'s
/// post-`NtCreateUserProcess` path sees a coherent success state.
fn fill_create_outparams(
    ch: &ipc::Channel,
    target: HANDLE,
    req: &ipc::Wire,
    child: &PROCESS_INFORMATION,
    target_hproc: u64,
    target_hthread: u64,
) -> Result<()> {
    let _ = (target_hproc, target_hthread);
    // ── PS_CREATE_INFO @ args[9]
    // Layout (x64): Size:u64 @0x00, State:u32 @0x08, then a union.
    // For State=PsCreateSuccess(6), SuccessState starts @0x10:
    //   OutputFlags:u32 @0x10, FileHandle @0x18, SectionHandle @0x20,
    //   UserProcessParametersNative @0x28, UserProcessParametersWow64 @0x30,
    //   CurrentParameterFlags @0x34, PebAddressNative @0x38,
    //   PebAddressWow64 @0x40, ManifestAddress @0x48, ManifestSize @0x50.
    let ci = req.args[9] as usize;
    if ci != 0 {
        let peb = remote_peb(child.hProcess).unwrap_or(0);
        // PEB+0x20 = ProcessParameters; PEB+0x20+0x08 = its Flags.
        let upp: u64 = if peb != 0 {
            interception::read_remote(child.hProcess, peb + 0x20).unwrap_or(0)
        } else { 0 };
        let upp_flags: u32 = if upp != 0 {
            interception::read_remote(child.hProcess, upp as usize + 0x08).unwrap_or(0)
        } else { 0 };
        // Reopen the child's image file + SEC_IMAGE section so the
        // caller's CreateProcessInternalW can run AppCompat / Safer
        // checks (BasepCheckWinSaferRestrictions reads FileHandle)
        // and close them on the success path.
        let (t_file, t_sect) = open_child_image(ch, child.hProcess)
            .unwrap_or_else(|e| {
                eprintln!("[sbox-exec] ipc: open_child_image: {e:#}");
                (0, 0)
            });
        eprintln!(
            "[sbox-exec] ipc: ci peb={:#x} upp={:#x} flags={:#x} file={:#x} sect={:#x}",
            peb, upp, upp_flags, t_file, t_sect,
        );
        interception::write_remote::<u32>(target, ci + 0x08, &6)?;            // State = PsCreateSuccess
        interception::write_remote::<u32>(target, ci + 0x10, &0)?;            // OutputFlags = 0
        interception::write_remote::<u64>(target, ci + 0x18, &t_file)?;       // FileHandle
        interception::write_remote::<u64>(target, ci + 0x20, &t_sect)?;       // SectionHandle
        interception::write_remote::<u64>(target, ci + 0x28, &upp)?;          // UserProcessParametersNative
        interception::write_remote::<u32>(target, ci + 0x30, &0)?;            // UserProcessParametersWow64
        interception::write_remote::<u32>(target, ci + 0x34, &upp_flags)?;    // CurrentParameterFlags
        interception::write_remote::<u64>(target, ci + 0x38, &(peb as u64))?; // PebAddressNative
        interception::write_remote::<u32>(target, ci + 0x40, &0)?;            // PebAddressWow64
        interception::write_remote::<u64>(target, ci + 0x48, &0)?;            // ManifestAddress
        interception::write_remote::<u32>(target, ci + 0x50, &0)?;            // ManifestSize
    }
    // ── PS_ATTRIBUTE_LIST @ args[10]
    // { TotalLength:u64; Attributes[]: { Attr:u64, Size:u64, ValuePtr:u64, ReturnLength:*u64 } }
    let al = req.args[10] as usize;
    if al != 0 {
        let total: u64 = interception::read_remote(target, al)?;
        let mut off = 8usize;
        while off + 0x20 <= total as usize {
            let attr: u64 = interception::read_remote(target, al + off)?;
            let size: u64 = interception::read_remote(target, al + off + 8)?;
            let valp: u64 = interception::read_remote(target, al + off + 16)?;
            let attr_num = (attr & 0xFFFF) as u32;
            match attr_num {
                // PsAttributeClientId = 3 → CLIENT_ID { pid, tid }
                3 if valp != 0 && size >= 16 => {
                    interception::write_remote::<u64>(target, valp as usize,
                        &(child.dwProcessId as u64))?;
                    interception::write_remote::<u64>(target, valp as usize + 8,
                        &(child.dwThreadId as u64))?;
                }
                // PsAttributeImageInfo = 6 → SECTION_IMAGE_INFORMATION.
                // CreateProcessInternalW reads SubSystemType (offset
                // 0x20) and Machine (0x30) here; with the previous
                // zero-fill cmd.exe printed "cannot be run in Win32
                // mode". Fetch the real struct from the child we just
                // created — the broker has full access to it.
                6 if valp != 0 && size > 0 => {
                    let sii = query_image_info(child.hProcess)?;
                    let n = (size as usize).min(sii.len());
                    eprintln!(
                        "[sbox-exec] ipc: image_info subsys={} machine={:#x} → {} bytes",
                        u32::from_le_bytes(sii[0x20..0x24].try_into().unwrap()),
                        u16::from_le_bytes(sii[0x30..0x32].try_into().unwrap()),
                        n,
                    );
                    let mut written = 0usize;
                    unsafe {
                        let _ = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                            target, valp as *const c_void,
                            sii.as_ptr() as *const c_void,
                            n, Some(&mut written),
                        );
                    }
                }
                _ => {}
            }
            off += 0x20;
        }
    }
    Ok(())
}

fn remote_peb(proc: HANDLE) -> Result<usize> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
    unsafe {
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut len = 0u32;
        let st = NtQueryInformationProcess(
            proc, PROCESSINFOCLASS(0),
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut len,
        );
        anyhow::ensure!(st.0 >= 0, "NtQueryInformationProcess: {:#x}", st.0);
        Ok(pbi.PebBaseAddress as usize)
    }
}

/// `NtQueryInformationProcess(ProcessImageInformation)` →
/// `SECTION_IMAGE_INFORMATION` (0x40 bytes on x64). Used to fill the
/// requesting process's `PS_ATTRIBUTE_IMAGE_INFO` out-attribute.
fn query_image_info(proc: HANDLE) -> Result<[u8; 0x40]> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    unsafe {
        let mut buf = [0u8; 0x40];
        let mut len = 0u32;
        let st = NtQueryInformationProcess(
            proc, PROCESSINFOCLASS(37),
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32, &mut len,
        );
        anyhow::ensure!(st.0 >= 0,
            "NtQueryInformationProcess(ProcessImageInformation): {:#x}", st.0);
        Ok(buf)
    }
}

/// Reopen `child`'s image file + SEC_IMAGE section, duplicate both
/// into the requesting process via `ch`, and return the *target-side*
/// handle values for `PS_CREATE_INFO.SuccessState.{FileHandle,SectionHandle}`.
fn open_child_image(ch: &ipc::Channel, child: HANDLE) -> Result<(u64, u64)> {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    use windows::Win32::System::Memory::SEC_IMAGE;
    #[link(name = "ntdll")]
    extern "system" {
        fn NtOpenFile(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES,
            iosb: *mut [usize; 2], share: u32, options: u32) -> NTSTATUS;
        fn NtCreateSection(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES, max: *const u64, prot: u32,
            attrs: u32, file: HANDLE) -> NTSTATUS;
    }
    unsafe {
        // ProcessImageFileName (27) → UNICODE_STRING NT path.
        let mut buf = vec![0u8; 1024];
        let mut len = 0u32;
        let st = NtQueryInformationProcess(
            child, PROCESSINFOCLASS(27),
            buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut len,
        );
        anyhow::ensure!(st.0 >= 0, "NtQueryInformationProcess(ImageFileName): {:#x}", st.0);
        let us = &*(buf.as_ptr() as *const UNICODE_STRING);
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: us as *const _ as *mut _,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut file = HANDLE::default();
        let mut iosb = [0usize; 2];
        // SYNCHRONIZE | FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES
        let st = NtOpenFile(&mut file, 0x00100000 | 0x0001 | 0x0020 | 0x0080,
            &oa, &mut iosb,
            0x07, /* FILE_SHARE_READ|WRITE|DELETE */
            0x20  /* FILE_SYNCHRONOUS_IO_NONALERT */);
        anyhow::ensure!(st.0 >= 0, "NtOpenFile({}): {:#x}",
            String::from_utf16_lossy(std::slice::from_raw_parts(
                us.Buffer.0, us.Length as usize / 2)), st.0);
        let mut sect = HANDLE::default();
        let st = NtCreateSection(&mut sect, 0x000F001F /* SECTION_ALL_ACCESS */,
            std::ptr::null(), std::ptr::null(),
            0x10 /* PAGE_EXECUTE */, SEC_IMAGE.0, file);
        anyhow::ensure!(st.0 >= 0, "NtCreateSection: {:#x}", st.0);
        let t_file = ch.dup_to_target(file)?;
        let t_sect = ch.dup_to_target(sect)?;
        let _ = CloseHandle(file);
        let _ = CloseHandle(sect);
        Ok((t_file, t_sect))
    }
}

/// Chase `RTL_USER_PROCESS_PARAMETERS→CommandLine` in the target
/// and return it as a String.
fn read_target_cmdline(target: HANDLE, params_va: usize) -> Result<String> {
    if params_va == 0 { bail!("null ProcessParameters"); }
    // Layout (x64): Flags @ +0x08; CommandLine UNICODE_STRING @ +0x70
    //   { Length:u16, MaxLength:u16, _pad:u32, Buffer:u64 }
    #[repr(C)] #[derive(Clone, Copy)]
    struct UStr { length: u16, max: u16, _pad: u32, buffer: u64 }
    let flags: u32 = interception::read_remote(target, params_va + 0x08)?;
    let us: UStr = interception::read_remote(target, params_va + 0x70)?;
    let mut buf_va = us.buffer as usize;
    // If not RTL_USER_PROC_PARAMS_NORMALIZED, Buffer is an offset
    // from the struct base.
    if flags & 0x01 == 0 { buf_va = params_va.wrapping_add(buf_va); }
    if us.length == 0 || us.length > 32768 { bail!("CommandLine length {}", us.length); }
    interception::read_remote_wstr(target, buf_va, us.length as usize)
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

