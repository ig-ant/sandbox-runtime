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
    ac_sid_string: String,
    job: HANDLE,
    primary: HANDLE,
    initial: HANDLE,
    cwd: String,
    env: Vec<(String, String)>,
    stop: Arc<AtomicBool>,
    fs: crate::policy_engine::FsPolicy,
    /// Whether to install the NtCreateFile/NtOpenFile hooks. When
    /// false the Phase-1 ACL grants are the only FS boundary and
    /// reads of paths the AC SID isn't granted on fail in the
    /// target with no broker involvement.
    hook_fs: bool,
    /// `SBOX_TRACE=1`: log every brokered FS/registry/section
    /// open with path + status, including successes.
    trace: bool,
    /// `WINSBOX_TOKEN=lockdown`: changes registry brokering
    /// behaviour — under lockdown, KEY_ALL_ACCESS opens are
    /// masked to KEY_READ and brokered (passthrough fails the
    /// normal-SID check); under USER_LIMITED they passthrough
    /// (succeeds, and brokering them all caused an
    /// `ExitProcess`-time spinlock hang at 12e3d0d).
    lockdown: bool,
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
    // Both tokens MUST be at the same IL and lowbox-wrapped or
    // SeTokenCanImpersonate downgrades the impersonation to
    // Identification (PoC P5). `spec_from_env` returns
    // (USER_LIMITED, Low) by default; WINSBOX_TOKEN=lockdown →
    // (USER_LOCKDOWN, Untrusted) for step-0 retesting on CI.
    let (spec, il) = token::spec_from_env();
    let lockdown = token::make_lockdown_with(base, il, spec)?;
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
    log!(
        "broker tokens: primary={spec:?}+lowbox, initial=USER_RESTRICTED_SAME_ACCESS+lowbox, IL={:#x}",
        il,
    );
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

    // Filesystem policy → ACEs (Phase-1 mechanism). When the FS
    // broker is active:
    //  - allowRead grants are skipped — the broker opens read
    //    paths under its own token, and reads always go via
    //    NtCreateFile/NtOpenFile (hooked).
    //  - allowWrite still gets the AC-SID grant: libuv issues
    //    RootDirectory-relative writes that the broker can't
    //    path-resolve and passes through; without the on-disk
    //    ACE the target's lowbox token can't complete those
    //    (npm cacache copyfile, 460f267). The RESTRICTED grant
    //    is dropped — the broker covers the restricting check
    //    and the persistent S-1-5-12 ACE was undesirable
    //    anyway. Halves the icacls count.
    //  - denyRead/denyWrite stay regardless: under
    //    USER_LIMITED a raw NtCreateFile bypassing the hook
    //    would otherwise succeed via the enabled `Users`
    //    group, so the on-disk ACE is the security boundary.
    const RESTRICTED_SID: &str = "S-1-5-12";
    let ac_sid = ac.sid_string.clone();
    let both = [ac_sid.as_str(), RESTRICTED_SID];
    let grant_sids: &[&str] = if pol.broker_fs { &both[..1] } else { &both };
    let mut acl_op = |op: &str, p: &str, perm: &str, deny: bool, sids: &[&str]| {
        for sid in sids {
            let r = if deny { acls.deny(p, sid, perm) }
                    else    { acls.grant(p, sid, perm) };
            if let Err(e) = r { log!("ACL {op} {p} ({sid}): {e:#}"); }
        }
    };
    if !pol.broker_fs {
        for p in &pol.allow_read {
            if std::path::Path::new(p).exists() {
                acl_op("allow-read", p, READ_EXECUTE, false, grant_sids);
            }
        }
    }
    for p in &pol.allow_write {
        let leaf = std::path::Path::new(p).file_name()
            .map(|f| f.to_string_lossy().to_ascii_uppercase()).unwrap_or_default();
        if matches!(leaf.as_str(), "NUL" | "CON" | "PRN" | "AUX") { continue; }
        std::fs::create_dir_all(p).ok();
        acl_op("allow-write", p, MODIFY, false, grant_sids);
    }
    for p in &pol.deny_write {
        if std::path::Path::new(p).exists() {
            acl_op("deny-write", p, MODIFY, true, &both);
        }
    }
    for p in &pol.deny_read {
        if std::path::Path::new(p).exists() {
            acl_op("deny-read", p, FULL, true, &both);
            log!("icacls {p}:\n{}", crate::acl::dump(p).trim_end());
        }
    }
    log!(
        "ACLs: {} allow-grants {} {} denies",
        if pol.broker_fs { "skipped (broker_fs)," } else { "applied," },
        pol.allow_read.len() + pol.allow_write.len(),
        pol.deny_read.len() + pol.deny_write.len(),
    );

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

    // Mode::Broker layers a restricted lowbox token on top. Hard
    // error on failure — silently degrading to AppContainer-only
    // gave a false green when CreateRestrictedToken rejected the
    // package SID in the restricting list.
    let tokens = if pol.mode == Mode::Broker {
        Some(build_broker_tokens(&ac).context("broker token build")?)
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
        ac_sid_string: ac.sid_string.clone(),
        job: job.handle(),
        primary: t.primary,
        initial: t.initial,
        cwd: target_cwd.clone(),
        env: extra_env.clone(),
        stop: stop.clone(),
        fs: crate::policy_engine::FsPolicy::from_policy(pol),
        hook_fs: pol.broker_fs,
        trace: std::env::var("SBOX_TRACE").is_ok(),
        lockdown: token::spec_from_env().0.keep_enabled.is_empty(),
        threads: Mutex::new(Vec::new()),
    }));
    if let Some(ctx) = ctx.as_ref() {
        match install_broker_hook(pi.hProcess, pi.hThread, false, ctx.clone()) {
            Ok(()) => log!("interception installed on target"),
            Err(e) => {
                log!("interception install failed ({e:#}); grandchild spawns will fail");
                unsafe { ResumeThread(pi.hThread); }
            }
        }
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

/// Create an IPC channel for `target`, patch the ntdll FS hooks
/// (ntdll is mapped at `CREATE_SUSPENDED`), install the
/// entry-point rendezvous, **resume** the target so its loader
/// runs (with FS opens already brokered — required for
/// USER_LOCKDOWN, where parallel-loader worker threads run under
/// the NULL-restricting process token and would otherwise
/// `0xc0000135` on any non-KnownDll import; P12), wait for the
/// rendezvous, patch `kernelbase!CreateProcessInternalW`, and let
/// the target continue. Called once for the immediate target and
/// recursively for each grandchild the broker spawns. The target
/// must be SUSPENDED on entry; on success it is running unless
/// `suspend_after` (the stub re-suspends itself post-rendezvous
/// so the *caller*'s `ResumeThread` is what releases it —
/// honours `CREATE_SUSPENDED`).
fn install_broker_hook(
    target: HANDLE, thread: HANDLE, suspend_after: bool, ctx: Arc<SpawnCtx>,
) -> Result<()> {
    let ch = ipc::Channel::create(target)?;
    let addrs = ch.stub_env_snapshot();
    let sync = crate::entry_trampoline::install(target, thread, suspend_after)?;
    if ctx.hook_fs {
        interception::install_fs(target, &addrs)?;
        interception::install_reg(target, &addrs)?;
    }
    let target_raw = target.0 as isize;
    let ctx_thread = ctx.clone();
    let _ = std::thread::spawn(move || serve_ipc(ch, target_raw, ctx_thread));
    unsafe { ResumeThread(thread); }
    if !sync.wait_loaded_or_exit(target, 15_000) {
        bail!("entry rendezvous timed out (loader hung/exited)");
    }
    // Loader done; kernelbase is mapped and the target is parked
    // in the entry stub.
    let cpw = crate::entry_trampoline::cpw_address()?;
    interception::install_cpw(target, &addrs, cpw)?;
    let _ = ctx;
    sync.go();
    Ok(())
}

/// Per-channel service loop. Dispatches on `Wire.op`.
fn serve_ipc(ch: ipc::Channel, target_raw: isize, ctx: Arc<SpawnCtx>) {
    let target = HANDLE(target_raw as *mut c_void);
    while !ctx.stop.load(Ordering::Relaxed) {
        let req = match ch.wait_request(250) { Some(r) => r, None => continue };
        match req.op {
            ipc::OP_CPW => handle_cpw(&ch, target, &req, &ctx),
            ipc::OP_NTCREATEFILE | ipc::OP_NTOPENFILE =>
                handle_fs(&ch, target, &req, &ctx),
            ipc::OP_NTOPENKEY | ipc::OP_NTOPENKEYEX | ipc::OP_NTOPENSECTION =>
                handle_reg(&ch, target, &req, &ctx),
            ipc::OP_NTQUERYATTR | ipc::OP_NTQUERYFULLATTR =>
                handle_attr(&ch, target, &req, &ctx),
            op => {
                eprintln!("[sbox-exec] ipc: unknown op {op}");
                ch.reply_fs(0, 0, 0xC0000002u32 as i32 /* STATUS_NOT_IMPLEMENTED */);
            }
        }
    }
}

fn handle_cpw(ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>) {
    // CreateProcessInternalW args:
    //   [1]=lpApplicationName, [2]=lpCommandLine, [6]=dwCreationFlags,
    //   [8]=lpCurrentDirectory, [9]=lpStartupInfo, [10]=lpProcessInformation.
    let app = read_target_wstr(target, req.args[1] as usize).unwrap_or_default();
    let cmd = read_target_wstr(target, req.args[2] as usize).unwrap_or_default();
    // NULL lpCurrentDirectory means "inherit caller's cwd";
    // read_target_wstr returns "" for null, which
    // CreateProcessAsUserW rejects with ERROR_INVALID_NAME.
    let cwd = read_target_wstr(target, req.args[8] as usize)
        .ok().filter(|s| !s.is_empty());
    let caller_flags = req.args[6] as u32;
    let si = read_target_startupinfo(target, req.args[9] as usize);
    let cmdline = if !cmd.is_empty() { cmd } else { app.clone() };
    if cmdline.is_empty() {
        eprintln!("[sbox-exec] ipc: empty cmdline (app={app:?})");
        ch.reply_cpw_err(87 /* ERROR_INVALID_PARAMETER */);
        return;
    }
    eprintln!(
        "[sbox-exec] ipc: brokered spawn: {cmdline}  (flags={caller_flags:#x} si.flags={:#x} app={app:?})",
        si.dwFlags.0,
    );
    let suspend_after = caller_flags & 0x00000004 /* CREATE_SUSPENDED */ != 0;
    let app_opt = (!app.is_empty()).then_some(app.as_str());
    let mut envb = read_target_env(target, req.args[7] as usize, caller_flags, ctx);
    match broker_spawn(ctx, app_opt, &cmdline, cwd.as_deref(),
                       caller_flags, &si, &mut envb) {
        Ok(child) => {
            if let Err(e) = install_broker_hook(
                child.hProcess, child.hThread, suspend_after, ctx.clone(),
            ) {
                eprintln!("[sbox-exec] ipc: recurse hook failed: {e:#}; child runs unhooked");
                unsafe { ResumeThread(child.hThread); }
            }
            let p = ch.dup_to_target(child.hProcess).unwrap_or(0);
            let t = ch.dup_to_target(child.hThread).unwrap_or(0);
            ch.reply_cpw_ok(p, t, child.dwProcessId, child.dwThreadId);
            // Keep child.hProcess open: the recursive Channel
            // holds it for future dup_to_target calls. Job
            // KILL_ON_JOB_CLOSE bounds the leak.
            unsafe { let _ = CloseHandle(child.hThread); }
            close_si_handles(&si);
        }
        Err(e) => {
            let gle = unsafe {
                windows::Win32::Foundation::GetLastError().0
            };
            eprintln!("[sbox-exec] ipc: brokered spawn failed: {e:#} (gle={gle})");
            ch.reply_cpw_err(if gle != 0 { gle } else { 5 });
            close_si_handles(&si);
        }
    }
}

fn handle_fs(ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>) {
    // NtCreateFile/NtOpenFile args:
    //   [0]=PHANDLE FileHandle, [1]=DesiredAccess,
    //   [2]=POBJECT_ATTRIBUTES, [3]=PIO_STATUS_BLOCK,
    //   create: [4]=AllocationSize [5]=FileAttributes [6]=ShareAccess
    //           [7]=CreateDisposition [8]=CreateOptions [9]=EaBuffer [10]=EaLength
    //   open:   [4]=ShareAccess [5]=OpenOptions
    let access = req.args[1] as u32;
    let oa_va = req.args[2] as usize;
    let path = match read_target_obj_path(target, oa_va) {
        Ok(p) => p,
        Err(e) => {
            // RootDirectory that isn't a file handle, or other
            // shapes the broker can't resolve — let the target
            // do the open itself under its own token.
            eprintln!("[sbox-exec] fs: passthrough ({e:#})");
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
    };
    use crate::policy_engine::Decision;
    match ctx.fs.evaluate(&path, access) {
        Decision::Deny(why) => {
            eprintln!("[sbox-exec] fs: DENY {path} ({why}, access={access:#x})");
            ch.reply_fs(0, 0, 0xC0000022u32 as i32 /* STATUS_ACCESS_DENIED */);
            return;
        }
        Decision::AllowAsTarget => {
            // Tell the stub to tail-jmp the saved original
            // syscall so the *target* does the open under its
            // own lowbox token — required for AFD/ConDrv where
            // the endpoint must be created inside the target's
            // AppContainer process, not the broker's.
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
        Decision::Allow => {}
    }
    match broker_open(req, &path, HANDLE::default()) {
        Ok((h, info)) => {
            let th = ch.dup_to_target(h).unwrap_or(0);
            unsafe { let _ = CloseHandle(h); }
            if ctx.trace {
                eprintln!("[sbox-exec] fs: ok {path} access={access:#x} → h={th:#x}");
            }
            ch.reply_fs(th, info, 0);
        }
        Err(st) => {
            if ctx.trace || (st != 0xC0000034u32 as i32 && st != 0xC000003Au32 as i32) {
                eprintln!("[sbox-exec] fs: open {path}: {st:#x} access={access:#x}");
            }
            if st == 0xC000000Du32 as i32 {
                eprintln!(
                    "[sbox-exec] fs:   args op={} a4={:#x} a5={:#x} a6={:#x} a7={:#x} a8={:#x} a9={:#x} a10={:#x}",
                    req.op, req.args[4], req.args[5], req.args[6],
                    req.args[7], req.args[8], req.args[9], req.args[10],
                );
            }
            ch.reply_fs(0, 0, st);
        }
    }
}

/// Issue the brokered `NtCreateFile`/`NtOpenFile` with the
/// caller's flags. If `impersonate` is non-null, the open
/// happens under that token (used for `\Device\*` so the
/// endpoint is created in the target's AppContainer); otherwise
/// under the broker's full token. Returns the broker-side
/// handle + `IO_STATUS_BLOCK.Information`, or the raw `NTSTATUS`.
fn broker_open(
    req: &ipc::Wire, nt_path: &str, impersonate: HANDLE,
) -> std::result::Result<(HANDLE, u64), i32> {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES, iosb: *mut [usize; 2],
            alloc: *const u64, fattrs: u32, share: u32, disp: u32,
            opts: u32, ea: *const c_void, ea_len: u32) -> NTSTATUS;
        fn NtOpenFile(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES, iosb: *mut [usize; 2],
            share: u32, opts: u32) -> NTSTATUS;
    }
    unsafe {
        let mut wpath = wstr(nt_path);
        // Strip the trailing NUL — UNICODE_STRING.Length excludes it.
        if wpath.last() == Some(&0) { wpath.pop(); }
        let us = UNICODE_STRING {
            Length: (wpath.len() * 2) as u16,
            MaximumLength: (wpath.len() * 2) as u16,
            Buffer: PWSTR(wpath.as_mut_ptr()),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: &us as *const _ as *mut _,
            Attributes: 0x40 /* OBJ_CASE_INSENSITIVE */,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        if !impersonate.is_invalid() {
            let _ = SetThreadToken(None, impersonate);
        }
        let mut h = HANDLE::default();
        let mut iosb = [0usize; 2];
        let access = req.args[1] as u32;
        let st = if req.op == ipc::OP_NTCREATEFILE {
            // FILE_CONTAINS_EXTENDED_CREATE_INFORMATION (0x10000000,
            // Win11 22H2+) means EaBuffer carries an
            // EXTENDED_CREATE_INFORMATION struct; CopyFile2 sets
            // it. Stripping EaBuffer while leaving the flag set →
            // STATUS_INVALID_PARAMETER. Strip the flag too.
            const FILE_CONTAINS_EXTENDED_CREATE_INFORMATION: u32 = 0x10000000;
            let opts = req.args[8] as u32
                & !FILE_CONTAINS_EXTENDED_CREATE_INFORMATION;
            NtCreateFile(&mut h, access, &oa, &mut iosb,
                std::ptr::null(),               // AllocationSize: ignore
                req.args[5] as u32,             // FileAttributes
                req.args[6] as u32,             // ShareAccess
                req.args[7] as u32,             // CreateDisposition
                opts,                           // CreateOptions
                std::ptr::null(), 0)            // EaBuffer/Length: drop
        } else {
            NtOpenFile(&mut h, access, &oa, &mut iosb,
                req.args[4] as u32,             // ShareAccess
                req.args[5] as u32)             // OpenOptions
        };
        if !impersonate.is_invalid() {
            let _ = SetThreadToken(None, None);
        }
        if st.0 < 0 { Err(st.0) } else { Ok((h, iosb[1] as u64)) }
    }
}

/// `NtQuery{,Full}AttributesFile`: args[0]=POBJECT_ATTRIBUTES,
/// args[1]=out struct. Read-only by definition; evaluate
/// against the FS policy (denyRead → ACCESS_DENIED, else
/// re-issue under the broker's token). Result struct (≤56
/// bytes) goes back via the section at `ATTR_OFF`.
fn handle_attr(
    ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>,
) {
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryAttributesFile(
            oa: *const c_void, out: *mut [u8; 56],
        ) -> windows::Win32::Foundation::NTSTATUS;
        fn NtQueryFullAttributesFile(
            oa: *const c_void, out: *mut [u8; 56],
        ) -> windows::Win32::Foundation::NTSTATUS;
    }
    let path = match read_target_obj_path(target, req.args[0] as usize) {
        Ok(p) => p,
        Err(_) => { ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH); return; }
    };
    use crate::policy_engine::Decision;
    match ctx.fs.evaluate(&path, 0x0080 /* FILE_READ_ATTRIBUTES */) {
        Decision::Deny(why) => {
            eprintln!("[sbox-exec] attr: DENY {path} ({why})");
            ch.reply_attr(0xC0000022u32 as i32, &[0u8; 56]);
            return;
        }
        Decision::AllowAsTarget => {
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
        Decision::Allow => {}
    }
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::UNICODE_STRING;
    let st;
    let mut out = [0u8; 56];
    unsafe {
        let mut wpath = wstr(&path);
        if wpath.last() == Some(&0) { wpath.pop(); }
        let us = UNICODE_STRING {
            Length: (wpath.len() * 2) as u16,
            MaximumLength: (wpath.len() * 2) as u16,
            Buffer: PWSTR(wpath.as_mut_ptr()),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: &us as *const _ as *mut _,
            Attributes: 0x40,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        st = if req.op == ipc::OP_NTQUERYFULLATTR {
            NtQueryFullAttributesFile(&oa as *const _ as *const c_void, &mut out)
        } else {
            NtQueryAttributesFile(&oa as *const _ as *const c_void, &mut out)
        };
    }
    if ctx.trace {
        eprintln!("[sbox-exec] attr: {path} → {:#x}", st.0);
    }
    ch.reply_attr(st.0, &out);
}

/// `NtOpenKey` / `NtOpenKeyEx` / `NtOpenSection`:
/// args[0]=PHANDLE, [1]=DesiredAccess, [2]=POBJECT_ATTRIBUTES,
/// (NtOpenKeyEx only) [3]=OpenOptions. v1: default-allow-read;
/// passthrough on any write bit (lockdown token denies). The
/// broker dup's the caller's `RootDirectory` and re-issues the
/// open relative to it — no path stringification needed for
/// default-allow-read. With `SBOX_TRACE`, logs every call so
/// the sequence before a failure is visible.
fn handle_reg(
    ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>,
) {
    const MAXIMUM_ALLOWED: u32 = 0x02000000;
    const KEY_READ: u32 = 0x20019;
    const KEY_WOW64: u32 = 0x0100 | 0x0200;
    const KEY_WRITE_BITS: u32 =
        0x0002 /* KEY_SET_VALUE */ | 0x0004 /* KEY_CREATE_SUB_KEY */ |
        0x0020 /* KEY_CREATE_LINK */ | 0x00010000 | 0x00040000 |
        0x00080000 | 0x40000000 | 0x10000000;
    const KEY_READ_INTENT: u32 =
        0x0001 /*QUERY_VALUE*/ | 0x0008 /*ENUM_SUBKEYS*/ |
        0x0010 /*NOTIFY*/ | 0x80000000 | MAXIMUM_ALLOWED;
    const SEC_WRITE_BITS: u32 =
        0x0002 /* SECTION_MAP_WRITE */ | 0x0010 /* SECTION_EXTEND_SIZE */ |
        0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000;
    let req_access = req.args[1] as u32;
    let tag = if req.op == ipc::OP_NTOPENSECTION { "sec" } else { "reg" };
    let (root_raw, leaf) = match read_target_oa_raw(target, req.args[2] as usize) {
        Ok(r) => r,
        Err(e) => {
            if ctx.trace {
                eprintln!("[sbox-exec] {tag}: passthrough oa-read ({e:#})");
            }
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
    };
    // Passthrough on any explicit write bit. Under
    // USER_LIMITED the target's token opens it directly;
    // under USER_LOCKDOWN the `Restricting::Lockdown` list
    // (Everyone, RESTRICTED, Logon) plus the lowbox-added
    // ALL APP PACKAGES enabled group lets system registry/
    // sections through anyway. Brokering every
    // KEY_ALL_ACCESS open (12e3d0d tried this) adds hundreds
    // of IPCs and risks an `ExitProcess`-time hang where a
    // thread is killed mid-stub holding the section
    // spinlock and a `DLL_PROCESS_DETACH` callback then
    // spins forever.
    let write_bits = if req.op == ipc::OP_NTOPENSECTION {
        SEC_WRITE_BITS
    } else { KEY_WRITE_BITS };
    // Sections always passthrough on write. Registry under
    // USER_LIMITED passthroughs on write (target's token
    // succeeds; brokering all of these caused the 12e3d0d
    // ExitProcess-spinlock hang). Registry under
    // USER_LOCKDOWN: passthrough fails the normal-SID check
    // (ALL APP PACKAGES has read-only on registry), so mask
    // to KEY_READ and broker — the dup'd handle is read-only
    // so writes through it still fail. The spinlock hang is
    // a known risk under lockdown until the section gets a
    // proper mutant; lockdown is opt-in via WINSBOX_TOKEN.
    let mask_writes = ctx.lockdown && req.op != ipc::OP_NTOPENSECTION;
    if req_access & write_bits != 0 && !mask_writes {
        if ctx.trace {
            eprintln!("[sbox-exec] {tag}: passthrough write access={req_access:#x} {leaf}");
        }
        ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
        return;
    }
    if mask_writes
        && req_access & KEY_READ_INTENT == 0
        && req_access & write_bits != 0
    {
        if ctx.trace {
            eprintln!("[sbox-exec] {tag}: passthrough write-only access={req_access:#x} {leaf}");
        }
        ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
        return;
    }
    // MAXIMUM_ALLOWED under the broker's token would resolve
    // to write — substitute the read mask. Under lockdown
    // every brokered registry open uses KEY_READ regardless.
    let access = if req.op == ipc::OP_NTOPENSECTION {
        req_access & !MAXIMUM_ALLOWED
    } else if mask_writes || req_access & MAXIMUM_ALLOWED != 0 {
        KEY_READ | (req_access & KEY_WOW64)
    } else {
        req_access
    };
    let root_h = if root_raw != 0 {
        match dup_from_target(target, root_raw) {
            Ok(h) => h,
            Err(_) => { ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH); return; }
        }
    } else { HANDLE::default() };
    let opts = if req.op == ipc::OP_NTOPENKEYEX { req.args[3] as u32 } else { 0 };
    let st = broker_open_handle(req.op, &leaf, root_h, access, opts);
    if root_raw != 0 { unsafe { let _ = CloseHandle(root_h); } }
    match st {
        Ok(h) => {
            let th = ch.dup_to_target(h).unwrap_or(0);
            unsafe { let _ = CloseHandle(h); }
            if ctx.trace {
                eprintln!("[sbox-exec] {tag}: ok root={root_raw:#x} {leaf} → h={th:#x}");
            }
            ch.reply_fs(th, 0, 0);
        }
        Err(st) => {
            if ctx.trace || st == 0xC0000022u32 as i32 {
                eprintln!(
                    "[sbox-exec] {tag}: {st:#x} root={root_raw:#x} {leaf} access={access:#x}",
                );
            }
            ch.reply_fs(0, 0, st);
        }
    }
}

fn broker_open_handle(
    op: u64, leaf: &str, root: HANDLE, access: u32, opts: u32,
) -> std::result::Result<HANDLE, i32> {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtOpenKeyEx(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES, opts: u32) -> NTSTATUS;
        fn NtOpenSection(h: *mut HANDLE, access: u32,
            oa: *const OBJECT_ATTRIBUTES) -> NTSTATUS;
    }
    unsafe {
        let mut wleaf = wstr(leaf);
        if wleaf.last() == Some(&0) { wleaf.pop(); }
        let us = UNICODE_STRING {
            Length: (wleaf.len() * 2) as u16,
            MaximumLength: (wleaf.len() * 2) as u16,
            Buffer: PWSTR(wleaf.as_mut_ptr()),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: root,
            ObjectName: &us as *const _ as *mut _,
            Attributes: 0x40 /* OBJ_CASE_INSENSITIVE */,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut h = HANDLE::default();
        let st = if op == ipc::OP_NTOPENSECTION {
            NtOpenSection(&mut h, access, &oa)
        } else {
            NtOpenKeyEx(&mut h, access, &oa, opts)
        };
        if st.0 < 0 { Err(st.0) } else { Ok(h) }
    }
}

/// Read `OBJECT_ATTRIBUTES.{RootDirectory, ObjectName}` from
/// target memory without resolving the root to a path string.
fn read_target_oa_raw(target: HANDLE, oa_va: usize) -> Result<(u64, String)> {
    if oa_va == 0 { bail!("null OBJECT_ATTRIBUTES"); }
    #[repr(C)] #[derive(Clone, Copy)]
    struct ObjAttrs {
        length: u32, _pad: u32, root: u64, name: u64,
        attrs: u32, _pad2: u32, sd: u64, sqos: u64,
    }
    #[repr(C)] #[derive(Clone, Copy)]
    struct UStr { len: u16, max: u16, _pad: u32, buf: u64 }
    let oa: ObjAttrs = interception::read_remote(target, oa_va)?;
    let leaf = if oa.name == 0 {
        String::new()
    } else {
        let us: UStr = interception::read_remote(target, oa.name as usize)?;
        if us.len > 32768 { bail!("ObjectName length {}", us.len); }
        if us.len == 0 { String::new() }
        else { interception::read_remote_wstr(target, us.buf as usize, us.len as usize)? }
    };
    Ok((oa.root, leaf))
}

fn dup_from_target(target: HANDLE, raw: u64) -> Result<HANDLE> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let mut h = HANDLE::default();
        DuplicateHandle(
            target, HANDLE(raw as *mut c_void),
            GetCurrentProcess(), &mut h, 0, false, DUPLICATE_SAME_ACCESS,
        ).context("DuplicateHandle from target")?;
        Ok(h)
    }
}

/// Read `OBJECT_ATTRIBUTES.ObjectName` from target memory and
/// return the NT path. For `RootDirectory`-relative opens,
/// duplicates the root handle into the broker,
/// `GetFinalPathNameByHandle`s it, and returns
/// `\??\<root-dos-path>\<leaf>`.
fn read_target_obj_path(target: HANDLE, oa_va: usize) -> Result<String> {
    if oa_va == 0 { bail!("null OBJECT_ATTRIBUTES"); }
    #[repr(C)] #[derive(Clone, Copy)]
    struct ObjAttrs {
        length: u32, _pad: u32, root: u64, name: u64,
        attrs: u32, _pad2: u32, sd: u64, sqos: u64,
    }
    #[repr(C)] #[derive(Clone, Copy)]
    struct UStr { len: u16, max: u16, _pad: u32, buf: u64 }
    let oa: ObjAttrs = interception::read_remote(target, oa_va)?;
    let leaf = if oa.name == 0 {
        String::new()
    } else {
        let us: UStr = interception::read_remote(target, oa.name as usize)?;
        if us.len > 32768 { bail!("ObjectName length {}", us.len); }
        if us.len == 0 { String::new() }
        else { interception::read_remote_wstr(target, us.buf as usize, us.len as usize)? }
    };
    if oa.root == 0 {
        if leaf.is_empty() { bail!("null ObjectName"); }
        return Ok(leaf);
    }
    // Relative open: resolve the root directory's path. The root
    // handle was returned by an earlier brokered open, so it's a
    // value the broker put in the target's table; dup it back.
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    use windows::Win32::System::Threading::GetCurrentProcess;
    let root = unsafe {
        let mut h = HANDLE::default();
        DuplicateHandle(
            target, HANDLE(oa.root as *mut c_void),
            GetCurrentProcess(), &mut h, 0, false, DUPLICATE_SAME_ACCESS,
        ).context("dup RootDirectory")?;
        h
    };
    let mut buf = [0u16; 1024];
    let n = unsafe {
        GetFinalPathNameByHandleW(root, &mut buf,
            windows::Win32::Storage::FileSystem::FILE_NAME_NORMALIZED)
    };
    unsafe { let _ = CloseHandle(root); }
    if n == 0 || n as usize >= buf.len() {
        bail!("GetFinalPathNameByHandle on RootDirectory");
    }
    // Returns `\\?\C:\…`; convert to `\??\C:\…\<leaf>`.
    let dos = String::from_utf16_lossy(&buf[..n as usize]);
    let dos = dos.strip_prefix(r"\\?\").unwrap_or(&dos);
    if leaf.is_empty() {
        Ok(format!(r"\??\{dos}"))
    } else {
        Ok(format!(r"\??\{dos}\{leaf}"))
    }
}

/// Spawn `cmdline` under the same restricted+lowbox token + Job +
/// initial-impersonation recipe used for the immediate target,
/// forwarding the caller's console-related creation flags and
/// `STARTUPINFOW` (stdio handles already dup'd into the broker).
/// Returns SUSPENDED so the caller can install the hook first.
#[allow(clippy::too_many_arguments)]
fn broker_spawn(
    ctx: &SpawnCtx,
    app: Option<&str>,
    cmdline: &str,
    cwd: Option<&str>,
    caller_flags: u32,
    si: &STARTUPINFOW,
    envb: &mut Vec<u16>,
) -> Result<PROCESS_INFORMATION> {
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;
    use windows::Win32::System::Threading::PROCESS_CREATION_FLAGS;
    // Forward the flags that affect console/window behaviour and
    // priority; mask out the ones that would defeat brokering or
    // duplicate work the broker does itself. CREATE_SUSPENDED is
    // honoured by the entry-trampoline self-suspend, not here.
    const PASS_THROUGH: u32 =
        0x00000010 /* CREATE_NEW_CONSOLE */ |
        0x00000200 /* CREATE_NEW_PROCESS_GROUP */ |
        0x08000000 /* CREATE_NO_WINDOW */ |
        0x00000008 /* DETACHED_PROCESS */ |
        0x00040000 /* CREATE_PROTECTED_PROCESS — refused, but pass to surface error */ |
        0x00000020 | 0x00000040 | 0x00000080 | 0x00008000 |
        0x00000100 | 0x00100000; /* *_PRIORITY_CLASS */
    let fwd = PROCESS_CREATION_FLAGS(caller_flags & PASS_THROUGH);
    // The loader runs under the lowbox initial token (must
    // match the lowbox primary per SeTokenCanImpersonate), so it
    // can only read directories ACL'd for ALL APPLICATION
    // PACKAGES or the AC SID. Grant the AC SID + RESTRICTED on
    // the exe's directory so static-import DLLs alongside it
    // load. The grant is to a per-instance SID; the orphaned
    // ACE is inert once the AC profile is deleted.
    if let Some(app) = app {
        if let Some(dir) = std::path::Path::new(app).parent() {
            // `app` is sandboxed-caller-controlled. Gate the
            // grant on the same policy that gates brokered
            // reads so a confined process can't make the
            // broker ACL an arbitrary directory by passing it
            // as lpApplicationName. Only the AC SID is granted
            // (per-instance, inert once the profile is
            // deleted) — the loader runs under the *initial*
            // token whose restricting list already includes
            // the user SID, so the RESTRICTED grant isn't
            // needed here and would persist on disk.
            let nt = format!(r"\??\{}", dir.display());
            use crate::policy_engine::Decision;
            if matches!(ctx.fs.evaluate(&nt, 0x0001 /*FILE_READ_DATA*/),
                        Decision::Allow)
            {
                let _ = crate::acl::grant_oneshot(
                    &dir.to_string_lossy(), &ctx.ac_sid_string, READ_EXECUTE,
                );
            } else {
                eprintln!(
                    "[sbox-exec] broker_spawn: skip exe-dir grant on {} (policy deny)",
                    dir.display(),
                );
            }
        }
    }
    unsafe {
        let mut cmd = wstr(cmdline);
        let app_w = app.map(wstr);
        let app_p = app_w.as_ref().map(|w| pcwstr(w)).unwrap_or(PCWSTR::null());
        let cwd_w = wstr(cwd.unwrap_or(&ctx.cwd));
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessAsUserW(
            ctx.primary, app_p, PWSTR(cmd.as_mut_ptr()), None, None, true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | fwd,
            Some(envb.as_mut_ptr() as *mut c_void),
            PCWSTR(cwd_w.as_ptr()), si, &mut pi,
        ).with_context(|| format!("CreateProcessAsUserW(brokered, {cmdline})"))?;
        if let Err(e) = SetThreadToken(Some(&pi.hThread), ctx.initial) {
            eprintln!("[sbox-exec] broker_spawn: SetThreadToken: {e}");
        }
        AssignProcessToJobObject(ctx.job, pi.hProcess)
            .context("AssignProcessToJobObject(brokered)")?;
        let _ = ctx.ac_sid;
        Ok(pi)
    }
}

/// Read the caller's `STARTUPINFOW` from target memory and rebuild
/// it with stdio handles `DuplicateHandle`'d from the caller into
/// the broker (inheritable) so the brokered child inherits the
/// caller's redirections. String fields (lpDesktop/lpTitle) are
/// dropped — they reference caller-VA memory and would be invalid
/// in the broker; the broker's defaults apply instead.
fn read_target_startupinfo(target: HANDLE, va: usize) -> STARTUPINFOW {
    use windows::Win32::Foundation::DuplicateHandle;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, STARTF_USESTDHANDLES,
    };
    let mut out: STARTUPINFOW = unsafe { zeroed() };
    out.cb = size_of::<STARTUPINFOW>() as u32;
    if va == 0 { return out; }
    // STARTUPINFOW is the prefix of STARTUPINFOEXW; reading the W
    // size is safe regardless of which the caller passed.
    let theirs: STARTUPINFOW = match interception::read_remote(target, va) {
        Ok(s) => s, Err(_) => return out,
    };
    out.dwFlags = theirs.dwFlags;
    out.wShowWindow = theirs.wShowWindow;
    out.dwX = theirs.dwX; out.dwY = theirs.dwY;
    out.dwXSize = theirs.dwXSize; out.dwYSize = theirs.dwYSize;
    out.dwXCountChars = theirs.dwXCountChars;
    out.dwYCountChars = theirs.dwYCountChars;
    out.dwFillAttribute = theirs.dwFillAttribute;
    if theirs.dwFlags & STARTF_USESTDHANDLES != Default::default() {
        let dup = |h: HANDLE| -> HANDLE {
            if h.is_invalid() || h.0.is_null() { return h; }
            let mut o = HANDLE::default();
            unsafe {
                let _ = DuplicateHandle(
                    target, h, GetCurrentProcess(), &mut o,
                    0, true, windows::Win32::Foundation::DUPLICATE_SAME_ACCESS,
                );
            }
            o
        };
        out.hStdInput  = dup(theirs.hStdInput);
        out.hStdOutput = dup(theirs.hStdOutput);
        out.hStdError  = dup(theirs.hStdError);
    }
    out
}

fn close_si_handles(si: &STARTUPINFOW) {
    use windows::Win32::System::Threading::STARTF_USESTDHANDLES;
    if si.dwFlags & STARTF_USESTDHANDLES == Default::default() { return; }
    for h in [si.hStdInput, si.hStdOutput, si.hStdError] {
        if !h.is_invalid() && !h.0.is_null() {
            unsafe { let _ = CloseHandle(h); }
        }
    }
}

/// Read the environment block the brokered child should
/// inherit. If the caller passed `lpEnvironment` use that;
/// otherwise read the *caller*'s own environment from its
/// `PEB→ProcessParameters→Environment` so `set FOO=bar && child`
/// propagates. Falls back to the broker's env (with the policy
/// extras) on any failure.
fn read_target_env(
    target: HANDLE, lp_env: usize, caller_flags: u32, ctx: &SpawnCtx,
) -> Vec<u16> {
    let read_block = |va: usize, wide: bool| -> Option<Vec<u16>> {
        if va == 0 { return None; }
        let mut out = Vec::<u16>::new();
        let mut off = 0usize;
        loop {
            if wide {
                let chunk: [u16; 512] =
                    interception::read_remote(target, va + off * 2).ok()?;
                for (i, &w) in chunk.iter().enumerate() {
                    out.push(w);
                    if w == 0 && out.len() >= 2 && out[out.len() - 2] == 0 {
                        return Some(out);
                    }
                    if out.len() > 128 * 1024 { return None; }
                    let _ = i;
                }
                off += chunk.len();
            } else {
                let chunk: [u8; 1024] =
                    interception::read_remote(target, va + off).ok()?;
                for &b in &chunk {
                    out.push(b as u16);
                    if b == 0 && out.len() >= 2 && out[out.len() - 2] == 0 {
                        return Some(out);
                    }
                    if out.len() > 128 * 1024 { return None; }
                }
                off += chunk.len();
            }
        }
    };
    // Explicit lpEnvironment from the caller.
    if lp_env != 0 {
        let wide = caller_flags & 0x0000_0400 /* CREATE_UNICODE_ENVIRONMENT */ != 0;
        if let Some(b) = read_block(lp_env, wide) { return b; }
    }
    // Inherit from the caller: PEB→ProcessParameters→Environment.
    // PEB+0x20 = ProcessParameters; +0x80 = Environment (x64).
    let env = (|| -> Option<Vec<u16>> {
        use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
        use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
        let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
        let mut len = 0u32;
        let st = unsafe {
            NtQueryInformationProcess(
                target, PROCESSINFOCLASS(0),
                &mut pbi as *mut _ as *mut c_void,
                size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut len,
            )
        };
        if st.0 < 0 { return None; }
        let peb = pbi.PebBaseAddress as usize;
        let pp: u64 = interception::read_remote(target, peb + 0x20).ok()?;
        let envp: u64 = interception::read_remote(target, pp as usize + 0x80).ok()?;
        read_block(envp as usize, true)
    })();
    env.unwrap_or_else(|| build_env_block(&ctx.env))
}

/// Read a NUL-terminated wide string from `target` at `va`. Used
/// to read `lpApplicationName` / `lpCommandLine` /
/// `lpCurrentDirectory` from the hooked `CreateProcessInternalW`
/// call. Returns `Ok("")` for a null pointer.
fn read_target_wstr(target: HANDLE, va: usize) -> Result<String> {
    if va == 0 { return Ok(String::new()); }
    const MAX: usize = 32 * 1024;
    let mut buf = Vec::<u16>::new();
    let mut off = 0usize;
    while off < MAX {
        let chunk: [u16; 128] = interception::read_remote(target, va + off * 2)?;
        for &w in &chunk {
            if w == 0 { return Ok(String::from_utf16_lossy(&buf)); }
            buf.push(w);
        }
        off += chunk.len();
    }
    bail!("unterminated wstr at {va:#x}")
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

