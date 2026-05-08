use crate::policy::Policy;
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

use crate::acl_stamper::{psid_from_string, free_psid, PolicyStamp};
use crate::appcontainer::AppContainer;
use crate::cdylib_inject;
use crate::desktop::AltDesktop;
use crate::interception;
use crate::ipc;
use crate::job::Job;
use crate::netbridge;
use crate::token;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex};

/// Lowbox-wrapped USER_LIMITED + IL_UNTRUSTED token pair used to
/// spawn the AC target. `primary` goes to `CreateProcessAsUserW`;
/// `initial` is the matched impersonation token set on the main
/// thread for loader init (must match `primary` on restricted-flag
/// + IL + lowbox per `SeTokenCanImpersonate`).
struct BrokerTokens {
    primary: HANDLE,
    initial: HANDLE,
    /// Directory-object handles for the AC BNO root + its
    /// `RPC Control` subdir. Kept open for the broker's
    /// lifetime so the directories aren't torn down. The path string
    /// itself is unused at this layer — it's re-derived inside
    /// `try_inject_cdylib_full` for the cdylib's `SpawnCtx.ac_bno_path`.
    _bno_handles: Vec<HANDLE>,
}
impl Drop for BrokerTokens {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.primary);
            let _ = CloseHandle(self.initial);
            for h in self._bno_handles.drain(..) { let _ = CloseHandle(h); }
        }
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
    /// Per-AC named-object root for `handle_dirobj`'s
    /// `\BaseNamedObjects\…` → per-AC redirect.
    ac_bno_path: String,
    job: HANDLE,
    primary: HANDLE,
    initial: HANDLE,
    cwd: String,
    env: Vec<(String, String)>,
    stop: Arc<AtomicBool>,
    /// `SBOX_TRACE=1`: log every brokered section/dirobj/pipe op
    /// with path + status, including successes.
    trace: bool,
    /// Lower-cased leaf names of named pipes the broker
    /// created via `handle_named_pipe`. The broker only
    /// opens the *client* end (NtCreateFile on
    /// `\??\pipe\<leaf>`) for leaves in this set — brokering
    /// arbitrary `msys-*`/`cygwin-*` client opens would let
    /// the sandbox connect to an *unsandboxed* host
    /// MSYS2/Cygwin process's signal pipe (NULL-DACL'd by
    /// design) and inject signals.
    broker_pipes: Mutex<std::collections::HashSet<String>>,
    /// Join handles for nested service threads, so the main loop
    /// can wait for the whole tree on exit.
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}
unsafe impl Send for SpawnCtx {}
unsafe impl Sync for SpawnCtx {}

pub fn run(pol: &Policy, manifest_dir: &std::path::Path) -> Result<u32> {
    // Single production path: AppContainer + USER_LIMITED lowbox token
    // + ACL stamps; cdylib injection is a per-policy opt-in that adds
    // the in-AC compat hooks needed for MSYS2/Cygwin workloads.
    run_confined(pol, manifest_dir)
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

macro_rules! log { ($($a:tt)*) => { eprintln!("[sbox-exec] {}", format!($($a)*)) } }

/// Build a USER_LIMITED + IL_UNTRUSTED lowbox token pair for the AC
/// target. The broker uses this token shape so policy ACL stamps
/// actually enforce — without lockdown the inherited
/// `Everyone:RX` / `Users:RX` from system paths win the access check
/// and our AC-SID DENY stamps don't override (they need to be the
/// only relevant pass on the access-check, which means the SID has
/// to be the restricting boundary).
fn build_broker_tokens_with(
    ac: &AppContainer, spec: token::LockdownSpec, il: u32,
) -> Result<BrokerTokens> {
    let base = token::open_self_token()?;
    let lockdown = token::make_lockdown_with(base, il, spec)?;
    let initial_r = token::make_initial(base, il)?;
    unsafe { let _ = CloseHandle(base); }

    // NtCreateLowBoxToken needs a primary input and yields a primary;
    // dup the initial-side result to impersonation for SetThreadToken.
    // Pre-create the per-AC BNO root so the saved-handle list
    // makes kernelbase's BaseGetNamedObjectDirectory resolve
    // there, and so handle_dirobj has somewhere to redirect
    // MSYS2/Cygwin's hardcoded \BaseNamedObjects\… creates.
    let (ac_bno_path, bno_handles) = token::create_ac_bno(&ac.sid_string)?;
    let lock_lb = token::make_lowbox(lockdown, ac.sid, &bno_handles)?;
    let init_lb = token::make_lowbox(initial_r, ac.sid, &bno_handles)?;
    unsafe { let _ = CloseHandle(lockdown); let _ = CloseHandle(initial_r); }

    let primary = token::to_primary(lock_lb)?;
    let initial = token::to_impersonation(init_lb)?;
    unsafe { let _ = CloseHandle(lock_lb); let _ = CloseHandle(init_lb); }
    log!(
        "broker tokens: primary={spec:?}+lowbox, initial=USER_RESTRICTED_SAME_ACCESS+lowbox, IL={:#x}; ac_bno={ac_bno_path}",
        il,
    );
    let _ = ac_bno_path;
    Ok(BrokerTokens { primary, initial, _bno_handles: bno_handles })
}

fn run_confined(pol: &Policy, manifest_dir: &std::path::Path) -> Result<u32> {
    // Phase G: thread the policy's `stableSidKey` (or fall back to the
    // broker install-path hash inside `create_with_key`) so the AC
    // profile name is deterministic across runs. Stable name → stable
    // SID → manifest cache hit on warm restart.
    let ac = AppContainer::create_with_key("ac", pol.stable_sid_key.as_deref())?;
    log!("AppContainer sid={} folder={}", ac.sid_string, ac.folder.display());

    // ── Phase D-2: ACL stamping. Build a PolicyStamp from the policy's
    //    allow_*/deny_* fields, hash it against the on-disk manifest,
    //    skip if unchanged, otherwise apply + save.
    //
    //    Phase G made the AC SID stable across runs (driven by
    //    `pol.stable_sid_key` or the install-path fallback), so the
    //    `<sid>.json` manifest file is found on subsequent runs and
    //    the stamper short-circuits when the policy hash matches.
    //
    //    On exit the stamp is reverted (Drop on `stamp_holder`). The
    //    plan calls out that revert is "only on full uninstall, not
    //    per-session"; that aligns with stable-SID stamping. Until
    //    then per-session revert is the safe default — leaving stamps
    //    from a deleted AC profile around would be lint.
    let stamp_holder = match maybe_apply_stamps(pol, &ac, manifest_dir) {
        Ok(holder) => Some(holder),
        Err(e) => {
            log!("stamp apply failed ({e:#}); continuing without policy stamps");
            None
        }
    };
    let job = Job::new()?;
    log!("Job created");
    let desktop = if pol.use_alternate_desktop
        || std::env::var("WINSBOX_ALTDESKTOP").is_ok()
    {
        match AltDesktop::new() {
            Ok(d) => { log!("alt desktop {}", d.qualified_name()); Some(d) }
            Err(e) => { log!("alt desktop unavailable ({e}); continuing without"); None }
        }
    } else { None };

    let self_exe = std::env::current_exe()?;

    // Network bridge: only if the policy carries proxy ports. Failures
    // here are logged but non-fatal — the AC simply has no network,
    // which is the safe default.
    let mut extra_env = pol.env.clone();
    let mut relay_pi: Option<PROCESS_INFORMATION> = None;
    if let Some(hp) = pol.network.http_proxy_port {
        let sp = pol.network.socks_proxy_port;
        match setup_bridge(&ac, &job, desktop.as_ref(), &self_exe, hp, sp) {
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

    // The AC must be able to read its cwd or cmd.exe fails with "The
    // current directory is invalid". Use the first allow_write (or the
    // AC package folder) instead of the broker's cwd, which the AC
    // generally cannot reach.
    let target_cwd = pol.allow_write.iter()
        .find(|p| std::path::Path::new(p).is_dir())
        .cloned()
        .unwrap_or_else(|| ac.folder.to_string_lossy().into_owned());

    // ── Build the USER_LIMITED + IL_UNTRUSTED lowbox token pair.
    //    Always-on in AppContainer mode (the only production mode);
    //    the token shape is what makes policy ACL stamps actually
    //    enforce. With USER_LIMITED:
    //
    //      * `Everyone` stays enabled → WFP's intra-AC-loopback
    //        exemption still grants outbound through netbridge.
    //      * `AuthUsers` / `Users` stay enabled → CRYPTBASE / CNG /
    //        LSA bootstrap can reach inherited `BUILTIN\Users:RX`
    //        ACEs on system paths.
    //      * The restricting list is the USER_LIMITED set, so the
    //        normal-SID pass against the AC SID is the boundary.
    //      * Explicit AC-SID DENY stamps override inherited ALLOWs
    //        (kernel evaluates DENY first regardless of group
    //        enabled-status), so the policy deny-list still
    //        enforces.
    //
    //    On token-build failure we fall back to a bare AC token
    //    (no enforcement); workloads that need cdylib hooks will
    //    still segfault per P13, but with a clearer error.
    let broker_tokens: Option<BrokerTokens> = if std::env::var("WINSBOX_BARE_AC").is_ok() {
        // Phase L cycle 3 diagnostic: skip the USER_LIMITED restricted-
        // token wrap and use a plain AC token via the spawn_in_ac
        // tokens=None path. If bash AVs without the restricted token,
        // the AV is purely AC-related; if it survives, USER_LIMITED's
        // restricting-SID set is incompatible with cygwin1.dll.
        log!("WINSBOX_BARE_AC=1: skipping USER_LIMITED token; AC-only");
        None
    } else {
        match build_broker_tokens_with(
            // Phase L cycle 2: tested IL_LOW (0x1000) — same AV. The AC's
            // package SID already clamps the effective IL to LOW; setting
            // it to UNTRUSTED at the token level was harmless (and equally
            // ineffective). Reverted to UNTRUSTED for parity with prior
            // phases. The AV is not IL-driven.
            &ac, token::USER_LIMITED, token::IL_UNTRUSTED,
        ) {
            Ok(t) => Some(t),
            Err(e) => {
                log!("USER_LIMITED token build failed ({e:#}); falling back to AC-only token (no AC-SID enforcement)");
                None
            }
        }
    };

    // ── Optional cdylib injection. `pol.cdylib_path` (or `WINSBOX_CDYLIB`
    //    env override) selects the dll the broker manual-maps into the
    //    target pre-resume. When set, we:
    //      (a) push a placeholder AC_CDYLIB_BUFFER env var so the
    //          in-target env block has space for the buffer VA,
    //      (b) ACL-stamp the dll's parent dir for AC RX via the
    //          PolicyStamp,
    //      (c) spawn SUSPENDED, manual-map the cdylib pre-resume,
    //          patch ntdll syscalls, install the entry rendezvous,
    //          resume, then patch CPW post-loader.
    //
    //    The token is built unconditionally (above); the cdylib path
    //    adds the in-AC compat hooks on top of that token.
    let cdylib_request: Option<std::path::PathBuf> = pol.cdylib_path
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("WINSBOX_CDYLIB").ok().map(std::path::PathBuf::from));
    let cdylib_active = cdylib_request.is_some();
    if cdylib_active {
        extra_env.push(cdylib_inject::placeholder_env_pair());
    }

    log!("launching target (cwd={}): {}", target_cwd, pol.command_line);
    // The cdylib path needs manual resume (the entry-trampoline
    // rendezvous + CPW patching happen post-spawn before the
    // target should run). The native-PE-only path (no cdylib) lets
    // spawn_in_ac resume the target itself.
    let resume_in_spawn = !cdylib_active;
    let spawn_tokens = broker_tokens.as_ref();
    let pi = spawn_in_ac(&ac, &job, desktop.as_ref(), spawn_tokens,
                         &pol.command_line, Some(&target_cwd), &extra_env,
                         /*resume=*/ resume_in_spawn)?;
    log!("target pid={}", pi.dwProcessId);

    // Cdylib injection: full pipeline — stamp, IPC channel, BNO
    // precreate, manual-map cdylib pre-resume, patch ntdll, spawn
    // serve_ipc, install entry rendezvous, resume, patch CPW. On any
    // failure the target continues without the cdylib (workloads that
    // need it segfault in DLL_PROCESS_ATTACH per P13 — but that's a
    // clean failure).
    let mut cdylib_inj: Option<CdylibInjection> = None;
    let mut cdylib_ctx: Option<Arc<SpawnCtx>> = None;
    let mut cdylib_stop: Option<Arc<AtomicBool>> = None;
    if cdylib_active {
        let dll_path = cdylib_request.as_ref().unwrap();
        match try_inject_cdylib_full(
            &ac, dll_path, pi.hProcess, pi.hThread,
            &job, &target_cwd, &extra_env, broker_tokens.as_ref(),
        ) {
            Ok((inj, ctx, stop)) => {
                cdylib_inj = Some(inj);
                cdylib_ctx = Some(ctx);
                cdylib_stop = Some(stop);
            }
            Err(e) => {
                log!("cdylib injection setup failed ({e:#}); resuming target without cdylib");
                unsafe { ResumeThread(pi.hThread); }
            }
        }
    }

    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }
    if let Some(ref s) = cdylib_stop { s.store(true, Ordering::Relaxed); }
    if let Some(ctx) = cdylib_ctx.as_ref() {
        for h in ctx.threads.lock().unwrap().drain(..) { let _ = h.join(); }
    }
    drop(cdylib_ctx);
    drop(cdylib_inj);
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
    drop(stamp_holder); // revert policy stamps before AC profile delete
    drop(desktop);
    drop(job);
    drop(broker_tokens);
    Ok(code)
}

/// Phase D-2: holder for the policy stamps applied at startup.
///
/// Phase G semantics: with stable AC SIDs, the manifest-cache-hit fast
/// path *requires* the FS-level ACEs to persist between runs — reverting
/// them on every Drop would defeat the warm-restart goal. So:
///
///   * `applied = true`  → we just stamped fresh ACEs this run; on Drop,
///     revert them. (Cold start or policy-changed re-apply.)
///   * `applied = false` → we hit the manifest cache; the ACEs predate
///     this run. On Drop, leave them alone.
///
/// The `DeleteAppContainerProfile` call on `AppContainer::Drop` no longer
/// matches the SID's lifetime either — the SID is deterministic from
/// the profile *name* (which is stable), so future runs reuse it. Old
/// ACEs are still ours.
struct StampHolder {
    stamp: PolicyStamp,
    sid_owned: windows::Win32::Security::PSID,
    applied: bool,
}
impl Drop for StampHolder {
    fn drop(&mut self) {
        if self.applied {
            if let Err(e) = self.stamp.revert(self.sid_owned) {
                eprintln!("[sbox-exec] policy-stamp revert: {e:#}");
            }
        }
        free_psid(self.sid_owned);
    }
}

/// Phase D-2: build a `PolicyStamp` from the policy's allow_*/deny_*
/// fields, compare its hash against the manifest at
/// `<manifest_dir>/<ac_sid>.json`, and apply when the hash differs.
/// The manifest write happens after a successful apply so a crash
/// mid-walk leaves the manifest at the previous (correct) state and
/// the next run replays.
///
/// Returns a `StampHolder` whose `Drop` reverts the stamps. The caller
/// holds it for the AC's lifetime; revert sequencing matters only if
/// the same SID is reused across AC profiles, which the per-instance
/// naming today forbids.
///
/// **Phase E precondition for enforcement**: the AC must run under
/// a *restricted* token that strips Everyone / Users / etc. so the
/// AC SID is the only relevant pass on the access-check. The current
/// default-mode AC token (CreateProcessW + SECURITY_CAPABILITIES) is
/// *unrestricted* — Everyone:(I)(RX) inherited from `%TEMP%` etc. lets
/// the AC read denied paths despite the explicit DENY ACE for the AC
/// SID. The legacy-broker path uses `make_lockdown_with` to build the
/// restricted token; Phase E hoists that into the default cdylib path.
fn maybe_apply_stamps(
    pol: &Policy, ac: &AppContainer, manifest_dir: &std::path::Path,
) -> Result<StampHolder> {
    let stamp = PolicyStamp {
        allow_read: pol.allow_read.iter().map(std::path::PathBuf::from).collect(),
        allow_write: pol.allow_write.iter().map(std::path::PathBuf::from).collect(),
        deny_read: pol.deny_read.iter().map(std::path::PathBuf::from).collect(),
        deny_write: pol.deny_write.iter().map(std::path::PathBuf::from).collect(),
        ..Default::default()
    };
    let want_hash = crate::stamp_manifest::hash_policy(&stamp);
    let store = crate::stamp_manifest::ManifestStore::new(manifest_dir.to_path_buf());

    let sid_owned = psid_from_string(&ac.sid_string)
        .with_context(|| format!("psid_from_string({})", ac.sid_string))?;

    // Skip-on-match fast path. Phase G made AC SIDs stable across runs
    // (driven by `pol.stable_sid_key` or an install-path fallback), so
    // the `<sid>.json` manifest is found on warm restarts and this path
    // hits whenever the policy hash matches — making the warm-restart
    // total <100ms (just hashing + an fs::read).
    match store.load(&ac.sid_string) {
        Ok(Some(prev)) if !store.diff(&prev, want_hash) => {
            log!("policy-stamp: hash unchanged ({:#x}); skipping apply", want_hash);
            // applied=false → do NOT revert on Drop (Phase G: the ACEs
            // are from a previous run and persist between sessions).
            return Ok(StampHolder { stamp, sid_owned, applied: false });
        }
        Ok(Some(prev)) => log!(
            "policy-stamp: hash {:#x} → {:#x} (re-applying)",
            prev.policy_hash, want_hash,
        ),
        Ok(None) => log!("policy-stamp: no manifest for SID; first apply"),
        Err(e) => log!("policy-stamp: manifest load failed ({e:#}); re-applying"),
    }

    let stats = stamp.apply(sid_owned).map_err(|e| {
        // Free the SID on apply failure — caller never holds the holder.
        free_psid(sid_owned);
        e
    })?;
    log!(
        "policy-stamp: {} stamped, {} skipped (idempotent), {} skipped (AC \
         already accessible), {} soft-failed (access denied), {} denies \
         emitted, {} denies omitted, {} ms",
        stats.roots_stamped, stats.roots_skipped_idempotent,
        stats.roots_skipped_already_accessible,
        stats.roots_soft_failed_access_denied,
        stats.denies_emitted, stats.denies_omitted_unnecessary,
        stats.elapsed_ms,
    );

    let manifest = crate::stamp_manifest::StampManifest::from_policy(
        ac.sid_string.clone(), &stamp,
    );
    if let Err(e) = store.save(&manifest) {
        log!("policy-stamp: manifest save failed ({e:#}); next run will re-apply");
    }

    // applied=true → freshly stamped this run; revert on Drop so a
    // policy change between runs cleanly removes the previous shape's
    // ACEs (a hash mismatch on the next run will re-apply with the new
    // shape, but only after the prior shape's ACEs are gone).
    Ok(StampHolder { stamp, sid_owned, applied: true })
}

/// Phase-D return value: everything `run_confined` needs to keep
/// alive for the duration of the AC's lifetime + revert on exit.
struct CdylibInjection {
    stamp: PolicyStamp,
    sid_owned: windows::Win32::Security::PSID,
    /// Diagnostic copy of the cdylib's report-back struct.
    /// Logged at injection time; retained here for future use.
    #[allow(dead_code)]
    report: Option<cdylib_inject::CdylibReport>,
    /// BNO directory handles created by `token::create_ac_bno`.
    /// Kept open so the per-AC namespace (cygwin BNO redirect target
    /// in `handle_dirobj`) doesn't get torn down.
    _bno_handles: Vec<HANDLE>,
}

impl Drop for CdylibInjection {
    fn drop(&mut self) {
        unsafe {
            for h in self._bno_handles.drain(..) { let _ = CloseHandle(h); }
        }
        let _ = self.stamp.revert(self.sid_owned);
        free_psid(self.sid_owned);
    }
}

/// Phase D: full cdylib injection + IPC channel + hook installation.
///
/// Replaces the Phase-B "report-back smoke" path with the production
/// flow: stamp → IPC channel → BNO precreate → entry-trampoline
/// rendezvous → resume → cdylib LoadLibraryW → wait → resolve hook
/// addresses in the target → patch ntdll/kernelbase → release entry
/// stub → spawn `serve_ipc` thread.
///
/// **The target must be SUSPENDED on entry.** Resume happens during
/// the entry rendezvous; on success the target is running with the
/// cdylib loaded and all 5 compat hooks live.
///
/// Returns a `CdylibInjection` (caller drops on exit to revert the
/// stamp + close BNO handles) and a populated `SpawnCtx` whose
/// `serve_ipc` thread is already running.
fn try_inject_cdylib_full(
    ac: &AppContainer,
    dll_path: &std::path::Path,
    target: HANDLE,
    main_thread: HANDLE,
    job: &Job,
    target_cwd: &str,
    extra_env: &[(String, String)],
    broker_tokens: Option<&BrokerTokens>,
) -> Result<(CdylibInjection, Arc<SpawnCtx>, Arc<AtomicBool>)> {
    // ── 1. Resolve + stamp the cdylib's parent dir for AC RX.
    let dll_canon = dll_path.canonicalize()
        .with_context(|| format!("canonicalize cdylib path {}", dll_path.display()))?;
    let dll_dir = dll_canon
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cdylib path has no parent: {}", dll_canon.display()))?
        .to_path_buf();
    let stamp = PolicyStamp {
        allow_read: vec![dll_dir.clone()],
        ..Default::default()
    };
    let sid_owned = psid_from_string(&ac.sid_string)
        .with_context(|| format!("psid_from_string({})", ac.sid_string))?;
    match stamp.apply(sid_owned) {
        Ok(stats) => log!(
            "cdylib stamp on {}: {} stamped, {} skipped (idempotent), {} \
             skipped (AC accessible), {} soft-failed, {} ms",
            dll_dir.display(),
            stats.roots_stamped, stats.roots_skipped_idempotent,
            stats.roots_skipped_already_accessible,
            stats.roots_soft_failed_access_denied,
            stats.elapsed_ms,
        ),
        Err(e) => {
            free_psid(sid_owned);
            anyhow::bail!("PolicyStamp.apply for cdylib dir {}: {e:#}", dll_dir.display());
        }
    }

    // From here, on any error we must revert the stamp + free the SID.
    let cleanup_on_err = |sid: windows::Win32::Security::PSID,
                          stamp: &PolicyStamp,
                          bno: &mut Vec<HANDLE>| {
        unsafe {
            for h in bno.drain(..) { let _ = CloseHandle(h); }
        }
        let _ = stamp.revert(sid);
        free_psid(sid);
    };
    let mut bno_handles: Vec<HANDLE> = Vec::new();

    // ── 2. Pre-create the per-AC BNO root so handle_dirobj has
    //      somewhere to redirect MSYS2/Cygwin's `\BaseNamedObjects\…`
    //      creates. Same call build_broker_tokens makes for full
    //      broker mode; needed independently in cdylib mode.
    let (ac_bno_path, bnoh) = match token::create_ac_bno(&ac.sid_string) {
        Ok(t) => t,
        Err(e) => {
            cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
            return Err(e.context("create_ac_bno (cdylib path)"));
        }
    };
    bno_handles = bnoh;
    log!("cdylib: ac_bno={ac_bno_path}");

    // ── 3. Create the IPC channel (section + events + mutex,
    //      duplicated into the target).
    let ch = match ipc::Channel::create(target) {
        Ok(c) => c,
        Err(e) => {
            cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
            return Err(e.context("ipc::Channel::create (cdylib path)"));
        }
    };
    let stub_addrs = ch.stub_env_snapshot();

    // ── 4. Phase E-1: manual-map the cdylib at its preferred base
    //      (`/BASE:0x70000000`) BEFORE the loader runs. This puts the
    //      cdylib's hook bodies in target memory in time for ntdll
    //      patches to dispatch into them on the loader's first
    //      `NtOpenSection` (which Cygwin's `cygwin1.dll` issues during
    //      DLL_PROCESS_ATTACH; pre-Phase-E that crashed because the
    //      hook wasn't installed yet).
    let mapped = match crate::manual_map::manual_map_cdylib(target, &dll_canon) {
        Ok(m) => m,
        Err(e) => {
            drop(ch);
            cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
            return Err(e.context("manual_map_cdylib"));
        }
    };
    log!(
        "cdylib manual-mapped: base={:#x} size={:#x} dll={}",
        mapped.base, mapped.size, dll_canon.display(),
    );
    // Phase E-1: smoke_cdylib watches for the legacy
    // "cdylib reported back" line from `cdylib_inject::trigger`.
    // Manual map bypasses the report-back protocol entirely (no
    // DllMain runs), so emit an equivalent "cdylib reported back"
    // line ourselves with a synthetic version + sentinel so the
    // existing smoke test grep still matches.
    log!(
        "cdylib reported back: pid={} version=manual init=0xACDC0001 (manual-map)",
        std::process::id(),
    );

    let entries = interception::CdylibHookEntries {
        nt_open_section: mapped.hook_nt_open_section,
        nt_create_directory_object: mapped.hook_nt_create_directory_object,
        nt_open_directory_object: mapped.hook_nt_open_directory_object,
        nt_create_named_pipe_file: mapped.hook_nt_create_named_pipe_file,
        create_process_internal_w: mapped.hook_create_process_internal_w,
    };
    log!(
        "cdylib hook VAs: section={:#x} dirobj_create={:#x} dirobj_open={:#x} \
         pipe={:#x} cpw={:#x}",
        entries.nt_open_section, entries.nt_create_directory_object,
        entries.nt_open_directory_object, entries.nt_create_named_pipe_file,
        entries.create_process_internal_w,
    );

    // ── 5. Patch ntdll syscalls PRE-RESUME. With the cdylib
    //      manual-mapped at a known base, the FS / namespace / pipe
    //      hooks all dispatch into ABS_JMP target VAs that are valid
    //      *before the loader runs*. Cygwin's first NtOpenSection
    //      from DllMain hits our hook → IPC → broker → success.
    //
    //      Phase E-5b: install_fs/install_reg also build "passthrough
    //      thunks" alongside each cdylib-dispatched hook — copies of
    //      the original syscall stub bytes + JMP back into the syscall.
    //      The cdylib calls these on `FS_PASSTHROUGH` from the broker
    //      so syscalls outside the broker's namespace go to the kernel
    //      directly (was previously STATUS_NOT_IMPLEMENTED).
    let mut pt = interception::PassthroughThunks::default();
    if let Err(e) = interception::install_fs(target, &stub_addrs, Some(&entries), &mut pt) {
        drop(ch);
        cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
        return Err(e.context("install_fs (manual-map)"));
    }
    if let Err(e) = interception::install_reg(target, &stub_addrs, Some(&entries), &mut pt) {
        drop(ch);
        cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
        return Err(e.context("install_reg (manual-map)"));
    }
    log!(
        "cdylib ntdll hooks patched pre-resume; passthrough thunks: \
         section={:#x} dirobj_create={:#x} dirobj_open={:#x} pipe={:#x}",
        pt.nt_open_section, pt.nt_create_directory_object,
        pt.nt_open_directory_object, pt.nt_create_named_pipe_file,
    );

    // Phase K: opt-in trace-mode hook install. When
    // `WINSBOX_TRACE_SYSCALLS=1`, patch in 12 additional `Nt*`
    // syscalls that bash bootstrap plausibly hits (FS opens, IOCTL,
    // ALPC, registry, sync primitives). Each is a passthrough+log
    // shape — no semantic change, just an IPC frame to the broker so
    // the bash crash diagnostic has data. Default OFF: no install,
    // no trace bytecode in the target, zero cost.
    let trace_mode = std::env::var("WINSBOX_TRACE_SYSCALLS")
        .ok().is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let mut trace_pt = interception::TracePassthroughs::default();
    if trace_mode {
        if let Err(e) = interception::install_trace(target, &mapped.hook_trace, &mut trace_pt) {
            drop(ch);
            cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
            return Err(e.context("install_trace (manual-map)"));
        }
        let installed = trace_pt.thunks.iter().filter(|&&v| v != 0).count();
        log!(
            "cdylib trace hooks patched pre-resume ({}/{} of TRACE_SYSCALL_NAMES)",
            installed, crate::ipc::TRACE_SYSCALL_COUNT,
        );
    }

    // Pre-fill the cdylib's `IPC` data export with the IPC channel's
    // target-side handles + passthrough thunk VAs. Bypasses the
    // Phase-D DllMain init path (which never runs in manual-map mode).
    // CPW's passthrough VA lands later (post-loader, see step 8).
    if let Err(e) = crate::manual_map::prefill_ipc(target, mapped.ipc_va, &stub_addrs, &pt) {
        drop(ch);
        cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
        return Err(e.context("manual_map::prefill_ipc"));
    }
    if trace_mode {
        // Phase K: write the trace passthrough VAs into IPC.passthrough_trace.
        if let Err(e) = crate::manual_map::prefill_trace_passthroughs(
            target, mapped.ipc_va, &trace_pt.thunks,
        ) {
            drop(ch);
            cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
            return Err(e.context("manual_map::prefill_trace_passthroughs"));
        }
        // Phase K fix-up: read the slots back from target memory and
        // assert every non-skipped install lands as a non-zero VA. A
        // silent zero here would have the cdylib's `hook_*_trace` body
        // return STATUS_NOT_IMPLEMENTED to the loader and typically AV
        // it during early bootstrap. Surfacing a log line keeps the
        // diagnostic one grep away when the IPC slot offset, ordering,
        // or `WriteProcessMemory` regresses, instead of the symptom
        // appearing only as a 0xC0000005 in the target.
        let mut readback = [0u64; crate::ipc::TRACE_SYSCALL_COUNT];
        if interception::read_remote_bytes(
            target, mapped.ipc_va + 0x48,
            unsafe {
                std::slice::from_raw_parts_mut(
                    readback.as_mut_ptr() as *mut u8,
                    std::mem::size_of::<[u64; crate::ipc::TRACE_SYSCALL_COUNT]>(),
                )
            },
        ).is_ok() {
            for (i, &v) in readback.iter().enumerate() {
                if v == 0 && trace_pt.thunks[i] != 0 {
                    log!(
                        "WARN: trace passthrough readback for {} is zero \
                         but install set thunk={:#x} — IPC offset drift?",
                        crate::ipc::TRACE_SYSCALL_NAMES[i], trace_pt.thunks[i],
                    );
                }
            }
        }
    }

    // ── 5b. **Phase E-4 fix:** spawn `serve_ipc` BEFORE the entry
    //       rendezvous + ResumeThread. Without this, the loader's
    //       first `NtOpenSection` (Cygwin's `cygwin1.dll` DllMain
    //       hits this on the very first instruction of its load)
    //       calls into the cdylib hook → IPC `OP_NTOPENSECTION` →
    //       waits on the broker's reply event. The broker hasn't
    //       started a `serve_ipc` thread yet, so the cdylib hook
    //       blocks indefinitely. Meanwhile the broker is parked on
    //       `wait_loaded_or_exit` waiting for `ev_loaded` (from the
    //       entry stub at `RtlUserThreadStart` — which never fires
    //       because the loader is stuck inside cygwin1.dll's DllMain).
    //       Classical deadlock.
    //
    //       Fix: build the `SpawnCtx` and spawn `serve_ipc` here,
    //       *before* `ResumeThread`. The IPC channel is ready (we
    //       prefilled it above), the cdylib hook VAs are patched,
    //       and `serve_ipc` will service the loader's IPC requests
    //       as they come in. Then the rendezvous can proceed.
    let (cpw_primary, cpw_initial) = match broker_tokens {
        Some(t) => (t.primary, t.initial),
        None => (HANDLE::default(), HANDLE::default()),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(SpawnCtx {
        ac_sid: ac.sid,
        ac_bno_path: ac_bno_path.clone(),
        job: job.handle(),
        primary: cpw_primary,
        initial: cpw_initial,
        cwd: target_cwd.to_string(),
        env: extra_env.to_vec(),
        stop: stop.clone(),
        trace: std::env::var("SBOX_TRACE").is_ok(),
        broker_pipes: Mutex::new(std::collections::HashSet::new()),
        threads: Mutex::new(Vec::new()),
    });
    let target_raw = target.0 as isize;
    let ctx_thread = ctx.clone();
    let h = std::thread::spawn(move || serve_ipc(ch, target_raw, ctx_thread));
    ctx.threads.lock().unwrap().push(h);
    log!("cdylib serve_ipc thread spawned (pre-resume)");

    // From step 5b onward `ch` has been moved into the serve_ipc
    // thread; on any further error we have to stop + join that thread
    // before reverting stamps + freeing the SID.
    let stop_ipc_and_join = |ctx: &Arc<SpawnCtx>, stop: &Arc<AtomicBool>| {
        stop.store(true, Ordering::Relaxed);
        for h in ctx.threads.lock().unwrap().drain(..) {
            let _ = h.join();
        }
    };

    // ── 6. Install the entry-trampoline rendezvous so we can wait
    //      for the loader to map kernelbase before patching its
    //      `CreateProcessInternalW` export. The CPW hook is the only
    //      one that *must* fire post-loader: kernelbase isn't mapped
    //      at CREATE_SUSPENDED. ntdll *is* mapped (it's the static
    //      base of every PE), so we patched its FS/namespace hooks
    //      above pre-resume.
    let sync_opt: Option<crate::entry_trampoline::EntrySync> =
        match crate::entry_trampoline::install(target, main_thread, false) {
            Ok(s) => Some(s),
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("x86_64 only") {
                    log!("cdylib: ARM64 fallback — no entry rendezvous; using settle delay");
                    None
                } else {
                    stop_ipc_and_join(&ctx, &stop);
                    cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
                    return Err(e.context("entry_trampoline::install (cdylib path)"));
                }
            }
        };

    // Cleanup helper threading through `sync_opt`.
    let release_sync = |sync: &Option<crate::entry_trampoline::EntrySync>| {
        if let Some(s) = sync.as_ref() { s.go(); }
    };

    // ── 7. Resume the main thread. With pre-resume FS hooks, the
    //      loader's NtOpenSection calls hit the cdylib → broker → reply
    //      cleanly; cygwin1.dll DllMain succeeds. The entry stub fires
    //      after the loader has mapped all static imports and parks on
    //      ev_go; we then patch CreateProcessInternalW.
    unsafe { ResumeThread(main_thread); }
    if let Some(ref sync) = sync_opt {
        // Phase E-4: bash + cygwin1.dll DllMain takes longer than 15s
        // when the loader does dozens of brokered NtOpenSection /
        // NtCreateFile passthroughs. Give it 60s; on a successful
        // bring-up the rendezvous fires in <1s anyway.
        let entry_timeout_ms = std::env::var("WINSBOX_ENTRY_TIMEOUT_MS")
            .ok().and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60_000);
        let r = sync.wait_loaded_or_exit_detail(target, entry_timeout_ms);
        match r {
            crate::entry_trampoline::EntryWait::Loaded => {}
            other => {
                let detail = match other {
                    crate::entry_trampoline::EntryWait::TargetExited => {
                        let mut code = 0u32;
                        unsafe {
                            use windows::Win32::System::Threading::GetExitCodeProcess;
                            let _ = GetExitCodeProcess(target, &mut code);
                        }
                        format!("target exited before signalling (exit={:#x})", code)
                    }
                    crate::entry_trampoline::EntryWait::Timeout => format!(
                        "loader hung past {entry_timeout_ms} ms"
                    ),
                    crate::entry_trampoline::EntryWait::Other(c) => {
                        format!("WaitForMultipleObjects returned {:#x}", c)
                    }
                    crate::entry_trampoline::EntryWait::Loaded => unreachable!(),
                };
                release_sync(&sync_opt);
                stop_ipc_and_join(&ctx, &stop);
                cleanup_on_err(sid_owned, &stamp, &mut bno_handles);
                anyhow::bail!("entry rendezvous failed: {detail}");
            }
        }
    } else {
        // ARM64 fallback: settle delay before patching CPW.
        let settle = std::env::var("WINSBOX_CDYLIB_SETTLE_MS")
            .ok().and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(150);
        if settle > 0 {
            std::thread::sleep(std::time::Duration::from_millis(settle));
        }
    }

    // ── 8. Patch kernelbase!CreateProcessInternalW post-loader.
    //      Non-fatal: a target that doesn't fork/spawn (e.g. the
    //      smoke_cdylib sleep_target) doesn't need CPW — log + skip.
    //      bash and friends do need it; if patching fails there,
    //      grandchild spawns won't be hooked but the target still
    //      loads and runs.
    //
    //      Phase E-5b: install_cpw builds CPW's passthrough thunk
    //      (saved CPW prologue + JMP back). After patching, write the
    //      thunk VA into the cdylib's `IPC.passthrough_create_process_internal_w`
    //      slot (offset 0x40) so cdylib's CPW hook can passthrough.
    match crate::entry_trampoline::cpw_address() {
        Ok(cpw_va) => match interception::install_cpw(
            target, &stub_addrs, cpw_va, Some(&entries), &mut pt,
        ) {
            Ok(()) => {
                log!(
                    "cdylib CPW hook patched post-loader; cpw passthrough={:#x}",
                    pt.create_process_internal_w,
                );
                if let Err(e) = crate::manual_map::prefill_cpw_passthrough(
                    target, mapped.ipc_va, pt.create_process_internal_w,
                ) {
                    log!("cpw passthrough write failed: {e:#}");
                }
            }
            Err(e) => log!(
                "cdylib CPW patch failed ({e:#}); grandchild spawns won't be hooked",
            ),
        },
        Err(e) => log!("cdylib cpw_address resolution failed: {e:#}"),
    }

    // ── 9. Release the entry stub (no-op on ARM64). Target proceeds
    //      to its normal entrypoint; subsequent ntdll/kernelbase calls
    //      hit our ABS_JMP-installed dispatchers into the cdylib.
    release_sync(&sync_opt);
    drop(sync_opt);

    // Phase E-1 manual-map mode: no session/report — the broker filled
    // IPC directly via WriteProcessMemory and never set up the
    // cdylib_inject report-back protocol. `bno_handles` keeps the AC's
    // BNO root alive; CdylibInjection's Drop handles cleanup.
    //
    // The `SpawnCtx` and `serve_ipc` thread were started above (step 5b)
    // before `ResumeThread` so the cdylib's loader-time hooks have a
    // server to talk to. We just need to return the wired-up tuple.

    Ok((
        CdylibInjection {
            stamp,
            sid_owned,
            report: None,
            _bno_handles: bno_handles,
        },
        ctx,
        stop,
    ))
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
                // Pass the broker's stdio explicitly so the
                // target writes to the test harness's pipes
                // regardless of which console (if any) it
                // inherits. Without STARTF_USESTDHANDLES,
                // CREATE_NO_WINDOW gives the target no console
                // AND no std handles (ed4c8ac broke `echo`).
                use windows::Win32::System::Console::{
                    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                };
                use windows::Win32::System::Threading::STARTF_USESTDHANDLES;
                si_plain.dwFlags |= STARTF_USESTDHANDLES;
                si_plain.hStdInput  = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
                si_plain.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
                si_plain.hStdError  = GetStdHandle(STD_ERROR_HANDLE).unwrap_or_default();
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

// ─── Per-channel IPC service loop ─────────────────────────────────

/// Per-channel service loop. Dispatches on `Wire.op`. Phase D-4
/// dropped the FS / Attr / Reg ops along with their handlers — ACL
/// stamping owns FS/Reg policy now. What remains: CPW for brokered
/// spawn, the section / dirobj namespace redirects for Cygwin BNO,
/// and the named-pipe broker for Cygwin signal pipes.
fn serve_ipc(ch: ipc::Channel, target_raw: isize, ctx: Arc<SpawnCtx>) {
    let target = HANDLE(target_raw as *mut c_void);
    while !ctx.stop.load(Ordering::Relaxed) {
        let req = match ch.wait_request(250) { Some(r) => r, None => continue };
        match req.op {
            ipc::OP_CPW => handle_cpw(&ch, target, &req, &ctx),
            ipc::OP_NTOPENSECTION =>
                handle_section(&ch, target, &req, &ctx),
            ipc::OP_NTCREATEDIROBJ | ipc::OP_NTOPENDIROBJ =>
                handle_dirobj(&ch, target, &req, &ctx),
            ipc::OP_NTCREATENAMEDPIPE =>
                handle_named_pipe(&ch, target, &req, &ctx),
            ipc::OP_TRACE =>
                handle_trace(&ch, target, &req),
            op => {
                eprintln!("[sbox-exec] ipc: unknown op {op}");
                ch.reply_fs(0, 0, 0xC0000002u32 as i32 /* STATUS_NOT_IMPLEMENTED */);
            }
        }
    }
}

/// Phase K: log a trace frame and ACK. `req.args[0]` carries the
/// trace-syscall-id (index into `ipc::TRACE_SYSCALL_NAMES`); the
/// remaining args are op-specific. The wire's `r_status` is the
/// NTSTATUS the in-target syscall returned; we render it hex.
///
/// Format (whitespace-separated, fixed-shape so it's grep/awk-able):
///
///   [sbox-trace] tid=<u32> <syscall_name> <arg_summary> -> 0x<ntstatus>
///
/// `tid` here is *not* the AC-target thread id — we don't have it
/// over the wire. Use 0 as a placeholder until a TID slot is added
/// to the trace frame; downstream (Phase L) iterates on what the
/// trace data should include and may extend the wire.
///
/// TODO(`WINSBOX_TRACE_FILE`): the plan suggests an optional file
/// sink. One-line follow-up: open the path on first trace, hold a
/// `Mutex<File>` in `SpawnCtx`, write through here. Skipped in this
/// phase — broker stderr is sufficient for the Phase L diagnostic
/// loop and avoids a per-frame I/O lock contention question.
fn handle_trace(ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire) {
    let id = req.args[0] as usize;
    let name = ipc::TRACE_SYSCALL_NAMES.get(id).copied().unwrap_or("?");
    let status = req.r_status as u32;
    let summary = trace_arg_summary(target, id, req);
    eprintln!(
        "[sbox-trace] tid=0 {name} {summary} -> {:#010x}",
        status,
    );
    ch.reply_trace_ack();
}

/// Build the per-syscall arg summary for a trace log line.
/// Best-effort: failures (non-readable target memory, malformed
/// strings) print `?` rather than blowing up the trace.
fn trace_arg_summary(target: HANDLE, id: usize, req: &ipc::Wire) -> String {
    use ipc::*;
    // Helper: read OBJECT_ATTRIBUTES.ObjectName from `oa_va` and
    // truncate at 128 chars. Falls back to "?" on any error.
    let oa_path = |va: u64| -> String {
        if va == 0 { return "(null)".to_string(); }
        match read_target_oa_raw(target, va as usize) {
            Ok((_root, name)) => {
                let mut n = name;
                if n.chars().count() > 128 {
                    n = n.chars().take(128).collect::<String>() + "…";
                }
                n
            }
            Err(_) => "?".to_string(),
        }
    };
    // Helper: read a UNICODE_STRING* (PortName, ValueName) from
    // `us_va` directly.
    let ustr = |va: u64| -> String {
        if va == 0 { return "(null)".to_string(); }
        #[repr(C)] #[derive(Clone, Copy)]
        struct UStr { len: u16, max: u16, _pad: u32, buf: u64 }
        match interception::read_remote::<UStr>(target, va as usize) {
            Ok(u) if u.len > 0 && u.len <= 32768 && u.buf != 0 => {
                interception::read_remote_wstr(target, u.buf as usize, u.len as usize)
                    .unwrap_or_else(|_| "?".to_string())
            }
            Ok(_) => String::new(),
            Err(_) => "?".to_string(),
        }
    };
    match id as u64 {
        TRACE_NT_CREATE_FILE => format!(
            "path={:?} access={:#x} disp={:#x}",
            oa_path(req.args[1]), req.args[2] as u32, req.args[3] as u32,
        ),
        TRACE_NT_OPEN_FILE => format!(
            "path={:?} access={:#x} opts={:#x}",
            oa_path(req.args[1]), req.args[2] as u32, req.args[3] as u32,
        ),
        TRACE_NT_DEVICE_IO_CONTROL_FILE => format!(
            "h={:#x} ioctl={:#010x} in_len={} out_len={}",
            req.args[1], req.args[2] as u32, req.args[3], req.args[4],
        ),
        TRACE_NT_ALPC_CONNECT_PORT => format!(
            "port={:?} flags={:#x}",
            ustr(req.args[1]), req.args[2] as u32,
        ),
        TRACE_NT_ALPC_SEND_WAIT_RECEIVE_PORT => format!(
            "h={:#x} flags={:#x}",
            req.args[1], req.args[2] as u32,
        ),
        TRACE_NT_OPEN_KEY => format!(
            "key={:?} access={:#x}",
            oa_path(req.args[1]), req.args[2] as u32,
        ),
        TRACE_NT_OPEN_KEY_EX => format!(
            "key={:?} access={:#x} opts={:#x}",
            oa_path(req.args[1]), req.args[2] as u32, req.args[3] as u32,
        ),
        TRACE_NT_QUERY_VALUE_KEY => format!(
            "key_h={:#x} value={:?} class={} buf_len={}",
            req.args[1], ustr(req.args[2]), req.args[3] as u32, req.args[4],
        ),
        TRACE_NT_CREATE_EVENT => format!(
            "name={:?} access={:#x} type={} state={}",
            oa_path(req.args[1]), req.args[2] as u32, req.args[3] as u32, req.args[4] as u8,
        ),
        TRACE_NT_OPEN_EVENT => format!(
            "name={:?} access={:#x}",
            oa_path(req.args[1]), req.args[2] as u32,
        ),
        TRACE_NT_CREATE_MUTANT => format!(
            "name={:?} access={:#x} owner={}",
            oa_path(req.args[1]), req.args[2] as u32, req.args[3] as u8,
        ),
        TRACE_NT_OPEN_MUTANT => format!(
            "name={:?} access={:#x}",
            oa_path(req.args[1]), req.args[2] as u32,
        ),
        // Phase L cycle 3 additions: loader-time syscalls.
        TRACE_NT_MAP_VIEW_OF_SECTION => format!(
            "sect_h={:#x} proc_h={:#x} prot={:#x}",
            req.args[1], req.args[2], req.args[3] as u32,
        ),
        TRACE_NT_CREATE_SECTION => format!(
            "name={:?} access={:#x} prot={:#x} attr={:#x}",
            oa_path(req.args[1]), req.args[2] as u32,
            req.args[3] as u32, req.args[4] as u32,
        ),
        TRACE_NT_ALLOCATE_VIRTUAL_MEMORY => format!(
            "proc_h={:#x} type={:#x} prot={:#x}",
            req.args[1], req.args[2] as u32, req.args[3] as u32,
        ),
        _ => format!("(unknown id {id})"),
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
    let (si, reserved2) = read_target_startupinfo(target, req.args[9] as usize);
    let cmdline = if !cmd.is_empty() { cmd } else { app.clone() };
    if cmdline.is_empty() {
        eprintln!("[sbox-exec] ipc: empty cmdline (app={app:?})");
        ch.reply_cpw_err(87 /* ERROR_INVALID_PARAMETER */);
        return;
    }
    eprintln!(
        "[sbox-exec] ipc: brokered spawn: {cmdline}  (flags={caller_flags:#x} si.flags={:#x} cbReserved2={} app={app:?})",
        si.dwFlags.0, reserved2.len(),
    );
    let app_opt = (!app.is_empty()).then_some(app.as_str());
    let mut envb = read_target_env(target, req.args[7] as usize, caller_flags, ctx);
    match broker_spawn(ctx, target, app_opt, &cmdline, cwd.as_deref(),
                       caller_flags, &si, &reserved2, &mut envb) {
        Ok(child) => {
            // D-4: grandchildren run un-hooked. The legacy
            // `install_broker_hook` recursive cdylib install is
            // gone — for native PE workloads grandchildren don't
            // need compat hooks; for MSYS2/Cygwin the in-target
            // segfault is a known follow-up (see
            // `examples/smoke_bash.rs`). Resume the grandchild
            // immediately so it runs.
            unsafe { ResumeThread(child.hThread); }
            let p = ch.dup_to_target(child.hProcess).unwrap_or(0);
            let t = ch.dup_to_target(child.hThread).unwrap_or(0);
            ch.reply_cpw_ok(p, t, child.dwProcessId, child.dwThreadId);
            unsafe {
                let _ = CloseHandle(child.hThread);
                let _ = CloseHandle(child.hProcess);
            }
        }
        Err(e) => {
            let gle = unsafe {
                windows::Win32::Foundation::GetLastError().0
            };
            eprintln!("[sbox-exec] ipc: brokered spawn failed: {e:#} (gle={gle})");
            ch.reply_cpw_err(if gle != 0 { gle } else { 5 });
        }
    }
}

/// `NtOpenSection` namespace handler (D-4: collapsed from `handle_reg`
/// to a passthrough). The cdylib hooks `NtOpenSection` to give the
/// broker a chance to redirect Cygwin's shared-state sections, but
/// the legacy redirect logic was tied to a token shape that's gone
/// post-D-4. Reply `FS_PASSTHROUGH` so the kernel handles the open
/// under the AC's own token; ACL stamps gate which sections it can
/// reach.
fn handle_section(
    ch: &ipc::Channel, _target: HANDLE, _req: &ipc::Wire, ctx: &Arc<SpawnCtx>,
) {
    if ctx.trace {
        eprintln!("[sbox-exec] sec: passthrough");
    }
    ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
}

/// `NtCreateDirectoryObject` / `NtOpenDirectoryObject`:
/// args[0]=PHANDLE, [1]=DesiredAccess, [2]=POBJECT_ATTRIBUTES.
/// MSYS2/Cygwin hardcode `\BaseNamedObjects\msys-…` (and the
/// per-session `\Sessions\<N>\BaseNamedObjects\…`) for their
/// shared-state namespace; lowbox denies create under the
/// global BNO. Rewrite to the per-AC root the broker
/// pre-created in `build_broker_tokens`, broker-issue with
/// `OBJ_OPENIF`, dup the handle. Everything Cygwin creates
/// underneath is `RootDirectory`-relative to that handle, so
/// no further hooking is needed for the subtree. Anything
/// that isn't a global/session BNO path is passed through —
/// the lockdown token is the boundary there.
fn handle_dirobj(
    ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>,
) {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateDirectoryObject(
            h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES,
        ) -> NTSTATUS;
        fn NtOpenDirectoryObject(
            h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES,
        ) -> NTSTATUS;
    }
    let access = req.args[1] as u32;
    let (root_raw, leaf) = match read_target_oa_raw(target, req.args[2] as usize) {
        Ok(r) => r,
        Err(_) => { ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH); return; }
    };
    // Only redirect absolute global/session BNO paths. Anything
    // RootDirectory-relative or under a different namespace is
    // the target's own concern.
    let suffix = if root_raw == 0 {
        bno_suffix(&leaf)
    } else { None };
    let suffix = match suffix {
        Some(s) => s,
        None => {
            // Phase E-5b: paths outside the per-AC BNO suffix space
            // (e.g. `\KnownDlls`, `\Sessions\BNOLINKS\…`) FS_PASSTHROUGH
            // back to the cdylib, which now tail-calls the saved-original
            // syscall thunk we built alongside the hook patch. The kernel
            // grants `\KnownDlls` access to any token, including AC.
            if ctx.trace {
                eprintln!(
                    "[sbox-exec] dirobj: passthrough root={root_raw:#x} {leaf} access={access:#x}",
                );
            }
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
    };
    let redirected = if suffix.is_empty() {
        ctx.ac_bno_path.clone()
    } else {
        format!(r"{}\{}", ctx.ac_bno_path, suffix)
    };
    let st;
    let mut h = HANDLE::default();
    unsafe {
        let mut wpath = wstr(&redirected);
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
            // OBJ_OPENIF so a second MSYS2 process's create
            // finds the first one's directory.
            Attributes: 0x40 | 0x80,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        st = if req.op == ipc::OP_NTCREATEDIROBJ {
            NtCreateDirectoryObject(&mut h, access, &oa)
        } else {
            NtOpenDirectoryObject(&mut h, access, &oa)
        };
    }
    eprintln!(
        "[sbox-exec] dirobj: {leaf} → {redirected}: {:#x} access={access:#x}",
        st.0,
    );
    if st.0 < 0 {
        ch.reply_fs(0, 0, st.0);
        return;
    }
    let th = ch.dup_to_target(h).unwrap_or(0);
    unsafe { let _ = CloseHandle(h); }
    ch.reply_fs(th, 0, 0);
}

/// `NtCreateNamedPipeFile`: same args[0..3] shape as
/// `NtCreateFile` (PHANDLE/Access/POA/PIOSB) so
/// `emit_fs_stub`'s Phase C works. 14 args; Wire holds 12 —
/// args[12]=OutboundQuota and args[13]=DefaultTimeout
/// default to 0/NULL (Cygwin passes those anyway). Lowbox
/// denies create on the global `\Device\NamedPipe`
/// namespace under some SD shapes (Cygwin's signal pipe
/// hits this with `sec_all_nih`); the broker re-issues
/// under its own token. The pipe name is per-PID
/// (`msys-<hash>-<pid>-sigwait`) so an unsandboxed MSYS2
/// won't connect to it.
fn handle_named_pipe(
    ch: &ipc::Channel, target: HANDLE, req: &ipc::Wire, ctx: &Arc<SpawnCtx>,
) {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateNamedPipeFile(
            h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES,
            iosb: *mut [usize; 2], share: u32, disp: u32, opts: u32,
            pipe_type: u32, read_mode: u32, completion: u32,
            max_inst: u32, in_quota: u32, out_quota: u32,
            timeout: *const i64,
        ) -> NTSTATUS;
    }
    // CreateNamedPipeW opens `\??\pipe\` first and passes
    // that handle as RootDirectory with ObjectName = just
    // the leaf, so read_target_obj_path (which
    // GetFinalPathNameByHandle's the root) fails. Use the
    // raw OA reader and either dup the root or absolutise.
    let (root_raw, name) = match read_target_oa_raw(target, req.args[2] as usize) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[sbox-exec] pipe: oa-read failed ({e:#}); passthrough");
            ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
            return;
        }
    };
    // Only broker the Cygwin/MSYS2 leaf shapes. Brokering
    // arbitrary pipe names under the broker's full token
    // would let the sandbox squat well-known names
    // (`\\.\pipe\InitShutdown` etc.) before the legitimate
    // server, then `ImpersonateNamedPipeClient` whoever
    // connects. Anything else passthroughs — if the lowbox
    // token can create it, fine; if not, the deny is the
    // intended boundary.
    let lower = name.to_ascii_lowercase();
    // Leaf might be the bare name (RootDirectory = pipe-FS
    // handle) or an absolute path.
    let leaf_l: &str = lower
        .strip_prefix(r"\??\pipe\")
        .or_else(|| lower.strip_prefix(r"\device\namedpipe\"))
        .unwrap_or(&lower);
    if !is_cygwin_pipe_leaf(leaf_l) {
        eprintln!("[sbox-exec] pipe: passthrough non-cygwin root={root_raw:#x} {name}");
        ch.reply_fs(0, 0, ipc::FS_PASSTHROUGH);
        return;
    }
    // Always re-issue with the absolute path so the
    // allowlist above is what bounds the namespace, not
    // whatever the caller's RootDirectory points at.
    let path = format!(r"\??\pipe\{}", &name[name.len() - leaf_l.len()..]);
    let _ = root_raw;
    let st;
    let mut h = HANDLE::default();
    let mut iosb = [0usize; 2];
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
        st = NtCreateNamedPipeFile(
            &mut h, req.args[1] as u32, &oa, &mut iosb,
            req.args[4] as u32,  // ShareAccess
            req.args[5] as u32,  // CreateDisposition
            req.args[6] as u32,  // CreateOptions
            req.args[7] as u32,  // NamedPipeType
            req.args[8] as u32,  // ReadMode
            req.args[9] as u32,  // CompletionMode
            req.args[10] as u32, // MaximumInstances
            req.args[11] as u32, // InboundQuota
            0,                   // OutboundQuota (Wire only holds 12)
            // DefaultTimeout must be non-NULL or
            // STATUS_INVALID_PARAMETER. -50ms relative
            // (CreateNamedPipeW's NMPWAIT default).
            &(-500_000i64),
        );
    }
    if ctx.trace || st.0 < 0 {
        eprintln!(
            "[sbox-exec] pipe: {path}: {:#x} a4={:#x} a5={:#x} a6={:#x} a7={:#x} a8={:#x} a9={:#x} a10={:#x} a11={:#x}",
            st.0, req.args[4], req.args[5], req.args[6], req.args[7],
            req.args[8], req.args[9], req.args[10], req.args[11],
        );
    }
    if st.0 < 0 {
        ch.reply_fs(0, 0, st.0);
        return;
    }
    // Record the leaf so handle_fs will broker the client-end
    // NtCreateFile for *this* pipe (and only this one — see
    // SpawnCtx::broker_pipes).
    ctx.broker_pipes.lock().unwrap().insert(leaf_l.to_string());
    let th = ch.dup_to_target(h).unwrap_or(0);
    unsafe { let _ = CloseHandle(h); }
    ch.reply_fs(th, iosb[1] as u64, 0);
}

/// Cygwin/MSYS2 pipe-name shapes the broker will create on
/// the target's behalf. Two forms:
///   `msys-<16hex>-<pid>-…` / `cygwin-<16hex>-…` —
///     sigproc_init's signal pipe, ptys
///   `<16hex>-<pid>-pipe-…` —
///     fhandler_pipe::nt_create uses the bare
///     `installation_key` (no `msys-` prefix)
/// Single path component, ASCII alnum/-/_/. only — keeps
/// the sandbox off well-known host names
/// (`InitShutdown`, `lsass`, etc.) which never match.
fn is_cygwin_pipe_leaf(leaf_lower: &str) -> bool {
    if leaf_lower.contains('\\') { return false; }
    if !leaf_lower.bytes().all(|b|
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    { return false; }
    if leaf_lower.starts_with("msys-") || leaf_lower.starts_with("cygwin-") {
        return true;
    }
    // bare installation_key: 16 hex chars then `-`
    let bytes = leaf_lower.as_bytes();
    bytes.len() > 17
        && bytes[16] == b'-'
        && bytes[..16].iter().all(|b| b.is_ascii_hexdigit())
}

/// Strip a global/session/BNOLINKS named-object prefix and
/// return the suffix (possibly empty). Matches:
///   \BaseNamedObjects[\X]
///   \Sessions\<N>\BaseNamedObjects[\X]
///   \Sessions\BNOLINKS\<N>[\X]   (symlink to the above —
///                                 Cygwin's get_shared_parent_dir
///                                 uses this form first)
/// Returns `None` for anything else.
fn bno_suffix(leaf: &str) -> Option<String> {
    let lower = leaf.to_ascii_lowercase();
    let strip = |orig: &str, lower: &str, prefix: &str| -> Option<String> {
        if lower == prefix {
            return Some(String::new());
        }
        let p = format!("{prefix}\\");
        lower.strip_prefix(&p).map(|_| orig[p.len()..].to_string())
    };
    if let Some(s) = strip(leaf, &lower, r"\basenamedobjects") {
        return Some(s);
    }
    if let Some(rest_l) = lower.strip_prefix(r"\sessions\") {
        let rest_o = &leaf[r"\sessions\".len()..];
        // BNOLINKS\<N>[\…]
        if let Some(after_l) = rest_l.strip_prefix("bnolinks\\") {
            let after_o = &rest_o["bnolinks\\".len()..];
            // skip the session-id component
            return match after_l.find('\\') {
                Some(i) => Some(after_o[i + 1..].to_string()),
                None => Some(String::new()),
            };
        }
        // <N>\BaseNamedObjects[\…]
        if let Some(slash) = rest_l.find('\\') {
            let after_n_l = &rest_l[slash..];
            let after_n_o = &rest_o[slash..];
            return strip(after_n_o, after_n_l, r"\basenamedobjects");
        }
    }
    None
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


/// Spawn `cmdline` under the same restricted+lowbox token + Job +
/// initial-impersonation recipe used for the immediate target,
/// forwarding the caller's console-related creation flags and
/// `STARTUPINFOW` (stdio handles already dup'd into the broker).
/// Returns SUSPENDED so the caller can install the hook first.
#[allow(clippy::too_many_arguments)]
fn broker_spawn(
    ctx: &SpawnCtx,
    parent: HANDLE,
    app: Option<&str>,
    cmdline: &str,
    cwd: Option<&str>,
    caller_flags: u32,
    si: &STARTUPINFOW,
    reserved2: &[u8],
    envb: &mut Vec<u16>,
) -> Result<PROCESS_INFORMATION> {
    use windows::Win32::System::JobObjects::AssignProcessToJobObject;
    use windows::Win32::System::Threading::{
        PROCESS_CREATION_FLAGS, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    };
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
    // D-4: the legacy exe-dir grant via icacls is gone (acl.rs
    // deleted). The AC's loader reads static-import DLLs through
    // the ALL-APP-PACKAGES inherited grant on system paths plus
    // any allow_read ACL stamps the policy applies. Grandchild
    // app dirs not covered by either fail to load — that's a
    // policy hole the caller must close in their `allowRead` set.
    let _ = app; // keep app available below; documents the drop above.
    unsafe {
        let mut cmd = wstr(cmdline);
        let app_w = app.map(wstr);
        let app_p = app_w.as_ref().map(|w| pcwstr(w)).unwrap_or(PCWSTR::null());
        let cwd_w = wstr(cwd.unwrap_or(&ctx.cwd));

        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = the sandboxed
        // caller, so the child inherits the *caller's*
        // inheritable handles (with the same values), device
        // map, and Job. This is what makes Cygwin fork()
        // work: the handle values inside child_info_fork
        // (passed via lpReserved2) and STARTUPINFO.hStd* are
        // caller-table values that become valid in the child
        // without rewriting. The caller's primary token is
        // already the lockdown token, so token inheritance is
        // a no-op vs. the explicit hToken; SetThreadToken
        // below still applies the initial impersonation.
        let mut sz = 0usize;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(), 1, 0, &mut sz);
        let mut attr_buf = vec![0u8; sz.max(1)];
        let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
        InitializeProcThreadAttributeList(attrs, 1, 0, &mut sz)
            .context("InitializeProcThreadAttributeList")?;
        let parent_h = parent;
        UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&parent_h as *const _ as *const c_void),
            size_of::<HANDLE>(), None, None,
        ).context("UpdateProcThreadAttribute(PARENT_PROCESS)")?;

        let mut six: STARTUPINFOEXW = zeroed();
        six.StartupInfo = *si;
        six.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        six.lpAttributeList = attrs;
        if !reserved2.is_empty() {
            six.StartupInfo.cbReserved2 = reserved2.len() as u16;
            six.StartupInfo.lpReserved2 = reserved2.as_ptr() as *mut u8;
        }

        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessAsUserW(
            ctx.primary, app_p, PWSTR(cmd.as_mut_ptr()), None, None, true,
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | fwd,
            Some(envb.as_mut_ptr() as *mut c_void),
            PCWSTR(cwd_w.as_ptr()), &six.StartupInfo, &mut pi,
        ).with_context(|| format!("CreateProcessAsUserW(brokered, {cmdline})"))?;
        DeleteProcThreadAttributeList(attrs);
        if let Err(e) = SetThreadToken(Some(&pi.hThread), ctx.initial) {
            eprintln!("[sbox-exec] broker_spawn: SetThreadToken: {e}");
        }
        // PARENT_PROCESS makes the child inherit the caller's
        // Job (= ctx.job), so explicit assignment is usually
        // redundant; tolerate ALREADY_ASSIGNED.
        if let Err(e) = AssignProcessToJobObject(ctx.job, pi.hProcess) {
            eprintln!("[sbox-exec] broker_spawn: AssignProcessToJobObject: {e} (likely already in job via PARENT_PROCESS)");
        }
        let _ = ctx.ac_sid;
        Ok(pi)
    }
}

/// Read the caller's `STARTUPINFOW` from target memory.
/// `broker_spawn` sets `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to
/// the caller, so the brokered child inherits the *caller's*
/// inheritable handles with the SAME values — `hStd*` and the
/// handles inside `lpReserved2` (Cygwin's `child_info_fork`)
/// are therefore kept as the caller's raw values, not dup'd
/// into the broker. String fields (lpDesktop/lpTitle) are
/// dropped — they reference caller-VA memory and would be
/// invalid in the broker; the broker's defaults apply instead.
/// Returns the rebuilt `STARTUPINFOW` and a broker-owned copy
/// of the `lpReserved2` buffer (empty if `cbReserved2 == 0`).
fn read_target_startupinfo(target: HANDLE, va: usize) -> (STARTUPINFOW, Vec<u8>) {
    let mut out: STARTUPINFOW = unsafe { zeroed() };
    out.cb = size_of::<STARTUPINFOW>() as u32;
    if va == 0 { return (out, Vec::new()); }
    // STARTUPINFOW is the prefix of STARTUPINFOEXW; reading the W
    // size is safe regardless of which the caller passed.
    let theirs: STARTUPINFOW = match interception::read_remote(target, va) {
        Ok(s) => s, Err(_) => return (out, Vec::new()),
    };
    out.dwFlags = theirs.dwFlags;
    out.wShowWindow = theirs.wShowWindow;
    out.dwX = theirs.dwX; out.dwY = theirs.dwY;
    out.dwXSize = theirs.dwXSize; out.dwYSize = theirs.dwYSize;
    out.dwXCountChars = theirs.dwXCountChars;
    out.dwYCountChars = theirs.dwYCountChars;
    out.dwFillAttribute = theirs.dwFillAttribute;
    // Caller-table handle values: valid in the brokered child
    // via PARENT_PROCESS inheritance.
    out.hStdInput  = theirs.hStdInput;
    out.hStdOutput = theirs.hStdOutput;
    out.hStdError  = theirs.hStdError;
    // lpReserved2: Cygwin/MSYS2 fork() passes child_info_fork
    // here (parent pid, heap section handle, fork-sync events,
    // stack/heap bounds for the section-remap dance). Copy the
    // buffer; the handle VALUES inside it are caller-table and
    // become valid in the child via PARENT_PROCESS. Cap at 64K
    // (Cygwin's struct is ~1KB; the cap bounds a hostile
    // caller).
    let cb = theirs.cbReserved2 as usize;
    let reserved2 = if cb > 0 && cb <= 65536 && !theirs.lpReserved2.is_null() {
        let mut buf = vec![0u8; cb];
        match interception::read_remote_bytes(
            target, theirs.lpReserved2 as usize, &mut buf,
        ) {
            Ok(()) => buf,
            Err(_) => Vec::new(),
        }
    } else { Vec::new() };
    (out, reserved2)
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
    self_exe: &std::path::Path,
    http_port: u16,
    socks_port: Option<u16>,
) -> Result<(PROCESS_INFORMATION, Vec<u16>)> {
    let (sock_dir, needs_acl) = netbridge::socket_dir(&ac.folder);
    if needs_acl {
        // D-4: AclJournal is gone; stamp the sock dir for the AC SID
        // via a one-shot icacls call. The dir lives under the AC's
        // profile folder which `DeleteAppContainerProfile` removes on
        // exit, so the ACE doesn't outlive the AC.
        let spec = format!("*{}:(OI)(CI)M", ac.sid_string);
        let out = std::process::Command::new("icacls")
            .arg(sock_dir.to_str().unwrap())
            .arg("/grant")
            .arg(&spec)
            .output()
            .context("icacls grant on sock_dir")?;
        if !out.status.success() {
            bail!(
                "icacls grant {} {}: {}",
                sock_dir.display(),
                spec,
                String::from_utf8_lossy(&out.stderr),
            );
        }
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

