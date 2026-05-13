//! Broker entry point: read marker, validate user + group state, build
//! the deny-only-group restricted token, generate the per-launch proxy
//! secret, spawn the target suspended, assign to job, start the proxy,
//! resume, wait for exit.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION,
    STARTUPINFOEXW, STARTUPINFOW,
};

// Process Creation Mitigation Policy bits (winnt.h). The windows-0.58
// crate exposes `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` but not the
// per-bit DWORD64 values — they're preprocessor macros in winnt.h, so
// we redefine them here. Encoding: each policy occupies a 4-bit slot
// in the u64; `..._ALWAYS_ON` flips the low bit of its slot.
//
// Layer 1 (Phase 4.5 v3): defense-in-depth mitigations that don't
// break Node/Python JIT (no ACG, no Microsoft-signed-only).
//
// `EXTENSION_POINT_DISABLE_ALWAYS_ON` — bit 32. Blocks legacy AppInit /
// IME / Winsock LSP DLLs from injecting into the child. Also blocks
// SetWindowsHookEx (covered by G5).
const PROC_MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 0x0000_0001 << 32;
// `IMAGE_LOAD_NO_REMOTE_ALWAYS_ON` — bit 52. Refuses LoadLibrary from
// UNC / network paths. The sandbox child should never DLL-load over
// SMB; this closes that path.
const PROC_MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 0x0000_0001 << 52;
// `IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON` — bit 56. Refuses LoadLibrary
// from any image whose mandatory label is Low IL. Stops a Low-IL
// attacker (e.g. another sandbox) from planting a DLL the child loads.
const PROC_MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 0x0000_0001 << 56;
// `IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON` — bit 60. Resolves DLL search
// order to System32 before the application directory. Defends against
// DLL-planting in the cwd / user-writable dirs.
const PROC_MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 0x0000_0001 << 60;
// `FONT_DISABLE_ALWAYS_ON` — bit 48. Blocks GDI from loading non-system
// fonts (a historic kernel-font parser RCE surface). Sandbox children
// run terminal / network workloads — no need for custom fonts.
const PROC_MITIGATION_FONT_DISABLE_ALWAYS_ON: u64 = 0x0000_0001 << 48;
// `CONTROL_FLOW_GUARD_ALWAYS_ON` — bit 8. Enforces CFG indirect-call
// checks for the child, even if the EXE wasn't CFG-instrumented at
// link time. Cheap if the binary already supports it.
const PROC_MITIGATION_CONTROL_FLOW_GUARD_ALWAYS_ON: u64 = 0x0000_0001 << 8;

use crate::job::Job;
use crate::policy::Policy;
use crate::sid::{self, GroupState};
use crate::token::{self, open_self_token, to_primary, LockdownSpec, IL_MEDIUM};
use crate::util::{pcwstr, wstr};
use crate::{proxy, wfp};

fn build_env(pol: &Policy, proxy_port: u16, secret: &str) -> Vec<u16> {
    let mut env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            !matches!(
                k.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        })
        .collect();
    // socks5h:// keeps DNS inside the proxy. User=secret, password=x
    // (proxy ignores password but RFC 1929 requires the field).
    let proxy_url = format!("socks5h://{secret}:x@127.0.0.1:{proxy_port}");
    env.insert("HTTP_PROXY".into(), proxy_url.clone());
    env.insert("HTTPS_PROXY".into(), proxy_url.clone());
    env.insert("ALL_PROXY".into(), proxy_url.clone());
    env.insert("NO_PROXY".into(), String::new());
    env.insert("http_proxy".into(), proxy_url.clone());
    env.insert("https_proxy".into(), proxy_url.clone());
    env.insert("all_proxy".into(), proxy_url.clone());
    env.insert("no_proxy".into(), String::new());

    // Surface the broker PID to the sandboxed child. Used by
    // `probe_proc.exe open-process <broker_pid>` test rows to verify
    // the broker-self-protection DACL actually blocks (Layer 5).
    env.insert(
        "WINSBOX_BROKER_PID".into(),
        std::process::id().to_string(),
    );

    for (k, v) in &pol.env_extra {
        env.insert(k.clone(), v.clone());
    }

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
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Quote an argument using cmd.exe's `/s /c` convention: wrap in outer
/// quotes (cmd's /s flag strips them), double any literal `"`, and
/// preserve everything else verbatim. Backslash escaping isn't honored
/// by cmd.exe's post-/c parser — that's the bug the CommandLineToArgvW
/// reverse in `quote_arg` walks into when the target is cmd.exe.
fn quote_arg_for_cmd(a: &str) -> String {
    let mut out = String::with_capacity(a.len() + 4);
    out.push('"');
    for c in a.chars() {
        if c == '"' {
            out.push('"');
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

/// True if `exe`'s file name is `cmd.exe` (case-insensitive). Used to
/// switch the trailing-arg quoting strategy.
fn target_is_cmd(exe: &std::path::Path) -> bool {
    exe.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.eq_ignore_ascii_case("cmd.exe"))
        .unwrap_or(false)
}

fn build_cmdline(exe: &std::path::Path, args: &[String]) -> String {
    // cmd.exe special-case: when invoked with `/c <cmd>` (or `/k`),
    // the post-/c arg is parsed by cmd's OWN /s-stripping rules, not by
    // CommandLineToArgvW. Use `quote_arg_for_cmd` for that single arg
    // so callers like `cmd /c 'echo "hi"'` survive the round-trip.
    let cmd_target = target_is_cmd(exe);
    let cmd_split = if cmd_target {
        args.iter().position(|a| {
            matches!(a.to_ascii_lowercase().as_str(), "/c" | "/k" | "/r")
        })
    } else {
        None
    };
    let mut s = quote_arg(&exe.display().to_string());
    for (i, a) in args.iter().enumerate() {
        s.push(' ');
        if cmd_split.map(|p| i > p).unwrap_or(false) {
            // Inside cmd.exe's post-/c command — cmd-style quoting.
            s.push_str(&quote_arg_for_cmd(a));
        } else {
            s.push_str(&quote_arg(a));
        }
    }
    s
}

/// Run a policy and return the child's exit code.
pub fn run(pol: &Policy) -> Result<u32> {
    // 1) Marker must be present.
    let marker = wfp::read_install_marker()
        .context("wfp::read_install_marker")?
        .ok_or_else(|| {
            anyhow!(
                "WFP filters not installed; run `sbox-exec install` as \
                 administrator"
            )
        })?;

    // 2) User SID match (single-user v1).
    let user_sid = sid::current_user_sid()?;
    if user_sid != marker.user_sid {
        return Err(anyhow!(
            "current user SID ({user_sid}) does not match marker user_sid ({}). \
             Re-run `sbox-exec install` as the intended user.",
            marker.user_sid
        ));
    }

    // 3) Group must be enabled in our TokenGroups; if it's absent the
    //    user hasn't logged out and back in yet. Hosted CI runners
    //    can't logout/login mid-job, so `WINSBOX_SKIP_GROUP_CHECK=1`
    //    downgrades the Absent case to a warning. The broker will
    //    still fail to *pass* its own outbound traffic through F1 in
    //    that state (egress tests B* will be red on CI) but the
    //    token-shape, deny-only-fence, and lifecycle rows can still
    //    run end-to-end. Don't ship this in a non-CI broker.
    let skip_group_check =
        std::env::var_os("WINSBOX_SKIP_GROUP_CHECK").is_some();
    match sid::group_state_for_self(&marker.group_sid)? {
        GroupState::Enabled => {}
        GroupState::Absent if skip_group_check => {
            eprintln!(
                "[sbox-exec] WARNING: winsbox-allowed group is absent from \
                 the current token but WINSBOX_SKIP_GROUP_CHECK is set; \
                 proceeding. Broker-side egress through the proxy will be \
                 blocked by F3 until logout/login refreshes TokenGroups."
            );
        }
        GroupState::Absent => {
            return Err(anyhow!(
                "winsbox-allowed group ({}) is not present in the current \
                 token. Log out and log back in to refresh TokenGroups, then \
                 retry. (`sbox-exec install --verify` confirms.) Set \
                 WINSBOX_SKIP_GROUP_CHECK=1 to bypass in CI.",
                marker.group_sid
            ));
        }
        GroupState::DenyOnly => {
            return Err(anyhow!(
                "winsbox-allowed group is already deny-only in the current \
                 token. This usually means the broker itself is running \
                 inside a sandbox child — refuse to launch."
            ));
        }
        GroupState::Present => {
            return Err(anyhow!(
                "winsbox-allowed group is present but neither enabled nor \
                 deny-only (unexpected token attribute state)."
            ));
        }
    }

    // 4) Token.
    let self_tok = open_self_token()?;
    let spec = LockdownSpec {
        sids_to_disable: vec![marker.group_sid.clone()],
    };
    let restricted = token::make_sandbox_token(self_tok, IL_MEDIUM, &spec)
        .context("make_sandbox_token")?;
    let primary = to_primary(restricted).context("to_primary")?;

    // 5) Job.
    let job = Job::new().context("Job::new")?;

    // 6) Per-launch proxy auth.
    let secret = proxy::generate_secret();

    // 7) Env block.
    let mut env = build_env(pol, marker.port, &secret);

    // 8) Command line.
    let cmdline = build_cmdline(&pol.target_exe, &pol.target_args);
    let mut cmdline_w = wstr(&cmdline);

    // 9) Working dir.
    let cwd_w: Option<Vec<u16>> = pol
        .cwd
        .as_ref()
        .map(|p| wstr(&p.display().to_string()));

    // 10) Application name = target_exe.
    let app_w = wstr(&pol.target_exe.display().to_string());

    // 10a) Build the PROC_THREAD_ATTRIBUTE_LIST with our mitigation
    //      policy bits. Layer 1 sets exactly one attribute; later
    //      layers (handle-list, etc.) add to this list.
    //
    // The attribute list is opaque (`LPPROC_THREAD_ATTRIBUTE_LIST`).
    // Allocate via the standard two-call pattern: probe for size, then
    // initialize into a pinned buffer. The buffer must outlive
    // CreateProcessAsUserW *and* the kernel's read of the policy DWORD64
    // (which happens during process creation, synchronously). The
    // `_attr_storage` Vec + `mitigation_policy` u64 below both live to
    // the end of the function — fine.
    const ATTR_COUNT: u32 = 1;
    // Selected for compat with msys2/cygwin's `dofork`. The two bits we
    // CANNOT enable without regressing E2/F6/F7 are:
    //   - `IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON` — flips DLL search-order
    //     so System32 wins over the EXE's directory. Breaks the
    //     cygwin1.dll / msys-2.0.dll resolution model.
    //   - `CONTROL_FLOW_GUARD_ALWAYS_ON` — forces CFG indirect-call
    //     checks even when the EXE wasn't built with `/guard:cf`. Stock
    //     mingw-built `bash.exe` (Git-for-Windows) isn't CFG-enabled, so
    //     `bash -c '...'` dies inside `dofork` with `STATUS_STACK_BUFFER_
    //     OVERRUN`-style fallout. We accept the residual CFG miss; it's
    //     a defense-in-depth nicety, not a primary boundary.
    let mitigation_policy: u64 = PROC_MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | PROC_MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
        | PROC_MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
        | PROC_MITIGATION_FONT_DISABLE_ALWAYS_ON;

    let mut attr_size: usize = 0;
    unsafe {
        // Probe call: returns ERROR_INSUFFICIENT_BUFFER + writes size.
        // We use the windows-rs wrapper which converts BOOL!=TRUE to
        // an Err — ignore the result, we only want `attr_size`.
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            ATTR_COUNT,
            0,
            &mut attr_size,
        );
    }
    let mut attr_storage: Vec<u8> = vec![0u8; attr_size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_storage.as_mut_ptr() as *mut c_void);
    unsafe {
        InitializeProcThreadAttributeList(attr_list, ATTR_COUNT, 0, &mut attr_size)
            .context("InitializeProcThreadAttributeList")?;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
            Some(&mitigation_policy as *const u64 as *const c_void),
            size_of::<u64>(),
            None,
            None,
        )
        .context("UpdateProcThreadAttribute(MITIGATION_POLICY)")?;
    }

    let mut six: STARTUPINFOEXW = unsafe { zeroed() };
    six.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    six.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let cwd_pcwstr = cwd_w
        .as_ref()
        .map(|v| pcwstr(v))
        .unwrap_or(windows::core::PCWSTR::null());

    unsafe {
        CreateProcessAsUserW(
            primary,
            pcwstr(&app_w),
            PWSTR(cmdline_w.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(env.as_mut_ptr() as *const c_void),
            cwd_pcwstr,
            // Pass the embedded STARTUPINFOW pointer; with
            // EXTENDED_STARTUPINFO_PRESENT the kernel reads past it to
            // recover the lpAttributeList. STARTUPINFOEXW is
            // layout-compatible (StartupInfo is first member).
            &six.StartupInfo as *const STARTUPINFOW,
            &mut pi,
        )
        .with_context(|| {
            format!("CreateProcessAsUserW({})", pol.target_exe.display())
        })?;
    }

    // 11) Assign to job.
    job.assign(pi.hProcess).context("AssignProcessToJobObject")?;

    // 12) Start proxy with the per-launch secret.
    let _proxy = proxy::start(
        marker.port,
        Box::new(proxy::DirectDialer),
        Some(secret),
    )
    .context("proxy::start")?;

    // 13) Resume.
    unsafe { ResumeThread(pi.hThread) };

    // 14) Wait.
    let rc = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    if rc != WAIT_OBJECT_0 {
        eprintln!(
            "[sbox-exec] WaitForSingleObject returned 0x{:x}",
            rc.0
        );
    }
    let mut code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut code).context("GetExitCodeProcess")?;
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(primary);
        let _ = CloseHandle(restricted);
        let _ = CloseHandle(self_tok);
        // Tear down the attribute list. Safe to call after the child
        // is created — kernel snapshots the policy at CreateProcess time.
        DeleteProcThreadAttributeList(attr_list);
    }
    // Keep attr_storage alive until after DeleteProcThreadAttributeList.
    drop(attr_storage);
    Ok(code)
}
