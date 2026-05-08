//! Phase-B cdylib injection into a suspended AppContainer target.
//!
//! Productionised version of the B0 spike (`bin/spike_inject.rs`):
//! same protocol (anonymous section + event + env-var pointer +
//! remote `LoadLibraryW`) factored into a function the broker can
//! call from `launch.rs`. Defers the ARM64 entry-trampoline rework
//! to Phase C — Phase B uses the spike's CreateRemoteThread+settle
//! pattern, which is arch-independent.
//!
//! Caller responsibilities (in `launch.rs::run_confined`):
//!   * Spawn the target SUSPENDED with the cdylib placeholder env
//!     var pre-set (see [`patch_env_for_buffer`]).
//!   * ACL-stamp the cdylib's parent directory for the AC SID via
//!     Phase A's `acl_stamper::PolicyStamp` so `LoadLibraryW` can
//!     map it. (Done by the caller, not us.)
//!   * Call [`prepare`] before [`ResumeThread`] to allocate the
//!     buffer + patch the env block.
//!   * Resume the main thread.
//!   * Call [`trigger`] after the target has had a moment to settle
//!     (the loader needs to map kernel32 before remote LoadLibraryW
//!     can resolve). 150 ms is empirical from B0; the wake event
//!     gives a tighter bound on success — we only pay the timeout
//!     on failure.
//!
//! This module is **not** wired into the broker-mode (recursive hook
//! install) spawn flow yet. Phase C extends the entry-trampoline
//! rendezvous to also LoadLibrary the cdylib in-thread, removing the
//! CreateRemoteThread + settle dependency.

#![cfg(windows)]

use crate::ipc;
use crate::util::wstr;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, HANDLE,
    INVALID_HANDLE_VALUE, NTSTATUS, WAIT_OBJECT_0,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAllocEx,
    FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MEM_COMMIT, MEM_RESERVE,
    PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess,
    LPTHREAD_START_ROUTINE, PROCESS_BASIC_INFORMATION, WaitForSingleObject,
};

/// Env-var key used to pass the in-target VA of the [`CdylibBuffer`]
/// into `DllMain`. Must match `crates/ac-cdylib/src/lib.rs`.
pub const ENV_KEY: &str = "AC_CDYLIB_BUFFER";

/// 16-char hex placeholder the broker stamps into the env BEFORE
/// CreateProcess. Post-spawn we overwrite these 16 wide chars
/// in-place (so the buffer pointer arrives without any env-block
/// resize). Use a recognisable but invalid pointer pattern so a
/// botched patch is obvious.
pub const ENV_PLACEHOLDER: &str = "0000000000000000";

/// Layout MUST match `crates/ac-cdylib/src/lib.rs::CdylibBuffer`.
/// Phase C added the trailing IPC fields so the cdylib's hook bodies
/// can do their own IPC frame writes (no inline-asm stub in target
/// memory). All zero is permitted for Phase-B-style smoke runs that
/// don't enable any hooks.
#[repr(C)]
struct CdylibBuffer {
    section: u64,
    event: u64,
    view: u64,
    magic: u64,
    /// IPC section VA in the target's address space (one Wire-sized
    /// shared region; see `crate::ipc::Wire`).
    ipc_section: u64,
    /// Target-side handles for the IPC events + mutex.
    ipc_ev_req: u64,
    ipc_ev_resp: u64,
    ipc_mutex: u64,
}
const CDYLIB_MAGIC: u64 = 0xAC11_DEAD_BEEF_CAFEu64;

/// Layout MUST match `crates/ac-cdylib/src/lib.rs::CdylibResult`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CdylibReport {
    pub init_result: u32,
    pub version: u32,
    pub sentinel: u32,
    pub pid: u32,
}
/// Sentinel value the cdylib stamps into [`CdylibReport::sentinel`].
pub const RESULT_SENTINEL: u32 = 0xACDC_BABE;
/// Expected `cdylib_init()` return.
pub const CDYLIB_INIT_OK: u32 = 0xACDC_0001;

/// Locator: returns the absolute, canonical path to `ac_cdylib.dll`
/// considering, in order:
///   1. `WINSBOX_CDYLIB` (env-var override)
///   2. `ac_cdylib.dll` next to the running broker exe
///   3. `<exe-dir>/../release/ac_cdylib.dll` for `cargo run` / debug builds
///   4. `$CARGO_TARGET_DIR/release/ac_cdylib.dll`
pub fn locate_cdylib() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("WINSBOX_CDYLIB") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb.canonicalize().unwrap_or(pb));
        }
        bail!("WINSBOX_CDYLIB={pb:?} does not exist");
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let exe_dir = exe.parent().ok_or_else(|| anyhow!("exe has no parent"))?;
    let mut candidates: Vec<PathBuf> = vec![
        exe_dir.join("ac_cdylib.dll"),
    ];
    if let Some(p) = exe_dir.parent() {
        candidates.push(p.join("release").join("ac_cdylib.dll"));
    }
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(Path::new(&td).join("release").join("ac_cdylib.dll"));
    }
    for c in &candidates {
        if c.exists() {
            return Ok(c.canonicalize().unwrap_or_else(|_| c.clone()));
        }
    }
    bail!(
        "ac_cdylib.dll not found; build with `cargo build -p ac-cdylib --release`. \
         Searched: {candidates:#?}"
    )
}

/// State that survives between [`prepare`] and [`trigger`]. The
/// caller must keep this alive until trigger returns; the Drop impl
/// closes broker-side handles and unmaps the local view.
pub struct CdylibSession {
    /// Broker-side section handle (anonymous file mapping).
    section: HANDLE,
    /// Local mapped view; result struct lives here.
    view_local: MEMORY_MAPPED_VIEW_ADDRESS,
    /// Broker-side wake event; cdylib `SetEvent`s the duplicated
    /// target-side handle.
    event: HANDLE,
    /// In-target VA of the [`CdylibBuffer`].
    buf_va: usize,
    /// In-target VA where the cdylib path's UTF-16 string lives;
    /// passed to `LoadLibraryW` as its lpLibFileName arg.
    dll_path_va: *mut c_void,
    /// Path being injected (logged on failure).
    dll_path: PathBuf,
}

unsafe impl Send for CdylibSession {}

impl Drop for CdylibSession {
    fn drop(&mut self) {
        unsafe {
            if !self.view_local.Value.is_null() {
                let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view_local.Value,
                });
            }
            if !self.section.is_invalid() {
                let _ = CloseHandle(self.section);
            }
            if !self.event.is_invalid() {
                let _ = CloseHandle(self.event);
            }
            // dll_path_va is in the target's address space; no
            // explicit free — it's released when the target exits.
        }
    }
}

impl CdylibSession {
    /// Read the cdylib's report-back struct from the mapped view.
    pub fn read_report(&self) -> CdylibReport {
        unsafe {
            std::ptr::read_volatile(self.view_local.Value as *const CdylibReport)
        }
    }

    /// Validate a freshly-read report: sentinel + init_result match
    /// the constants the cdylib stamps. Returns `Ok(report)` on
    /// success or a descriptive error on mismatch.
    pub fn verify_report(&self) -> Result<CdylibReport> {
        let r = self.read_report();
        if r.sentinel != RESULT_SENTINEL {
            bail!(
                "cdylib report sentinel mismatch (got {:#x}, want {:#x})",
                r.sentinel, RESULT_SENTINEL,
            );
        }
        if r.init_result != CDYLIB_INIT_OK {
            bail!(
                "cdylib_init returned {:#x}, want {:#x}",
                r.init_result, CDYLIB_INIT_OK,
            );
        }
        Ok(r)
    }

    /// Broker-side wake event. Used by callers that orchestrate the
    /// entry-trampoline rendezvous themselves (Phase D) — they need
    /// to wait on this event after dispatching the LoadLibraryW
    /// remote thread, separately from `trigger`'s integrated wait.
    pub fn wake_event(&self) -> HANDLE { self.event }

    /// In-target VA of the staged dll-path string. Used as the arg
    /// to `LoadLibraryW` when the caller dispatches its own remote
    /// thread.
    pub fn dll_path_va(&self) -> *mut c_void { self.dll_path_va }
}

/// Phase-D helper: dispatch a `LoadLibraryW(dll_path_va)` remote
/// thread in `target` and return the thread handle. Used by the
/// integrated cdylib injection path that orchestrates entry-trampoline
/// rendezvous + cdylib load + hook install in one synchronous flow.
///
/// Caller is responsible for waiting on `session.wake_event()` and
/// closing the returned thread handle.
pub fn dispatch_load_library(
    session: &CdylibSession, target: HANDLE,
) -> Result<HANDLE> {
    unsafe {
        let load_library_w = {
            let m = GetModuleHandleW(PCWSTR(wstr("kernel32.dll").as_ptr()))
                .context("GetModuleHandleW(kernel32)")?;
            GetProcAddress(m, PCSTR(b"LoadLibraryW\0".as_ptr()))
                .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW)"))?
        };
        let start: LPTHREAD_START_ROUTINE =
            Some(std::mem::transmute(load_library_w));
        let th = CreateRemoteThread(
            target, None, 0, start,
            Some(session.dll_path_va), 0, None,
        ).context("CreateRemoteThread(LoadLibraryW)")?;
        Ok(th)
    }
}

/// Build the env-var entry the caller must include in the env block
/// passed to `CreateProcess`. Returns `(key, value)` so the caller
/// can `push` it into its env-pair vector. The placeholder is what
/// [`prepare`] later overwrites in-place with the real buffer VA.
pub fn placeholder_env_pair() -> (String, String) {
    (ENV_KEY.to_string(), ENV_PLACEHOLDER.to_string())
}

/// Inject the cdylib bookkeeping into a SUSPENDED target:
///   * Create section + event in the broker.
///   * DuplicateHandle them into the target.
///   * Pre-map the section into the target via NtMapViewOfSection.
///   * VirtualAllocEx the [`CdylibBuffer`] in the target and write it.
///   * Patch the env block in-place to point `AC_CDYLIB_BUFFER` at
///     the buffer VA.
///   * VirtualAllocEx + WriteProcessMemory the cdylib path string
///     (UTF-16) so [`trigger`] can pass its VA to LoadLibraryW.
///
/// `ipc_channel`, when supplied, contributes its target-side
/// section-VA / ev_req / ev_resp / mutex into the [`CdylibBuffer`]'s
/// IPC fields. The cdylib's hook bodies read these on every call to
/// IPC the broker. When `None`, the IPC fields are zero — the cdylib
/// `ipc_loaded()` check returns false and hooks short-circuit to
/// STATUS_ACCESS_DENIED. Phase B (no hooks installed) passes `None`;
/// Phase C+ shares the same channel that powers the inline-asm thunks
/// so the broker sees one stream of requests.
///
/// **Pre-condition:** the caller must have set `AC_CDYLIB_BUFFER=`
/// followed by exactly [`ENV_PLACEHOLDER`] in the env block passed
/// to CreateProcess. Use [`placeholder_env_pair`] to construct it.
///
/// **Pre-condition:** the cdylib's parent directory must already
/// have the AC SID's read+execute ACE — the broker stamps it via
/// `acl_stamper::PolicyStamp { allow_read: vec![dll.parent()], .. }`
/// before calling us.
pub fn prepare(
    target: HANDLE,
    dll_path: &Path,
    ipc_channel: Option<&ipc::Channel>,
) -> Result<CdylibSession> {
    if !dll_path.exists() {
        bail!("cdylib path does not exist: {}", dll_path.display());
    }

    unsafe {
        // ── 1. Section + event in the broker.
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        let section = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            Some(&sa),
            PAGE_READWRITE,
            0,
            4096,
            None,
        )
        .context("CreateFileMappingW(cdylib result)")?;
        let view_local = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        if view_local.Value.is_null() {
            let _ = CloseHandle(section);
            bail!("MapViewOfFile (broker)");
        }
        std::ptr::write_bytes(view_local.Value, 0, 4096);
        let event = CreateEventW(Some(&sa), false, false, None)
            .context("CreateEventW(cdylib wake)")?;

        // ── 2. Duplicate into target. The target was opened with
        //      PROCESS_DUP_HANDLE by the spawn path (CreateProcess
        //      hands out PROCESS_ALL_ACCESS by default).
        let target_section_h = dup_into(target, section)?;
        let target_event_h = dup_into(target, event)?;

        // ── 3. Pre-map the section into the target so DllMain
        //      doesn't need to (avoids dragging in NtMapViewOfSection
        //      from inside ac-cdylib).
        let target_view = map_into_target(section, target)?;

        // ── 4. Allocate + write the CdylibBuffer in the target.
        let buf_va = {
            let p = VirtualAllocEx(
                target,
                None,
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if p.is_null() {
                bail!("VirtualAllocEx(CdylibBuffer): {:?}", GetLastError());
            }
            // Phase C: when an IPC channel is supplied, surface its
            // target-side section VA + handle values into the buffer
            // so the cdylib's hook bodies can IPC the broker. The
            // channel itself was already mapped + duplicated into the
            // target by `ipc::Channel::create`; we just pass through
            // its `StubAddrs` snapshot.
            let (ipc_section, ipc_ev_req, ipc_ev_resp, ipc_mutex) = match ipc_channel {
                Some(ch) => {
                    let s = ch.stub_env_snapshot();
                    (s.section as u64, s.ev_req, s.ev_resp, s.mutex)
                }
                None => (0, 0, 0, 0),
            };
            let buf = CdylibBuffer {
                section: target_section_h,
                event: target_event_h,
                view: target_view as u64,
                magic: CDYLIB_MAGIC,
                ipc_section,
                ipc_ev_req,
                ipc_ev_resp,
                ipc_mutex,
            };
            let mut n = 0usize;
            WriteProcessMemory(
                target,
                p,
                &buf as *const _ as *const c_void,
                size_of::<CdylibBuffer>(),
                Some(&mut n),
            )
            .context("WriteProcessMemory(CdylibBuffer)")?;
            p as usize
        };

        // ── 5. Patch the target env block: replace the 16-char
        //      AC_CDYLIB_BUFFER placeholder with the real hex VA.
        patch_env_for_buffer(target, buf_va)
            .context("patch target env for AC_CDYLIB_BUFFER")?;

        // ── 6. Stage the dll path string (UTF-16) for LoadLibraryW.
        let dll_path_w: Vec<u16> = dll_path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let dll_path_va = {
            let p = VirtualAllocEx(
                target,
                None,
                dll_path_w.len() * 2,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if p.is_null() {
                bail!("VirtualAllocEx(dll_path): {:?}", GetLastError());
            }
            let mut n = 0usize;
            WriteProcessMemory(
                target,
                p,
                dll_path_w.as_ptr() as *const c_void,
                dll_path_w.len() * 2,
                Some(&mut n),
            )
            .context("WriteProcessMemory(dll_path)")?;
            p
        };

        Ok(CdylibSession {
            section,
            view_local,
            event,
            buf_va,
            dll_path_va,
            dll_path: dll_path.to_path_buf(),
        })
    }
}

/// Settle delay used between `ResumeThread` and `CreateRemoteThread`.
/// 150 ms is the B0-validated value; CreateRemoteThread serialises on
/// the loader lock so this is mostly insurance against logging the
/// wrong failure mode when the target dies during loader init.
pub const SETTLE_MS: u64 = 150;

/// Settles for [`SETTLE_MS`] (configurable via `WINSBOX_CDYLIB_SETTLE_MS`),
/// dispatches a remote thread at `LoadLibraryW(dll_path)`, then waits up
/// to `timeout_ms` for the cdylib's wake event. Pre-condition: the
/// target's main thread is already running — the caller (or
/// [`spawn_in_ac`](crate::launch)) resumed it.
///
/// On wake-event signal returns the validated [`CdylibReport`].
/// On timeout, includes diagnostic context (LoadLibraryW return,
/// target liveness) in the returned error so the caller can decide
/// whether to treat the failure as fatal.
pub fn trigger(
    session: &CdylibSession,
    target: HANDLE,
    timeout_ms: u32,
) -> Result<CdylibReport> {
    let t0 = std::time::Instant::now();
    unsafe {
        let sleep_ms = std::env::var("WINSBOX_CDYLIB_SETTLE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(SETTLE_MS);
        if sleep_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        let mut pcode: u32 = 0;
        let _ = GetExitCodeProcess(target, &mut pcode);
        const STILL_ACTIVE: u32 = 259;
        if pcode != STILL_ACTIVE {
            bail!(
                "target exited (code {:#x}) before LoadLibraryW dispatch — \
                 AC-incompatible loader (see P13 for MSYS2)",
                pcode,
            );
        }

        // Dispatch LoadLibraryW(dll_path) in the target. System DLL
        // bases match between processes per session, so the broker's
        // kernel32!LoadLibraryW VA is also valid in the target.
        let load_library_w = {
            let m = GetModuleHandleW(PCWSTR(wstr("kernel32.dll").as_ptr()))
                .context("GetModuleHandleW(kernel32)")?;
            GetProcAddress(m, PCSTR(b"LoadLibraryW\0".as_ptr()))
                .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW)"))?
        };
        let inject_thread = {
            let start: LPTHREAD_START_ROUTINE =
                Some(std::mem::transmute(load_library_w));
            CreateRemoteThread(
                target,
                None,
                0,
                start,
                Some(session.dll_path_va),
                0,
                None,
            )
            .context("CreateRemoteThread(LoadLibraryW)")?
        };

        let result_status = WaitForSingleObject(session.event, timeout_ms);
        if result_status == WAIT_OBJECT_0 {
            let _ = CloseHandle(inject_thread);
            let report = session.verify_report()?;
            let latency_ms = t0.elapsed().as_millis();
            eprintln!(
                "[sbox-exec] cdylib reported back: pid={} version={} init={:#x} \
                 (latency {} ms; settle {} ms)",
                report.pid, report.version, report.init_result,
                latency_ms, sleep_ms,
            );
            Ok(report)
        } else {
            // Diagnostics: how did it fail?
            let _ = WaitForSingleObject(inject_thread, 500);
            let mut tcode: u32 = 0;
            let _ = GetExitCodeProcess(inject_thread, &mut tcode);
            let _ = CloseHandle(inject_thread);
            let mut pcode: u32 = 0;
            let _ = GetExitCodeProcess(target, &mut pcode);
            const STILL_ACTIVE2: u32 = 259;
            let alive = pcode == STILL_ACTIVE2;
            bail!(
                "cdylib wake-event timeout ({timeout_ms} ms); LoadLibraryW \
                 thread exit={tcode:#x} (HMODULE; 0=fail), target_alive={alive} \
                 (exit={pcode:#x}); dll={}",
                session.dll_path.display(),
            );
        }
    }
}

/// Send-able wrapper around the raw `HANDLE` integer for moving into
/// a `std::thread::spawn` closure. Win32 HANDLEs are pointer-sized
/// integers; the closure runs on a thread we own and the target
/// process outlives the closure (the broker's run_confined holds
/// `pi.hProcess` until WaitForSingleObject returns).
struct SendHandle(isize);
unsafe impl Send for SendHandle {}

/// Spawn a background thread that runs [`trigger`] and logs the
/// outcome non-fatally. Useful when the broker's main thread needs
/// to immediately move on (e.g. WaitForSingleObject on the target),
/// e.g. for short-lived test commands like `cmd /c exit 0`.
///
/// The returned `JoinHandle` lets the caller wait for the report
/// before tearing down ACLs / job; for short-running targets the
/// caller usually just `join`s after the target exits, with the
/// timeout bounding total wait.
pub fn trigger_async(
    session: CdylibSession,
    target: HANDLE,
    timeout_ms: u32,
) -> std::thread::JoinHandle<Result<CdylibReport>> {
    let target_h = SendHandle(target.0 as isize);
    std::thread::spawn(move || {
        let target = HANDLE(target_h.0 as *mut c_void);
        let res = trigger(&session, target, timeout_ms);
        if let Err(ref e) = res {
            eprintln!("[sbox-exec] cdylib injection: {e:#}");
        }
        // Move session into here so its Drop runs *after* the wait
        // (we still own the broker-side section view that might
        // hold the report struct).
        drop(session);
        res
    })
}

/// Phase-D: walk the target's PEB→Ldr→InLoadOrderModuleList to find
/// the base address of a module by case-insensitive base-name match
/// (e.g. `"ac_cdylib.dll"`). Returns `Err` if the module isn't loaded
/// (caller should retry — DllMain may not have signalled the wake
/// event before the module table is updated).
///
/// Layout (x64): each `LDR_DATA_TABLE_ENTRY` starts with two
/// `LIST_ENTRY` links (`InLoadOrderLinks` at +0x00,
/// `InMemoryOrderLinks` at +0x10). `DllBase` is at +0x30,
/// `BaseDllName` (UNICODE_STRING) is at +0x58. The Ldr's
/// `InLoadOrderModuleList` head is at `PEB_LDR_DATA + 0x10`. PEB+0x18
/// holds the `PEB_LDR_DATA*`.
pub fn find_target_module_base(target: HANDLE, name: &str) -> Result<usize> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
    unsafe {
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut ret = 0u32;
        let st = NtQueryInformationProcess(
            target,
            PROCESSINFOCLASS(0),
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret,
        );
        if st.0 < 0 {
            bail!("NtQueryInformationProcess: {:#x}", st.0);
        }
        let peb = pbi.PebBaseAddress as usize;

        let read_usize = |va: usize| -> Result<usize> {
            let mut v: usize = 0;
            let mut n = 0usize;
            ReadProcessMemory(
                target, va as *const c_void,
                &mut v as *mut _ as *mut c_void, size_of::<usize>(), Some(&mut n),
            ).with_context(|| format!("ReadProcessMemory(usize) @ {va:#x}"))?;
            Ok(v)
        };

        let ldr = read_usize(peb + 0x18)?;
        let head = ldr + 0x10; // InLoadOrderModuleList LIST_ENTRY head
        let want = name.to_ascii_lowercase();

        let mut node = read_usize(head)?; // first Flink
        let mut steps = 0usize;
        while node != head && steps < 1024 {
            // `node` points at the LIST_ENTRY embedded at offset 0 of
            // the LDR_DATA_TABLE_ENTRY (InLoadOrderLinks).
            let entry = node;
            // DllBase @ entry + 0x30
            let dll_base = read_usize(entry + 0x30)?;
            // BaseDllName UNICODE_STRING @ entry + 0x58 (Length: u16 @ +0,
            // MaximumLength: u16 @ +2, _pad: u32 @ +4, Buffer: usize @ +8).
            let mut len_buf = [0u8; 2];
            let mut n = 0usize;
            ReadProcessMemory(
                target, (entry + 0x58) as *const c_void,
                len_buf.as_mut_ptr() as *mut c_void, 2, Some(&mut n),
            ).context("read BaseDllName.Length")?;
            let bname_len = u16::from_le_bytes(len_buf) as usize;
            let bname_buf = read_usize(entry + 0x58 + 8)?;
            if bname_len > 0 && bname_len <= 1024 && bname_buf != 0 {
                let mut wbuf = vec![0u16; bname_len / 2];
                ReadProcessMemory(
                    target, bname_buf as *const c_void,
                    wbuf.as_mut_ptr() as *mut c_void, bname_len, Some(&mut n),
                ).context("read BaseDllName.Buffer")?;
                let s = String::from_utf16_lossy(&wbuf).to_ascii_lowercase();
                if s == want {
                    return Ok(dll_base);
                }
            }
            node = read_usize(entry)?; // Flink
            steps += 1;
        }
        bail!("module {name:?} not found in target Ldr (walked {steps} entries)");
    }
}

/// Compute the in-target VA of an export symbol given the broker-side
/// loaded module. Loads the cdylib in-broker (idempotent — same path
/// returns the same HMODULE), uses `GetProcAddress` to resolve the
/// export's broker VA, computes its RVA against the broker-side base,
/// and adds the target-side base. Robust against per-process ASLR.
///
/// `dll_path` is passed to `LoadLibraryExW(LOAD_LIBRARY_AS_DATAFILE)`
/// so the cdylib's `DllMain` doesn't run in the broker — we only need
/// its export table.
///
/// Actually `LOAD_LIBRARY_AS_DATAFILE` skips relocations *and* exports
/// (loader doesn't process the export directory), so plain
/// `LoadLibraryW` is the right call. The broker is a small short-lived
/// process; the extra DllMain run there is harmless because the cdylib
/// reads `AC_CDYLIB_BUFFER` from the env, which the broker hasn't set
/// — the cdylib's `run_attach` early-returns and IPC fields stay
/// zeroed, which is the correct behaviour for the broker.
pub fn resolve_target_export(
    _target: HANDLE, dll_path: &Path, target_module_base: usize, export_name: &str,
) -> Result<usize> {
    unsafe {
        let path_w = wstr(&dll_path.to_string_lossy());
        let m = windows::Win32::System::LibraryLoader::LoadLibraryW(PCWSTR(path_w.as_ptr()))
            .with_context(|| format!("LoadLibraryW({})", dll_path.display()))?;
        let cname = std::ffi::CString::new(export_name)
            .map_err(|e| anyhow!("CString({export_name}): {e}"))?;
        let p = GetProcAddress(m, PCSTR(cname.as_ptr() as *const u8))
            .ok_or_else(|| anyhow!("GetProcAddress({export_name})"))?;
        let broker_va = p as usize;
        let broker_base = m.0 as usize;
        let rva = broker_va.checked_sub(broker_base)
            .ok_or_else(|| anyhow!("export {export_name} below broker base"))?;
        Ok(target_module_base + rva)
    }
}

// ─── helpers ───────────────────────────────────────────────────────

fn dup_into(target: HANDLE, src: HANDLE) -> Result<u64> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateHandle(
            GetCurrentProcess(),
            src,
            target,
            &mut out,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .context("DuplicateHandle into target")?;
        Ok(out.0 as u64)
    }
}

fn map_into_target(section: HANDLE, target: HANDLE) -> Result<usize> {
    #[link(name = "ntdll")]
    extern "system" {
        fn NtMapViewOfSection(
            section: HANDLE,
            process: HANDLE,
            base: *mut *mut c_void,
            zero_bits: usize,
            commit: usize,
            offset: *mut i64,
            view_size: *mut usize,
            inherit: u32,
            alloc_type: u32,
            protect: u32,
        ) -> NTSTATUS;
    }
    unsafe {
        let mut base: *mut c_void = std::ptr::null_mut();
        let mut size: usize = 0;
        let mut off: i64 = 0;
        let st = NtMapViewOfSection(
            section, target, &mut base, 0, 0, &mut off, &mut size,
            2, /* ViewUnmap */
            0, /* alloc_type */
            PAGE_READWRITE.0,
        );
        if st.0 < 0 {
            bail!("NtMapViewOfSection: {:#x}", st.0);
        }
        Ok(base as usize)
    }
}

/// Patch `AC_CDYLIB_BUFFER=<placeholder>` in the target's env block,
/// replacing the 16-char placeholder with the real hex VA.
///
/// Locates the env block via the target's
/// `PEB→RTL_USER_PROCESS_PARAMETERS→Environment` pointer (offset 0x80
/// on x64/ARM64) and uses `EnvironmentSize` (0x3F0) for the byte
/// length rather than scanning for a NUL-double-terminator (B0 P13
/// finding: scan races the loader on some MSYS-derived shells).
fn patch_env_for_buffer(target: HANDLE, buf_va: usize) -> Result<()> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    unsafe {
        let mut pbi: PROCESS_BASIC_INFORMATION = zeroed();
        let mut ret = 0u32;
        let st = NtQueryInformationProcess(
            target,
            PROCESSINFOCLASS(0), /* ProcessBasicInformation */
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret,
        );
        if st.0 < 0 {
            bail!("NtQueryInformationProcess: {:#x}", st.0);
        }
        let peb_addr = pbi.PebBaseAddress as usize;

        let mut params_ptr: usize = 0;
        let mut n = 0usize;
        ReadProcessMemory(
            target,
            (peb_addr + 0x20) as *const c_void,
            &mut params_ptr as *mut _ as *mut c_void,
            size_of::<usize>(),
            Some(&mut n),
        )
        .context("read PEB.ProcessParameters")?;

        let mut env_ptr: usize = 0;
        ReadProcessMemory(
            target,
            (params_ptr + 0x80) as *const c_void,
            &mut env_ptr as *mut _ as *mut c_void,
            size_of::<usize>(),
            Some(&mut n),
        )
        .context("read PROC_PARAMS.Environment")?;

        let mut env_size: usize = 0;
        ReadProcessMemory(
            target,
            (params_ptr + 0x3F0) as *const c_void,
            &mut env_size as *mut _ as *mut c_void,
            size_of::<usize>(),
            Some(&mut n),
        )
        .context("read PROC_PARAMS.EnvironmentSize")?;

        let env_byte_len = if env_size > 0 && env_size < 1 << 20 {
            env_size
        } else {
            // Fallback: 64 KiB scan window. Same heuristic as B0.
            65536
        };
        let mut env_buf = vec![0u8; env_byte_len];
        ReadProcessMemory(
            target,
            env_ptr as *const c_void,
            env_buf.as_mut_ptr() as *mut c_void,
            env_byte_len,
            Some(&mut n),
        )
        .context("read target env block")?;

        // Find "AC_CDYLIB_BUFFER=" + placeholder in the wide block.
        let needle: Vec<u16> = format!("{ENV_KEY}={ENV_PLACEHOLDER}")
            .encode_utf16()
            .collect();
        let needle_bytes: &[u8] = std::slice::from_raw_parts(
            needle.as_ptr() as *const u8,
            needle.len() * 2,
        );
        let pos = env_buf
            .windows(needle_bytes.len())
            .position(|w| w == needle_bytes)
            .ok_or_else(|| {
                anyhow!(
                    "{ENV_KEY}={ENV_PLACEHOLDER} not found in target env \
                     ({env_byte_len} bytes); did the caller include the \
                     placeholder env-var?"
                )
            })?;
        let placeholder_byte_off = pos + (format!("{ENV_KEY}=").len() * 2);

        let hex = format!("{:016x}", buf_va);
        let hex_w: Vec<u16> = hex.encode_utf16().collect();
        debug_assert_eq!(hex_w.len(), 16);
        let hex_bytes: &[u8] = std::slice::from_raw_parts(
            hex_w.as_ptr() as *const u8,
            16 * 2,
        );

        let mut wn = 0usize;
        WriteProcessMemory(
            target,
            (env_ptr + placeholder_byte_off) as *mut c_void,
            hex_bytes.as_ptr() as *const c_void,
            hex_bytes.len(),
            Some(&mut wn),
        )
        .context("WriteProcessMemory(env placeholder)")?;
    }
    Ok(())
}
