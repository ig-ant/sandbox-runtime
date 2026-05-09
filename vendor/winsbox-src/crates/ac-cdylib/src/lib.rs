//! Production cdylib loaded into the AppContainer target.
//!
//! Phase E-5c: this crate is `#![no_std]`. The cdylib is manual-mapped
//! into the AC pre-resume by the broker (`crate::manual_map`) — no
//! TLS callbacks, no `DllMain`, no loader-driven init at all. The
//! broker pre-fills the [`IPC`] global directly via `WriteProcessMemory`
//! and patches ntdll/kernelbase syscall stubs to dispatch into the
//! `hook_*` exports below. Removing `std` removes the cdylib's TLS
//! directory entirely (Rust's std runtime is the only thing that needs
//! TLS in our hook bodies), which sidesteps the `manual_map` warning
//! about un-executed TLS callbacks: with no TLS at all, there is
//! nothing to skip.
//!
//! Hook-body machinery:
//!   * Each `hook_*` function is `extern "system"` matching the ABI
//!     the patched ntdll/kernelbase export expected.
//!   * Reads input args from the standard Win64 ABI (rcx/rdx/r8/r9 +
//!     stack on x64; x0..x7 on ARM64).
//!   * Acquires the IPC mutex, writes the wire frame, signals
//!     `ev_req`, waits on `ev_resp`.
//!   * Writes the broker's reply into the caller's out-params.
//!   * On `FS_PASSTHROUGH` from the broker, tail-calls the broker-built
//!     passthrough thunk (Phase E-5b) instead.
//!   * Releases the mutex and returns `r_status`.
//!
//! The IPC layout (`Wire`) and op codes match the broker's
//! `src/ipc.rs` byte-for-byte. We re-declare them locally rather than
//! depend on the broker crate so the cdylib stays a leaf workspace
//! member (no cyclic dep, smaller link surface).

#![cfg(windows)]
#![cfg_attr(not(test), no_std)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};

// ─── Minimal Win32 ABI bindings ────────────────────────────────────
//
// We re-declare these here rather than pull in `windows`/`windows-sys`
// because (a) `windows` 0.58 isn't no_std-compatible (its proc-macro
// crates pull `std`), and (b) the cdylib's surface is tiny: HANDLE
// (pointer-sized), NTSTATUS (`i32`), and three ntdll syscall signatures.
// ABI-equivalent declarations keep the broker side untouched.
//
// `HANDLE` is exposed in this crate's exports purely as a pointer-
// sized integer; the broker passes raw `usize`/`u64` values to/from
// these slots and never inspects the Rust type.

#[allow(non_camel_case_types)]
pub type HANDLE = *mut c_void;

#[allow(non_camel_case_types)]
pub type NTSTATUS = i32;

#[link(name = "ntdll")]
extern "system" {
    fn NtSetEvent(h: HANDLE, prev: *mut i32) -> NTSTATUS;
    fn NtWaitForSingleObject(h: HANDLE, alertable: u8, timeout: *const i64) -> NTSTATUS;
    fn NtReleaseMutant(h: HANDLE, prev: *mut i32) -> NTSTATUS;
}

// ─── Versioning ────────────────────────────────────────────────────

/// Cdylib version stamp. Bumps whenever the layout of `CdylibBuffer`,
/// `CdylibResult`, or the wire format changes. Broker compares to its
/// own constant on readback to catch broker/cdylib skew.
///
/// v3 (Phase K): added `passthrough_trace[TRACE_SYSCALL_COUNT]` tail
/// of `IpcEnv` for `WINSBOX_TRACE_SYSCALLS` opt-in tracing. Default
/// runs leave the new fields zero-initialised (broker only writes them
/// when trace mode is on), so the cost on the cold path is one extra
/// page of zeroed `.bss`-equivalent in the manual-mapped image.
///
/// v4 (Phase L cycle 3): TRACE_SYSCALL_COUNT bumped 12 -> 15 to
/// add NtMapViewOfSection, NtCreateSection,
/// NtAllocateVirtualMemory — the syscalls the loader exercises
/// before reaching the original 12 trace family. Wire format
/// otherwise unchanged.
///
/// v5 (Phase N-0): added always-on `hook_NtCreateFile_denylog` and
/// `hook_NtOpenFile_denylog`. New `OP_DENIED_OPEN` opcode carries a
/// truncated wide-path snapshot + access/share/options/status. Both
/// hooks tail-call the saved-original passthrough first; only on
/// `STATUS_ACCESS_DENIED` do they emit IPC. Two new passthrough VAs
/// land in `IpcEnv` (alongside the trace passthroughs). Disable via
/// the broker's `WINSBOX_LOG_DENIES=0` env var; default ON.
///
/// v6 (Phase N-2): the always-on `denylog` hooks become proxy-mode
/// hooks. After the passthrough returns `STATUS_ACCESS_DENIED`, the
/// hook first sends an `OP_BROKER_OPEN` frame; the broker may grant
/// the open by re-issuing under its own user-token, canonicalizing
/// the path, validating against `allowRead`/`allowWrite`/auto-
/// toolchain dirs, and `DuplicateHandle`-ing the result into the AC.
/// On a granted open the cdylib writes the duped handle into the
/// caller's `*FileHandle` and returns SUCCESS. On rejection the
/// cdylib falls through to the legacy `OP_DENIED_OPEN` log frame
/// and returns the original ACCESS_DENIED. Disable mediation via
/// `WINSBOX_BROKER_OPEN=0` (broker-side env); deny-logging stays on.
///
/// v7 (Phase N-5): TRACE_SYSCALL_COUNT bumped 15 → 30 to broaden
/// Cygwin DllMain coverage. Added trace hooks for NtOpenSection,
/// NtQueryInformationProcess, NtOpenProcessToken, NtOpenThreadToken,
/// NtQueryInformationToken, NtQuerySystemInformation,
/// NtReadVirtualMemory, NtClose, NtCreateNamedPipeFile_trace,
/// NtFsControlFile, NtSetInformationFile, NtQueryDirectoryFile,
/// NtCreateKey, NtCreateMailslotFile, NtUnmapViewOfSection. The
/// `passthrough_trace` array grows from 15 to 30 slots; downstream
/// `passthrough_nt_create_file_denylog` field offset shifts from
/// 0xC0 to 0x138. Wire format otherwise unchanged.
pub const CDYLIB_VERSION: u32 = 7;

/// Sentinel return value for `cdylib_init`. Broker verifies on
/// report-back. Retained as a no-op export so the broker's
/// `resolve_target_export("cdylib_init")` still succeeds even though
/// the manual-map path never invokes it.
pub const CDYLIB_INIT_OK: u32 = 0xACDC_0001;

#[no_mangle]
pub extern "system" fn cdylib_init() -> u32 {
    CDYLIB_INIT_OK
}

pub const CDYLIB_MAGIC: u64 = 0xAC11_DEAD_BEEF_CAFEu64;
pub const RESULT_SENTINEL: u32 = 0xACDC_BABE;

// ─── IPC env (process-static, populated pre-resume by the broker) ──

/// Number of trace-mode passthrough thunks. Indexed by the
/// `TRACE_*` syscall-id constants below; must match
/// `TRACE_SYSCALL_COUNT` on the broker side.
pub const TRACE_SYSCALL_COUNT: usize = 30;

// Trace-mode syscall IDs. Each is the index into
// `IpcEnv.passthrough_trace` *and* the value sent in the
// `OP_TRACE` wire frame's `args[0]`. Order matches the broker's
// `TRACE_SYSCALL_NAMES` table in `src/ipc.rs`.
pub const TRACE_NT_CREATE_FILE: u64 = 0;
pub const TRACE_NT_OPEN_FILE: u64 = 1;
pub const TRACE_NT_DEVICE_IO_CONTROL_FILE: u64 = 2;
pub const TRACE_NT_ALPC_CONNECT_PORT: u64 = 3;
pub const TRACE_NT_ALPC_SEND_WAIT_RECEIVE_PORT: u64 = 4;
pub const TRACE_NT_OPEN_KEY: u64 = 5;
pub const TRACE_NT_OPEN_KEY_EX: u64 = 6;
pub const TRACE_NT_QUERY_VALUE_KEY: u64 = 7;
pub const TRACE_NT_CREATE_EVENT: u64 = 8;
pub const TRACE_NT_OPEN_EVENT: u64 = 9;
pub const TRACE_NT_CREATE_MUTANT: u64 = 10;
pub const TRACE_NT_OPEN_MUTANT: u64 = 11;
// Phase L cycle 3 additions: loader-time syscalls.
pub const TRACE_NT_MAP_VIEW_OF_SECTION: u64 = 12;
pub const TRACE_NT_CREATE_SECTION: u64 = 13;
pub const TRACE_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 14;
// Phase N-5 additions: Cygwin DllMain coverage. The previous 15 hooks
// emitted few or zero lines for bash before the AV; these extend
// trace coverage to cover the syscalls Cygwin's DllMain plausibly
// executes (section open, token queries, system info, cross-process
// reads, handle close, FS metadata, registry create, mailslots).
pub const TRACE_NT_OPEN_SECTION: u64 = 15;
pub const TRACE_NT_QUERY_INFORMATION_PROCESS: u64 = 16;
pub const TRACE_NT_OPEN_PROCESS_TOKEN: u64 = 17;
pub const TRACE_NT_OPEN_THREAD_TOKEN: u64 = 18;
pub const TRACE_NT_QUERY_INFORMATION_TOKEN: u64 = 19;
pub const TRACE_NT_QUERY_SYSTEM_INFORMATION: u64 = 20;
pub const TRACE_NT_READ_VIRTUAL_MEMORY: u64 = 21;
pub const TRACE_NT_CLOSE: u64 = 22;
pub const TRACE_NT_CREATE_NAMED_PIPE_FILE: u64 = 23;
pub const TRACE_NT_FS_CONTROL_FILE: u64 = 24;
pub const TRACE_NT_SET_INFORMATION_FILE: u64 = 25;
pub const TRACE_NT_QUERY_DIRECTORY_FILE: u64 = 26;
pub const TRACE_NT_CREATE_KEY: u64 = 27;
pub const TRACE_NT_CREATE_MAILSLOT_FILE: u64 = 28;
pub const TRACE_NT_UNMAP_VIEW_OF_SECTION: u64 = 29;

/// Process-static IPC environment. The broker locates this via the
/// `IPC` data export, writes the IPC handles directly with
/// `WriteProcessMemory` *pre-resume*, and patches ntdll syscalls to
/// dispatch into the manual-mapped hooks. No DllMain runs — the broker
/// handles every initialisation step.
///
/// Field ordering and types must NOT change without bumping
/// [`CDYLIB_VERSION`] — the broker writes a contiguous `[u64; N]`
/// starting at `&IPC`. `AtomicU64` over a `u64` is `repr(C)` per the
/// std atomics docs; the broker writes plain `u64` values via
/// `WriteProcessMemory` and the cdylib reads them as `Atomic*` loads.
/// The pre-resume write happens-before any AC-side observation since
/// every AC thread starts after `ResumeThread`, which is a global
/// synchronisation point.
///
/// The `passthrough_*` fields each hold the in-target VA of a small
/// thunk built by the broker that contains a copy of the original
/// ntdll syscall's first 12 bytes (x64) / 16 bytes (ARM64), followed
/// by an absolute jump back to `syscall_va + 12/16`. Calling the thunk
/// pointer with the original `extern "system"` signature executes the
/// underlying syscall as if no hook were installed. Hook bodies use
/// these on `FS_PASSTHROUGH` to delegate the call to the kernel
/// directly.
#[repr(C)]
pub struct IpcEnv {
    pub section: AtomicU64,
    pub ev_req: AtomicU64,
    pub ev_resp: AtomicU64,
    pub mutex: AtomicU64,
    /// Passthrough thunk VAs. Zero = no passthrough available; hook
    /// returns STATUS_NOT_IMPLEMENTED in that case (broker bug).
    pub passthrough_nt_open_section: AtomicU64,
    pub passthrough_nt_create_directory_object: AtomicU64,
    pub passthrough_nt_open_directory_object: AtomicU64,
    pub passthrough_nt_create_named_pipe_file: AtomicU64,
    pub passthrough_create_process_internal_w: AtomicU64,
    /// Phase K: per-trace-syscall passthrough thunk VAs. Filled in by
    /// the broker only when `WINSBOX_TRACE_SYSCALLS=1` was set; left
    /// zero in default runs (the trace hooks aren't installed in that
    /// case, so the thunks aren't read either).
    pub passthrough_trace: [AtomicU64; TRACE_SYSCALL_COUNT],
    /// Phase N-0: passthrough thunks for the always-on
    /// `hook_NtCreateFile_denylog` / `hook_NtOpenFile_denylog`
    /// hooks. Always written when the deny-log hooks install
    /// (default on, off via `WINSBOX_LOG_DENIES=0`). Both hooks
    /// tail-call into these to invoke the un-hooked syscall, then
    /// only emit `OP_DENIED_OPEN` on `STATUS_ACCESS_DENIED`.
    pub passthrough_nt_create_file_denylog: AtomicU64,
    pub passthrough_nt_open_file_denylog: AtomicU64,
}

/// Exported as a no-mangle data symbol so the broker's
/// `resolve_target_export("IPC")` returns the in-target VA of this
/// struct. Pre-resume the broker writes a contiguous `[u64; 9]`
/// directly here via `WriteProcessMemory`. Post-resume hook bodies
/// read these as `AtomicU64::load(Acquire)`.
///
/// In trace mode (Phase K) the broker also writes a contiguous
/// `[u64; TRACE_SYSCALL_COUNT]` at offset `0x48` (= 9 * 8) covering
/// `passthrough_trace`.
#[no_mangle]
pub static IPC: IpcEnv = IpcEnv {
    section: AtomicU64::new(0),
    ev_req: AtomicU64::new(0),
    ev_resp: AtomicU64::new(0),
    mutex: AtomicU64::new(0),
    passthrough_nt_open_section: AtomicU64::new(0),
    passthrough_nt_create_directory_object: AtomicU64::new(0),
    passthrough_nt_open_directory_object: AtomicU64::new(0),
    passthrough_nt_create_named_pipe_file: AtomicU64::new(0),
    passthrough_create_process_internal_w: AtomicU64::new(0),
    // Repeating `AtomicU64::new(0)` 30× rather than using a `[…; N]`
    // shorthand (which requires `Copy`, and `AtomicU64` isn't).
    passthrough_trace: [
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    ],
    passthrough_nt_create_file_denylog: AtomicU64::new(0),
    passthrough_nt_open_file_denylog: AtomicU64::new(0),
};

#[inline]
fn ipc_loaded() -> bool {
    IPC.section.load(Ordering::Acquire) != 0
}

// ─── Wire-format constants (mirror crate::ipc) ─────────────────────

const OP_CPW: u64 = 0;
const OP_NTOPENSECTION: u64 = 5;
const OP_NTCREATEDIROBJ: u64 = 8;
const OP_NTOPENDIROBJ: u64 = 9;
const OP_NTCREATENAMEDPIPE: u64 = 10;
/// Phase K: passthrough+log trace frame. The broker logs the syscall
/// + key arg + return status to stderr (or a sink the broker chooses)
/// and replies with a no-op ACK so the cdylib can release the IPC
/// mutex. `args[0]` holds the trace-syscall-id; the remaining `args`
/// are op-specific (see `hook_*_trace` builders).
const OP_TRACE: u64 = 100;

/// Phase N-0: always-on denied-open log frame. Sent by the cdylib's
/// `hook_NtCreateFile_denylog` / `hook_NtOpenFile_denylog` after the
/// passthrough thunk returned `STATUS_ACCESS_DENIED`. The wire layout:
///
///   args[0] = syscall id (0=NtCreateFile, 1=NtOpenFile)
///   args[1] = OBJECT_ATTRIBUTES* VA (broker chases via RPM and
///             truncates the resulting wide path to 256 bytes)
///   args[2] = desired_access (u32, low half)
///   args[3] = share_access   (u32, low half)
///   args[4] = options        (u32, low half) — CreateOptions for
///             NtCreateFile / OpenOptions for NtOpenFile
///   args[5] = status         (u32, low half — always 0xC0000022 in
///             current impl, included for forward compat)
///
/// Cheaper than packing the path into the wire: it keeps the cdylib
/// no_std (no allocator, no UTF-16 conversion) and reuses the
/// broker-side `read_target_oa_raw` helper the trace path already
/// has. Broker logs to stderr; no semantic effect on the caller (the
/// kernel already returned ACCESS_DENIED).
const OP_DENIED_OPEN: u64 = 101;

/// Syscall IDs for the deny-log path (independent numbering from the
/// `TRACE_*` family; broker maps these via `OP_DENIED_OPEN.args[0]`).
const DENYLOG_NT_CREATE_FILE: u64 = 0;
const DENYLOG_NT_OPEN_FILE: u64 = 1;

/// Phase N-2: broker-mediated open opcode. Sent by the proxy-mode
/// hooks after the passthrough returns `STATUS_ACCESS_DENIED`. Wire
/// layout:
///   args[0] = OBJECT_ATTRIBUTES* VA
///   args[1] = desired_access (u32)
///   args[2] = share_access   (u32)
///   args[3] = options        (u32 — CreateOptions / OpenOptions)
///   args[4] = syscall id (`BROKER_OPEN_NT_CREATE_FILE` /
///             `BROKER_OPEN_NT_OPEN_FILE`)
/// Reply (broker writes back into the same `Wire`):
///   args[0] = NTSTATUS (u32)
///   args[1] = duped target-side HANDLE on success, 0 otherwise
const OP_BROKER_OPEN: u64 = 102;

/// Phase N-2: syscall ids for `OP_BROKER_OPEN`. Same shape as the
/// `DENYLOG_*` family — independent numbering, broker-side decode.
const BROKER_OPEN_NT_CREATE_FILE: u64 = 0;
const BROKER_OPEN_NT_OPEN_FILE: u64 = 1;

/// Phase N-2: NTSTATUS_SUCCESS sentinel for broker-open replies.
const STATUS_SUCCESS: i32 = 0;

const FS_PASSTHROUGH: i32 = 0xE0000001u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC0000022u32 as i32;
const STATUS_NOT_IMPLEMENTED: i32 = 0xC0000002u32 as i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct Wire {
    op: u64,
    args: [u64; 12],
    r0: u64,
    r1: u64,
    r2: u32,
    r3: u32,
    r_status: i32,
    r_error: u32,
}
const _: () = assert!(core::mem::size_of::<Wire>() == 0x88);

// ─── Hook-body machinery ───────────────────────────────────────────

/// One IPC round-trip. Caller fills in `op` + `args[..]`, we acquire
/// the broker mutex, copy the local frame into the shared section,
/// signal `ev_req`, wait on `ev_resp`, copy the reply back into
/// `frame`, release the mutex, and return.
///
/// Concurrency: a per-channel mutant — the broker IPC section holds
/// one request at a time, so two threads in the AC racing two hooks
/// serialise on this mutant. Same model as the legacy inline-asm
/// stubs (see broker `src/ipc.rs` doc).
unsafe fn ipc_roundtrip(frame: &mut Wire) {
    let section = IPC.section.load(Ordering::Acquire) as *mut Wire;
    let ev_req = IPC.ev_req.load(Ordering::Acquire) as HANDLE;
    let ev_resp = IPC.ev_resp.load(Ordering::Acquire) as HANDLE;
    let mutex = IPC.mutex.load(Ordering::Acquire) as HANDLE;

    // Acquire mutex. STATUS_ABANDONED still grants ownership — same
    // policy as the inline-asm stubs.
    let _ = NtWaitForSingleObject(mutex, 0, core::ptr::null());
    // Write request frame into the shared section.
    core::ptr::write_volatile(section, *frame);
    // Signal the broker; wait for reply.
    let _ = NtSetEvent(ev_req, core::ptr::null_mut());
    let _ = NtWaitForSingleObject(ev_resp, 0, core::ptr::null());
    // Read reply.
    *frame = core::ptr::read_volatile(section);
    // Release mutex.
    let _ = NtReleaseMutant(mutex, core::ptr::null_mut());
}

/// Common dispatch for the 3 handle-only hooks: NtOpenSection,
/// NtCreate/OpenDirectoryObject. All three have the
/// (PHANDLE, ACCESS, POBJECT_ATTRIBUTES) signature; the broker
/// returns `r0 = handle`, `r_status = NTSTATUS`. On `FS_PASSTHROUGH`
/// we tail-call the broker-built passthrough thunk for this hook
/// (Phase E-5b), which is a copy of the original ntdll syscall stub's
/// first 12/16 bytes followed by a JMP back into the syscall stub past
/// our patch — semantically equivalent to the un-hooked syscall.
#[inline]
unsafe fn hook_handle_op(
    op: u64, passthrough_va: u64,
    out_handle: *mut HANDLE, desired: u32, oa: *const c_void,
) -> NTSTATUS {
    if !ipc_loaded() {
        return STATUS_ACCESS_DENIED;
    }
    let mut frame = Wire {
        op,
        args: [0, desired as u64, oa as u64, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        r0: 0, r1: 0, r2: 0, r3: 0, r_status: 0, r_error: 0,
    };
    // args[0] = the out-handle pointer (broker uses it as
    // identity, not for writes — we write the result locally).
    frame.args[0] = out_handle as u64;
    ipc_roundtrip(&mut frame);
    if frame.r_status == FS_PASSTHROUGH {
        if passthrough_va == 0 {
            // Broker requested passthrough but no thunk available
            // (install bug). Surface a defined failure.
            return STATUS_NOT_IMPLEMENTED;
        }
        type Fn3 = unsafe extern "system" fn(
            *mut HANDLE, u32, *const c_void,
        ) -> NTSTATUS;
        let f: Fn3 = core::mem::transmute(passthrough_va as usize);
        return f(out_handle, desired, oa);
    }
    if frame.r_status >= 0 && !out_handle.is_null() {
        core::ptr::write(out_handle, frame.r0 as HANDLE);
    }
    frame.r_status
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_section(
    out_handle: *mut HANDLE, desired: u32, oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_nt_open_section.load(Ordering::Acquire);
    hook_handle_op(OP_NTOPENSECTION, pv, out_handle, desired, oa)
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_directory_object(
    out_handle: *mut HANDLE, desired: u32, oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_nt_create_directory_object.load(Ordering::Acquire);
    hook_handle_op(OP_NTCREATEDIROBJ, pv, out_handle, desired, oa)
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_directory_object(
    out_handle: *mut HANDLE, desired: u32, oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_nt_open_directory_object.load(Ordering::Acquire);
    hook_handle_op(OP_NTOPENDIROBJ, pv, out_handle, desired, oa)
}

/// `NtCreateNamedPipeFile` — 14 NT args, but Wire holds 12. The
/// broker's `handle_named_pipe` ignores `OutboundQuota` /
/// `DefaultTimeout` (Cygwin passes the broker-side defaults) and
/// reads the rest from `args[1..]`. Returns
/// `(handle, IO_STATUS_BLOCK.Information, NTSTATUS)`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_named_pipe_file(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    named_pipe_type: u32,
    read_mode: u32,
    completion_mode: u32,
    maximum_instances: u32,
    inbound_quota: u32,
    _outbound_quota: u32,
    _default_timeout: *const i64,
) -> NTSTATUS {
    if !ipc_loaded() {
        return STATUS_ACCESS_DENIED;
    }
    let mut frame = Wire {
        op: OP_NTCREATENAMEDPIPE,
        args: [
            out_handle as u64,
            desired_access as u64,
            oa as u64,
            iosb as u64,
            share_access as u64,
            create_disposition as u64,
            create_options as u64,
            named_pipe_type as u64,
            read_mode as u64,
            completion_mode as u64,
            maximum_instances as u64,
            inbound_quota as u64,
        ],
        r0: 0, r1: 0, r2: 0, r3: 0, r_status: 0, r_error: 0,
    };
    ipc_roundtrip(&mut frame);
    if frame.r_status == FS_PASSTHROUGH {
        let pv = IPC.passthrough_nt_create_named_pipe_file.load(Ordering::Acquire);
        if pv == 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
        type Fn14 = unsafe extern "system" fn(
            *mut HANDLE, u32, *const c_void, *mut [usize; 2],
            u32, u32, u32, u32, u32, u32, u32, u32, u32,
            *const i64,
        ) -> NTSTATUS;
        let f: Fn14 = core::mem::transmute(pv as usize);
        return f(
            out_handle, desired_access, oa, iosb,
            share_access, create_disposition, create_options,
            named_pipe_type, read_mode, completion_mode,
            maximum_instances, inbound_quota,
            _outbound_quota, _default_timeout,
        );
    }
    if frame.r_status >= 0 {
        if !out_handle.is_null() {
            core::ptr::write(out_handle, frame.r0 as HANDLE);
        }
        if !iosb.is_null() {
            // IO_STATUS_BLOCK = { Status, Information } both pointer-
            // sized. Match the legacy stub: status from r_status (sign-
            // extended), information from r1.
            (*iosb)[0] = frame.r_status as isize as usize;
            (*iosb)[1] = frame.r1 as usize;
        }
    }
    frame.r_status
}

/// `CreateProcessInternalW` — kernelbase export with the standard
/// CreateProcess signature (12 args). Broker's `handle_cpw` runs
/// the spawn under its own token, recursively installs the hook,
/// duplicates `(hProcess, hThread)` back, and replies with PID/TID.
/// On success we write the broker's `PROCESS_INFORMATION` into the
/// caller's `lpProcessInformation`. Returns BOOL via `r_status`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_create_process_internal_w(
    _h_token: HANDLE,
    application_name: *const u16,
    command_line: *mut u16,
    process_attrs: *const c_void,
    thread_attrs: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *mut c_void,
    current_directory: *const u16,
    startup_info: *const c_void,
    process_information: *mut ProcessInformation,
    new_token: *mut HANDLE,
) -> i32 {
    if !ipc_loaded() {
        // Match the legacy stub's failure behaviour: BOOL = 0.
        // GetLastError unset on this path; the OS will report the
        // last-error from whichever earlier call failed.
        return 0;
    }
    let mut frame = Wire {
        op: OP_CPW,
        args: [
            0, // h_token: broker spawns under its own token
            application_name as u64,
            command_line as u64,
            process_attrs as u64,
            thread_attrs as u64,
            inherit_handles as u64,
            creation_flags as u64,
            environment as u64,
            current_directory as u64,
            startup_info as u64,
            process_information as u64,
            new_token as u64,
        ],
        r0: 0, r1: 0, r2: 0, r3: 0, r_status: 0, r_error: 0,
    };
    ipc_roundtrip(&mut frame);
    if frame.r_status == FS_PASSTHROUGH {
        let pv = IPC.passthrough_create_process_internal_w.load(Ordering::Acquire);
        if pv == 0 {
            return 0;
        }
        type FnCpw = unsafe extern "system" fn(
            HANDLE, *const u16, *mut u16, *const c_void, *const c_void,
            i32, u32, *mut c_void, *const u16, *const c_void,
            *mut ProcessInformation, *mut HANDLE,
        ) -> i32;
        let f: FnCpw = core::mem::transmute(pv as usize);
        return f(
            _h_token, application_name, command_line,
            process_attrs, thread_attrs, inherit_handles, creation_flags,
            environment, current_directory, startup_info,
            process_information, new_token,
        );
    }
    // Write back PROCESS_INFORMATION on success. r_status is the
    // BOOL the kernel-side spawn returned (1 = success, 0 = failure).
    if frame.r_status != 0 && !process_information.is_null() {
        (*process_information).h_process = frame.r0 as HANDLE;
        (*process_information).h_thread = frame.r1 as HANDLE;
        (*process_information).process_id = frame.r2;
        (*process_information).thread_id = frame.r3;
    }
    if frame.r_status != 0 && !new_token.is_null() {
        // CreateProcessAsUserExW path passes phNewToken; broker
        // replies 0 here so caller sees NULL.
        core::ptr::write(new_token, core::ptr::null_mut());
    }
    if frame.r_status == 0 {
        // Set last-error from the broker's reply. SetLastError lives
        // in kernel32; we'd dynamically resolve, but the simpler path
        // is via the TEB's `LastErrorValue` (TEB+0x68 on x64, same on
        // ARM64). Defer that to a future refinement; for now leave
        // the OS-supplied last-error untouched (mirrors the legacy
        // stub behaviour absent the explicit `gs:[0x68]` write).
        let _ = frame.r_error;
    }
    frame.r_status
}

/// Subset of `PROCESS_INFORMATION` matching the Win32 layout. The
/// broker's caller (hooked `CreateProcessInternalW`) hands us a
/// pointer with this exact ABI.
#[repr(C)]
pub struct ProcessInformation {
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
}

// ─── Phase K: trace-mode hooks ─────────────────────────────────────
//
// Each `hook_<syscall>_trace` is a passthrough+log shape:
//
//   1. Tail-call the broker-built passthrough thunk for this syscall
//      to invoke the un-hooked kernel implementation.
//   2. Send an `OP_TRACE` frame to the broker carrying the
//      trace-syscall-id (in `args[0]`), the original syscall args of
//      interest (pointers into target memory — the broker uses
//      `ReadProcessMemory` to extract path/IOCTL/etc. summaries),
//      and the returned NTSTATUS.
//   3. Return the NTSTATUS to the caller.
//
// The broker's `OP_TRACE` handler is a no-op ACK after logging — it
// just `SetEvent(ev_resp)`. The cdylib still uses the existing
// `ipc_roundtrip` (mutex-protected, one-at-a-time) so the trace
// channel can't corrupt the wire while a real hook is mid-flight.
//
// Default-off cost: trace hooks are only patched in when
// `WINSBOX_TRACE_SYSCALLS=1`. When unset, none of the bytecode below
// is reachable — `passthrough_trace[*]` stays zero, the syscall stubs
// keep their original bytes, and the cdylib spends zero cycles on
// trace bookkeeping.

/// Lightweight one-way trace frame send. Same wire shape as
/// `ipc_roundtrip` (mutex + ev_req + section write + ev_resp wait)
/// but the broker reply is just an ACK — caller ignores `r_*` fields.
/// The wait-on-resp is necessary so the broker has finished copying
/// the request frame before another thread overwrites it.
#[inline]
unsafe fn ipc_trace_send(
    syscall_id: u64, status: NTSTATUS, args: [u64; 11],
) {
    if !ipc_loaded() { return; }
    let mut frame = Wire {
        op: OP_TRACE,
        args: [
            syscall_id,
            args[0], args[1], args[2], args[3], args[4],
            args[5], args[6], args[7], args[8], args[9], args[10],
        ],
        r0: 0, r1: 0, r2: 0, r3: 0,
        r_status: status,
        r_error: 0,
    };
    ipc_roundtrip(&mut frame);
}

/// Build a `[u64; 11]` argument tuple for `ipc_trace_send` from up
/// to N raw u64s, zero-padding the remainder. Avoids a verbose
/// 11-slot array literal at every call site.
#[inline]
fn trace_args<const N: usize>(vals: [u64; N]) -> [u64; 11] {
    let mut out = [0u64; 11];
    let mut i = 0;
    while i < N && i < 11 { out[i] = vals[i]; i += 1; }
    out
}

// 1. NtCreateFile / NtOpenFile — file/device opens. Args of
//    interest: OBJECT_ATTRIBUTES* in slot args[2]; broker chases
//    the embedded UNICODE_STRING `ObjectName` to get the path.

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_file_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    alloc_size: *const i64,
    file_attrs: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *const c_void,
    ea_length: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_FILE as usize].load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn11 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2], *const i64,
        u32, u32, u32, u32, *const c_void, u32,
    ) -> NTSTATUS;
    let f: Fn11 = core::mem::transmute(pv as usize);
    let st = f(
        out_handle, desired_access, oa, iosb, alloc_size,
        file_attrs, share_access, create_disposition,
        create_options, ea_buffer, ea_length,
    );
    ipc_trace_send(
        TRACE_NT_CREATE_FILE, st,
        trace_args([oa as u64, desired_access as u64, create_disposition as u64]),
    );
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_file_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_FILE as usize].load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn6 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2], u32, u32,
    ) -> NTSTATUS;
    let f: Fn6 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, iosb, share_access, open_options);
    ipc_trace_send(
        TRACE_NT_OPEN_FILE, st,
        trace_args([oa as u64, desired_access as u64, open_options as u64]),
    );
    st
}

// 2. NtDeviceIoControlFile — IOCTLs (CRYPTBASE/CNG/etc.).

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_device_io_control_file_trace(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *const c_void,
    apc_context: *const c_void,
    iosb: *mut [usize; 2],
    io_control_code: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_DEVICE_IO_CONTROL_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn10 = unsafe extern "system" fn(
        HANDLE, HANDLE, *const c_void, *const c_void, *mut [usize; 2],
        u32, *const c_void, u32, *mut c_void, u32,
    ) -> NTSTATUS;
    let f: Fn10 = core::mem::transmute(pv as usize);
    let st = f(
        file_handle, event, apc_routine, apc_context, iosb,
        io_control_code, in_buf, in_len, out_buf, out_len,
    );
    ipc_trace_send(
        TRACE_NT_DEVICE_IO_CONTROL_FILE, st,
        trace_args([file_handle as u64, io_control_code as u64,
                    in_len as u64, out_len as u64]),
    );
    st
}

// 3. NtAlpcConnectPort / NtAlpcSendWaitReceivePort — LSA / RPC under
//    the hood. The full ALPC signature is wide; we only care about
//    the first few args for the trace summary, so declare matching
//    `extern "system"` fn types and tail-call the kernel verbatim by
//    forwarding *every* arg position via the same prototype. We
//    spell out the full prototypes below.

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_alpc_connect_port_trace(
    out_handle: *mut HANDLE,
    port_name: *const c_void, // PUNICODE_STRING
    object_attributes: *const c_void,
    port_attrs: *const c_void,
    flags: u32,
    required_server_sid: *const c_void,
    connection_message: *mut c_void,
    buffer_length: *mut usize,
    out_message_attributes: *mut c_void,
    in_message_attributes: *mut c_void,
    timeout: *const i64,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_ALPC_CONNECT_PORT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn11 = unsafe extern "system" fn(
        *mut HANDLE, *const c_void, *const c_void, *const c_void,
        u32, *const c_void, *mut c_void, *mut usize,
        *mut c_void, *mut c_void, *const i64,
    ) -> NTSTATUS;
    let f: Fn11 = core::mem::transmute(pv as usize);
    let st = f(
        out_handle, port_name, object_attributes, port_attrs,
        flags, required_server_sid, connection_message, buffer_length,
        out_message_attributes, in_message_attributes, timeout,
    );
    ipc_trace_send(
        TRACE_NT_ALPC_CONNECT_PORT, st,
        trace_args([port_name as u64, flags as u64]),
    );
    st
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_alpc_send_wait_receive_port_trace(
    port_handle: HANDLE,
    flags: u32,
    send_message: *const c_void,
    send_message_attributes: *mut c_void,
    receive_message: *mut c_void,
    buffer_length: *mut usize,
    receive_message_attributes: *mut c_void,
    timeout: *const i64,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_ALPC_SEND_WAIT_RECEIVE_PORT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn8 = unsafe extern "system" fn(
        HANDLE, u32, *const c_void, *mut c_void, *mut c_void,
        *mut usize, *mut c_void, *const i64,
    ) -> NTSTATUS;
    let f: Fn8 = core::mem::transmute(pv as usize);
    let st = f(
        port_handle, flags, send_message, send_message_attributes,
        receive_message, buffer_length, receive_message_attributes, timeout,
    );
    ipc_trace_send(
        TRACE_NT_ALPC_SEND_WAIT_RECEIVE_PORT, st,
        trace_args([port_handle as u64, flags as u64]),
    );
    st
}

// 4. NtOpenKey / NtOpenKeyEx / NtQueryValueKey — registry reads.

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_key_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_KEY as usize].load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn3 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void,
    ) -> NTSTATUS;
    let f: Fn3 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa);
    ipc_trace_send(
        TRACE_NT_OPEN_KEY, st,
        trace_args([oa as u64, desired_access as u64]),
    );
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_key_ex_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    open_options: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_KEY_EX as usize].load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn4 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, u32,
    ) -> NTSTATUS;
    let f: Fn4 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, open_options);
    ipc_trace_send(
        TRACE_NT_OPEN_KEY_EX, st,
        trace_args([oa as u64, desired_access as u64, open_options as u64]),
    );
    st
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_query_value_key_trace(
    key_handle: HANDLE,
    value_name: *const c_void, // PUNICODE_STRING
    info_class: u32,
    info_buffer: *mut c_void,
    info_length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_QUERY_VALUE_KEY as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn6 = unsafe extern "system" fn(
        HANDLE, *const c_void, u32, *mut c_void, u32, *mut u32,
    ) -> NTSTATUS;
    let f: Fn6 = core::mem::transmute(pv as usize);
    let st = f(
        key_handle, value_name, info_class, info_buffer,
        info_length, result_length,
    );
    ipc_trace_send(
        TRACE_NT_QUERY_VALUE_KEY, st,
        trace_args([key_handle as u64, value_name as u64,
                    info_class as u64, info_length as u64]),
    );
    st
}

// 5–6. NtCreateEvent / NtOpenEvent / NtCreateMutant / NtOpenMutant —
//      synchronisation primitives. All read OBJECT_ATTRIBUTES for
//      the object name from args[2].

#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_event_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    event_type: u32,
    initial_state: u8,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_EVENT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn5 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, u32, u8,
    ) -> NTSTATUS;
    let f: Fn5 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, event_type, initial_state);
    ipc_trace_send(
        TRACE_NT_CREATE_EVENT, st,
        trace_args([oa as u64, desired_access as u64,
                    event_type as u64, initial_state as u64]),
    );
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_event_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_EVENT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn3 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void,
    ) -> NTSTATUS;
    let f: Fn3 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa);
    ipc_trace_send(
        TRACE_NT_OPEN_EVENT, st,
        trace_args([oa as u64, desired_access as u64]),
    );
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_mutant_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    initial_owner: u8,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_MUTANT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn4 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, u8,
    ) -> NTSTATUS;
    let f: Fn4 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, initial_owner);
    ipc_trace_send(
        TRACE_NT_CREATE_MUTANT, st,
        trace_args([oa as u64, desired_access as u64, initial_owner as u64]),
    );
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_mutant_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_MUTANT as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn3 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void,
    ) -> NTSTATUS;
    let f: Fn3 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa);
    ipc_trace_send(
        TRACE_NT_OPEN_MUTANT, st,
        trace_args([oa as u64, desired_access as u64]),
    );
    st
}

// 7. NtMapViewOfSection — every DLL load. Args of interest:
//    SectionHandle in args[0], BaseAddress* in args[2], ViewSize* in
//    args[6]. The broker logs the SectionHandle so it can be cross-
//    referenced with prior NtCreateSection / NtOpenSection calls.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_map_view_of_section_trace(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut i64,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_MAP_VIEW_OF_SECTION as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn10 = unsafe extern "system" fn(
        HANDLE, HANDLE, *mut *mut c_void, usize, usize, *mut i64,
        *mut usize, u32, u32, u32,
    ) -> NTSTATUS;
    let f: Fn10 = core::mem::transmute(pv as usize);
    let st = f(
        section_handle, process_handle, base_address, zero_bits,
        commit_size, section_offset, view_size,
        inherit_disposition, allocation_type, win32_protect,
    );
    ipc_trace_send(
        TRACE_NT_MAP_VIEW_OF_SECTION, st,
        trace_args([
            section_handle as u64,
            process_handle as u64,
            win32_protect as u64,
        ]),
    );
    st
}

// 8. NtCreateSection — Cygwin's cygheap shared section. Args of
//    interest: OBJECT_ATTRIBUTES* in args[2] for the section name.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_section_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    maximum_size: *const i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_SECTION as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn7 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *const i64, u32, u32, HANDLE,
    ) -> NTSTATUS;
    let f: Fn7 = core::mem::transmute(pv as usize);
    let st = f(
        out_handle, desired_access, oa, maximum_size,
        section_page_protection, allocation_attributes, file_handle,
    );
    ipc_trace_send(
        TRACE_NT_CREATE_SECTION, st,
        trace_args([
            oa as u64,
            desired_access as u64,
            section_page_protection as u64,
            allocation_attributes as u64,
        ]),
    );
    st
}

// 9. NtAllocateVirtualMemory — heap/stack init, also Cygwin's mmap
//    bridge. Very high-frequency; only useful when the trace cuts
//    off mid-AV.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_allocate_virtual_memory_trace(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_ALLOCATE_VIRTUAL_MEMORY as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn6 = unsafe extern "system" fn(
        HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32,
    ) -> NTSTATUS;
    let f: Fn6 = core::mem::transmute(pv as usize);
    let st = f(
        process_handle, base_address, zero_bits, region_size,
        allocation_type, protect,
    );
    ipc_trace_send(
        TRACE_NT_ALLOCATE_VIRTUAL_MEMORY, st,
        trace_args([
            process_handle as u64,
            allocation_type as u64,
            protect as u64,
        ]),
    );
    st
}

// ─── Phase N-5: Cygwin DllMain coverage trace hooks ────────────────
//
// Same passthrough+log shape as the prior 15 hooks. Each calls the
// broker-built passthrough thunk to invoke the un-hooked syscall,
// then ships an `OP_TRACE` frame with the syscall id + summary args
// + returned NTSTATUS. The broker's `trace_arg_summary` decodes the
// args; the wire format is unchanged.

// 10. NtOpenSection — Cygwin's shared_info opens an existing
//     `\BaseNamedObjects\cygwin1S5-sect`. AV hypothesis H1 fires
//     here. Args: handle out, access, OBJECT_ATTRIBUTES* in args[2].
#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_section_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_SECTION as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn3 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void,
    ) -> NTSTATUS;
    let f: Fn3 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa);
    ipc_trace_send(
        TRACE_NT_OPEN_SECTION, st,
        trace_args([oa as u64, desired_access as u64]),
    );
    st
}

// 11. NtQueryInformationProcess — process info queries; AC denies
//     several info classes (TokenStatistics etc.). Cygwin's child
//     setup reads its parent's basic info during fork().
#[no_mangle]
pub unsafe extern "system" fn hook_nt_query_information_process_trace(
    process_handle: HANDLE,
    info_class: u32,
    info_buffer: *mut c_void,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_QUERY_INFORMATION_PROCESS as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn5 = unsafe extern "system" fn(
        HANDLE, u32, *mut c_void, u32, *mut u32,
    ) -> NTSTATUS;
    let f: Fn5 = core::mem::transmute(pv as usize);
    let st = f(process_handle, info_class, info_buffer, info_length, return_length);
    ipc_trace_send(
        TRACE_NT_QUERY_INFORMATION_PROCESS, st,
        trace_args([process_handle as u64, info_class as u64,
                    info_length as u64]),
    );
    st
}

// 12. NtOpenProcessToken — token-handle acquire. Cygwin's
//     uinfo_init reads the process token to derive uid/gid.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_process_token_trace(
    process_handle: HANDLE,
    desired_access: u32,
    out_handle: *mut HANDLE,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_PROCESS_TOKEN as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn3 = unsafe extern "system" fn(
        HANDLE, u32, *mut HANDLE,
    ) -> NTSTATUS;
    let f: Fn3 = core::mem::transmute(pv as usize);
    let st = f(process_handle, desired_access, out_handle);
    ipc_trace_send(
        TRACE_NT_OPEN_PROCESS_TOKEN, st,
        trace_args([process_handle as u64, desired_access as u64]),
    );
    st
}

// 13. NtOpenThreadToken — thread-token impersonation lookup.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_thread_token_trace(
    thread_handle: HANDLE,
    desired_access: u32,
    open_as_self: u8,
    out_handle: *mut HANDLE,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_OPEN_THREAD_TOKEN as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn4 = unsafe extern "system" fn(
        HANDLE, u32, u8, *mut HANDLE,
    ) -> NTSTATUS;
    let f: Fn4 = core::mem::transmute(pv as usize);
    let st = f(thread_handle, desired_access, open_as_self, out_handle);
    ipc_trace_send(
        TRACE_NT_OPEN_THREAD_TOKEN, st,
        trace_args([thread_handle as u64, desired_access as u64,
                    open_as_self as u64]),
    );
    st
}

// 14. NtQueryInformationToken — token info readout (groups, user,
//     statistics, sandbox-info). Hot path during Cygwin uid/gid setup.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_query_information_token_trace(
    token_handle: HANDLE,
    info_class: u32,
    info_buffer: *mut c_void,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_QUERY_INFORMATION_TOKEN as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn5 = unsafe extern "system" fn(
        HANDLE, u32, *mut c_void, u32, *mut u32,
    ) -> NTSTATUS;
    let f: Fn5 = core::mem::transmute(pv as usize);
    let st = f(token_handle, info_class, info_buffer, info_length, return_length);
    ipc_trace_send(
        TRACE_NT_QUERY_INFORMATION_TOKEN, st,
        trace_args([token_handle as u64, info_class as u64,
                    info_length as u64]),
    );
    st
}

// 15. NtQuerySystemInformation — system-wide info queries; AC
//     denies many info classes. Cygwin's getloadavg/proc_subdir uses
//     SystemProcessInformation extensively.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_query_system_information_trace(
    info_class: u32,
    info_buffer: *mut c_void,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_QUERY_SYSTEM_INFORMATION as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn4 = unsafe extern "system" fn(
        u32, *mut c_void, u32, *mut u32,
    ) -> NTSTATUS;
    let f: Fn4 = core::mem::transmute(pv as usize);
    let st = f(info_class, info_buffer, info_length, return_length);
    ipc_trace_send(
        TRACE_NT_QUERY_SYSTEM_INFORMATION, st,
        trace_args([info_class as u64, info_length as u64]),
    );
    st
}

// 16. NtReadVirtualMemory — cross-process reads. AC denies cross-
//     process reads unless capability is granted. Cygwin's fork()
//     uses this against the parent during cygheap copy.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_read_virtual_memory_trace(
    process_handle: HANDLE,
    base_address: *const c_void,
    buffer: *mut c_void,
    buffer_size: usize,
    bytes_read: *mut usize,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_READ_VIRTUAL_MEMORY as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn5 = unsafe extern "system" fn(
        HANDLE, *const c_void, *mut c_void, usize, *mut usize,
    ) -> NTSTATUS;
    let f: Fn5 = core::mem::transmute(pv as usize);
    let st = f(process_handle, base_address, buffer, buffer_size, bytes_read);
    ipc_trace_send(
        TRACE_NT_READ_VIRTUAL_MEMORY, st,
        trace_args([process_handle as u64, base_address as u64,
                    buffer_size as u64]),
    );
    st
}

// 17. NtClose — handle close. Very high-frequency; useful as a
//     trace continuity marker so we can correlate handle lifetimes.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_close_trace(
    handle: HANDLE,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CLOSE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn1 = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
    let f: Fn1 = core::mem::transmute(pv as usize);
    let st = f(handle);
    ipc_trace_send(
        TRACE_NT_CLOSE, st,
        trace_args([handle as u64]),
    );
    st
}

// 18. NtCreateNamedPipeFile (trace flavour) — already brokered via
//     `hook_nt_create_named_pipe_file`. The trace variant is for
//     correlation with the AV: when the broker hook is in place the
//     trace hook is unused, but we install both paths so the broker
//     can choose at runtime which family to patch (for the N-5 run
//     we want the trace shape, no broker mediation, since the AV
//     research path benefits from un-modified semantics).
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_named_pipe_file_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    named_pipe_type: u32,
    read_mode: u32,
    completion_mode: u32,
    maximum_instances: u32,
    inbound_quota: u32,
    outbound_quota: u32,
    default_timeout: *const i64,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_NAMED_PIPE_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn14 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2],
        u32, u32, u32, u32, u32, u32, u32, u32, u32,
        *const i64,
    ) -> NTSTATUS;
    let f: Fn14 = core::mem::transmute(pv as usize);
    let st = f(
        out_handle, desired_access, oa, iosb,
        share_access, create_disposition, create_options,
        named_pipe_type, read_mode, completion_mode,
        maximum_instances, inbound_quota,
        outbound_quota, default_timeout,
    );
    ipc_trace_send(
        TRACE_NT_CREATE_NAMED_PIPE_FILE, st,
        trace_args([oa as u64, desired_access as u64,
                    create_disposition as u64, create_options as u64]),
    );
    st
}

// 19. NtFsControlFile — file control IO (FSCTL_*). Used by Cygwin
//     for reparse-point reads, junction queries.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_fs_control_file_trace(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *const c_void,
    apc_context: *const c_void,
    iosb: *mut [usize; 2],
    fs_control_code: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_FS_CONTROL_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn10 = unsafe extern "system" fn(
        HANDLE, HANDLE, *const c_void, *const c_void, *mut [usize; 2],
        u32, *const c_void, u32, *mut c_void, u32,
    ) -> NTSTATUS;
    let f: Fn10 = core::mem::transmute(pv as usize);
    let st = f(
        file_handle, event, apc_routine, apc_context, iosb,
        fs_control_code, in_buf, in_len, out_buf, out_len,
    );
    ipc_trace_send(
        TRACE_NT_FS_CONTROL_FILE, st,
        trace_args([file_handle as u64, fs_control_code as u64,
                    in_len as u64, out_len as u64]),
    );
    st
}

// 20. NtSetInformationFile — file metadata writes (rename, EOF,
//     disposition). Cygwin uses for chmod / unlink.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_set_information_file_trace(
    file_handle: HANDLE,
    iosb: *mut [usize; 2],
    info_buffer: *const c_void,
    info_length: u32,
    info_class: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_SET_INFORMATION_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn5 = unsafe extern "system" fn(
        HANDLE, *mut [usize; 2], *const c_void, u32, u32,
    ) -> NTSTATUS;
    let f: Fn5 = core::mem::transmute(pv as usize);
    let st = f(file_handle, iosb, info_buffer, info_length, info_class);
    ipc_trace_send(
        TRACE_NT_SET_INFORMATION_FILE, st,
        trace_args([file_handle as u64, info_class as u64,
                    info_length as u64]),
    );
    st
}

// 21. NtQueryDirectoryFile — directory enumeration; PATH walks.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_query_directory_file_trace(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *const c_void,
    apc_context: *const c_void,
    iosb: *mut [usize; 2],
    info_buffer: *mut c_void,
    info_length: u32,
    info_class: u32,
    return_single_entry: u8,
    file_name: *const c_void,
    restart_scan: u8,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_QUERY_DIRECTORY_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn11 = unsafe extern "system" fn(
        HANDLE, HANDLE, *const c_void, *const c_void, *mut [usize; 2],
        *mut c_void, u32, u32, u8, *const c_void, u8,
    ) -> NTSTATUS;
    let f: Fn11 = core::mem::transmute(pv as usize);
    let st = f(
        file_handle, event, apc_routine, apc_context, iosb,
        info_buffer, info_length, info_class,
        return_single_entry, file_name, restart_scan,
    );
    ipc_trace_send(
        TRACE_NT_QUERY_DIRECTORY_FILE, st,
        trace_args([file_handle as u64, info_class as u64,
                    info_length as u64, restart_scan as u64]),
    );
    st
}

// 22. NtCreateKey — registry key create (vs open). Cygwin's
//     mount-table lookup goes through a registry probe.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_key_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    title_index: u32,
    class: *const c_void,
    create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_KEY as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn7 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, u32, *const c_void, u32, *mut u32,
    ) -> NTSTATUS;
    let f: Fn7 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, title_index,
               class, create_options, disposition);
    ipc_trace_send(
        TRACE_NT_CREATE_KEY, st,
        trace_args([oa as u64, desired_access as u64,
                    create_options as u64]),
    );
    st
}

// 23. NtCreateMailslotFile — Cygwin uses mailslots in some IPC paths.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_mailslot_file_trace(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    create_options: u32,
    mailslot_quota: u32,
    maximum_message_size: u32,
    read_timeout: *const i64,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_CREATE_MAILSLOT_FILE as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn8 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2],
        u32, u32, u32, *const i64,
    ) -> NTSTATUS;
    let f: Fn8 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, iosb,
               create_options, mailslot_quota,
               maximum_message_size, read_timeout);
    ipc_trace_send(
        TRACE_NT_CREATE_MAILSLOT_FILE, st,
        trace_args([oa as u64, desired_access as u64,
                    create_options as u64,
                    maximum_message_size as u64]),
    );
    st
}

// 24. NtUnmapViewOfSection — DllMain may unmap; useful continuity
//     for tracking section lifetimes in DllMain.
#[no_mangle]
pub unsafe extern "system" fn hook_nt_unmap_view_of_section_trace(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS {
    let pv = IPC.passthrough_trace[TRACE_NT_UNMAP_VIEW_OF_SECTION as usize]
        .load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn2 = unsafe extern "system" fn(
        HANDLE, *mut c_void,
    ) -> NTSTATUS;
    let f: Fn2 = core::mem::transmute(pv as usize);
    let st = f(process_handle, base_address);
    ipc_trace_send(
        TRACE_NT_UNMAP_VIEW_OF_SECTION, st,
        trace_args([process_handle as u64, base_address as u64]),
    );
    st
}

// ─── Phase N-0: always-on denied-open hooks ────────────────────────
//
// These hooks tail-call the saved-original passthrough thunk first
// (so the kernel handles the syscall normally), then on
// `STATUS_ACCESS_DENIED` send an `OP_DENIED_OPEN` frame to the broker
// for stderr logging. Pays dividends in N-2 (broker-mediated open),
// N-4 (Schannel investigation), and N-5 (Cygwin debugger).
//
// Default ON. Disable via the broker's `WINSBOX_LOG_DENIES=0` env
// var, which makes the broker skip the install (the cdylib body
// stays present but unreachable).
//
// Wire format: see `OP_DENIED_OPEN` doc-comment above. Reuses the
// existing `ipc_roundtrip` (mutex-protected, one-at-a-time) so the
// deny-log channel can't corrupt the wire while a real hook is
// mid-flight.

#[inline]
unsafe fn ipc_denylog_send(
    syscall_id: u64, oa_va: u64,
    desired_access: u32, share_access: u32, options: u32, status: NTSTATUS,
) {
    if !ipc_loaded() { return; }
    let mut frame = Wire {
        op: OP_DENIED_OPEN,
        args: [
            syscall_id, oa_va,
            desired_access as u64,
            share_access as u64,
            options as u64,
            status as u32 as u64,
            0, 0, 0, 0, 0, 0,
        ],
        r0: 0, r1: 0, r2: 0, r3: 0, r_status: 0, r_error: 0,
    };
    ipc_roundtrip(&mut frame);
}

/// Phase N-2: send an `OP_BROKER_OPEN` frame and return
/// `(NTSTATUS, target-handle)`. On `STATUS_SUCCESS` the caller writes
/// `handle` into the syscall's `*FileHandle` out-param. Any other
/// status (including the original `STATUS_ACCESS_DENIED` if the
/// broker rejects the policy check) is returned to the caller
/// unchanged.
#[inline]
unsafe fn ipc_broker_open_send(
    syscall_id: u64, oa_va: u64,
    desired_access: u32, share_access: u32, options: u32,
) -> (NTSTATUS, u64) {
    if !ipc_loaded() {
        return (STATUS_ACCESS_DENIED, 0);
    }
    let mut frame = Wire {
        op: OP_BROKER_OPEN,
        args: [
            oa_va,
            desired_access as u64,
            share_access as u64,
            options as u64,
            syscall_id,
            0, 0, 0, 0, 0, 0, 0,
        ],
        r0: 0, r1: 0, r2: 0, r3: 0, r_status: 0, r_error: 0,
    };
    ipc_roundtrip(&mut frame);
    let status = frame.args[0] as u32 as i32;
    let handle = frame.args[1];
    (status, handle)
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "system" fn hook_nt_create_file_denylog(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    alloc_size: *const i64,
    file_attrs: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *const c_void,
    ea_length: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_nt_create_file_denylog.load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn11 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2], *const i64,
        u32, u32, u32, u32, *const c_void, u32,
    ) -> NTSTATUS;
    let f: Fn11 = core::mem::transmute(pv as usize);
    let st = f(
        out_handle, desired_access, oa, iosb, alloc_size,
        file_attrs, share_access, create_disposition,
        create_options, ea_buffer, ea_length,
    );
    if st == STATUS_ACCESS_DENIED {
        // Phase N-2 proxy: try to route through the broker first.
        // The broker validates against policy (allowRead / allowWrite
        // / auto-toolchain dirs), canonicalizes the path, and dups
        // the resulting handle into our process. On grant we return
        // SUCCESS with the duped handle; on rejection we fall through
        // to the legacy deny-log frame and surface the original
        // ACCESS_DENIED.
        let (bs, h) = ipc_broker_open_send(
            BROKER_OPEN_NT_CREATE_FILE, oa as u64,
            desired_access, share_access, create_options,
        );
        if bs == STATUS_SUCCESS && h != 0 {
            if !out_handle.is_null() {
                core::ptr::write(out_handle, h as HANDLE);
            }
            // Touch IO_STATUS_BLOCK so the caller's check for
            // FILE_OPENED / FILE_CREATED disposition doesn't read
            // uninitialised memory.
            if !iosb.is_null() {
                (*iosb)[0] = STATUS_SUCCESS as isize as usize;
                (*iosb)[1] = 1; // FILE_OPENED
            }
            return STATUS_SUCCESS;
        }
        // Broker either rejected or had no policy match; log and
        // return the original deny.
        ipc_denylog_send(
            DENYLOG_NT_CREATE_FILE, oa as u64,
            desired_access, share_access, create_options, st,
        );
    }
    st
}

#[no_mangle]
pub unsafe extern "system" fn hook_nt_open_file_denylog(
    out_handle: *mut HANDLE,
    desired_access: u32,
    oa: *const c_void,
    iosb: *mut [usize; 2],
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    let pv = IPC.passthrough_nt_open_file_denylog.load(Ordering::Acquire);
    if pv == 0 { return STATUS_NOT_IMPLEMENTED; }
    type Fn6 = unsafe extern "system" fn(
        *mut HANDLE, u32, *const c_void, *mut [usize; 2], u32, u32,
    ) -> NTSTATUS;
    let f: Fn6 = core::mem::transmute(pv as usize);
    let st = f(out_handle, desired_access, oa, iosb, share_access, open_options);
    if st == STATUS_ACCESS_DENIED {
        // Phase N-2 proxy: try broker mediation first (see twin in
        // `hook_nt_create_file_denylog` for full rationale).
        let (bs, h) = ipc_broker_open_send(
            BROKER_OPEN_NT_OPEN_FILE, oa as u64,
            desired_access, share_access, open_options,
        );
        if bs == STATUS_SUCCESS && h != 0 {
            if !out_handle.is_null() {
                core::ptr::write(out_handle, h as HANDLE);
            }
            if !iosb.is_null() {
                (*iosb)[0] = STATUS_SUCCESS as isize as usize;
                (*iosb)[1] = 1; // FILE_OPENED
            }
            return STATUS_SUCCESS;
        }
        ipc_denylog_send(
            DENYLOG_NT_OPEN_FILE, oa as u64,
            desired_access, share_access, open_options, st,
        );
    }
    st
}

// ─── no_std plumbing ───────────────────────────────────────────────
//
// We're a `cdylib` with `panic = "abort"` (workspace profiles, see
// `Cargo.toml`). The compiler still requires a `#[panic_handler]` for
// any `no_std` crate that produces a binary artifact. None of the
// hook bodies above panic — every fallible op returns an NTSTATUS or
// BOOL — so this handler is unreachable in practice; we spin-loop to
// be safe rather than recursing or calling abort (which would need
// another extern declaration).

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
