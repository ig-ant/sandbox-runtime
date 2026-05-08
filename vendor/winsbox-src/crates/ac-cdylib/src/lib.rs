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
pub const CDYLIB_VERSION: u32 = 2;

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
}

/// Exported as a no-mangle data symbol so the broker's
/// `resolve_target_export("IPC")` returns the in-target VA of this
/// struct. Pre-resume the broker writes a contiguous `[u64; 9]`
/// directly here via `WriteProcessMemory`. Post-resume hook bodies
/// read these as `AtomicU64::load(Acquire)`.
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
