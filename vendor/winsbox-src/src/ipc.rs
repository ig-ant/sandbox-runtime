//! One IPC channel per sandboxed process. The injected
//! `NtCreateUserProcess` stub spills its 11 raw arguments into the
//! shared section, signals `ev_req`, waits on `ev_resp`, then reads
//! back the broker-supplied process/thread handles + NTSTATUS. The
//! broker side maps the same section, ReadProcessMemory's the target
//! to chase the `ProcessParameters→CommandLine` pointer, performs
//! the spawn under its own token, `DuplicateHandle`s the results
//! into the target, and replies.
//!
//! Concurrency: the section holds one request at a time. Each
//! stub `NtWaitForSingleObject(mutex)` before writing args and
//! `NtReleaseMutant(mutex)` after reading the reply. A spinlock
//! is unsafe here — `ExitProcess` terminates threads at
//! arbitrary points, so a thread killed mid-stub leaves a
//! spinlock held forever and any `DLL_PROCESS_DETACH` callback
//! that hits a hooked syscall spins (observed at 12e3d0d). A
//! mutant is abandoned on owner-thread death and the next
//! waiter's `NtWaitForSingleObject` returns `STATUS_ABANDONED`,
//! which the stub treats as acquired.

use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE,
    NTSTATUS,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetCurrentProcess, SetEvent, WaitForSingleObject,
};

// Op-codes for the cdylib hook bodies' IPC frames. The legacy
// FS/Reg/Attr ops (NtCreateFile / NtOpenFile / NtQuery*Attributes /
// NtOpenKey* / NtOpenSection) were dropped in D-4: ACL stamping
// replaces broker-mediated FS/Reg policy, and `NtOpenSection`
// returned only for namespace-redirect cases (kept here as
// `OP_NTOPENSECTION`).
pub const OP_CPW: u64 = 0;
pub const OP_NTOPENSECTION: u64 = 5;
/// N-7 retry: Cygwin's path_conv calls NtQueryAttributesFile /
/// NtQueryFullAttributesFile to stat-style probe files (every
/// /etc/passwd, /etc/profile, /dev/null translation) before the
/// heavier NtCreateFile open. Under USER_LIMITED+AC the saved
/// original returns STATUS_ACCESS_DENIED (path_conv requires
/// FILE_READ_ATTRIBUTES on the *parent* directory, which our
/// per-AC ACL stamps don't always grant). The cdylib's
/// `hook_NtQueryAttributesFile` / `hook_NtQueryFullAttributesFile`
/// observe the deny and IPC the broker; the broker re-issues
/// under its own user-token after a `broker_open`-style policy
/// check, then writes the result struct back via
/// `attr_result_offset()` and replies with `reply_attr_query`.
pub const OP_NTQUERYATTR: u64 = 6;
pub const OP_NTQUERYFULLATTR: u64 = 7;
pub const OP_NTCREATEDIROBJ: u64 = 8;
pub const OP_NTOPENDIROBJ: u64 = 9;
pub const OP_NTCREATENAMEDPIPE: u64 = 10;

/// Phase K trace frame. Sent by the cdylib's `hook_*_trace` bodies
/// after the passthrough thunk has run; broker logs the syscall +
/// arg summary + NTSTATUS to stderr and replies with a no-op ACK.
/// `args[0]` holds the trace-syscall-id (see `TRACE_*` constants
/// below); the remaining `args` slots are op-specific arg pointers.
pub const OP_TRACE: u64 = 100;

/// Phase N-0: always-on denied-open frame. Sent by the cdylib's
/// `hook_NtCreateFile_denylog` / `hook_NtOpenFile_denylog` after the
/// saved-original passthrough returned `STATUS_ACCESS_DENIED`. Broker
/// chases `args[1]` (OBJECT_ATTRIBUTES* VA) via `ReadProcessMemory`,
/// renders the wide path truncated to 256 bytes, and emits one
/// `[sbox-exec] denied-open: …` line on stderr. Reply is a no-op ACK.
///
/// Wire layout (see cdylib `OP_DENIED_OPEN` doc):
///   args[0] = syscall id (0=NtCreateFile, 1=NtOpenFile)
///   args[1] = OBJECT_ATTRIBUTES* VA
///   args[2] = desired_access (u32)
///   args[3] = share_access   (u32)
///   args[4] = options        (u32 — CreateOptions / OpenOptions)
///   args[5] = status         (u32 — always 0xC0000022 today)
pub const OP_DENIED_OPEN: u64 = 101;

/// Phase N-0: deny-log syscall ids. Independent numbering from the
/// `TRACE_*` family — the broker's deny-log handler maps these
/// directly to ntdll syscall names.
pub const DENYLOG_NT_CREATE_FILE: u64 = 0;
pub const DENYLOG_NT_OPEN_FILE: u64 = 1;

/// Phase N-2: broker-mediated open frame. Sent by the cdylib's
/// `hook_NtCreateFile_proxy` / `hook_NtOpenFile_proxy` after the
/// saved-original passthrough returned `STATUS_ACCESS_DENIED` — the
/// broker re-opens under its own user-token, validates against
/// policy (allowRead/allowWrite plus auto-detected toolchain dirs),
/// canonicalizes via `GetFinalPathNameByHandleW` to defeat symlink/
/// junction escapes, and `DuplicateHandle`s the result into the AC.
///
/// Wire layout:
///   args[0] = OBJECT_ATTRIBUTES* VA (broker chases via RPM)
///   args[1] = desired_access (u32)
///   args[2] = share_access   (u32)
///   args[3] = options        (u32 — CreateOptions / OpenOptions)
///   args[4] = syscall id (`SYSCALL_NT_CREATE_FILE` / `_NT_OPEN_FILE`)
/// Reply (in same `Wire` struct):
///   args[0] = NTSTATUS (u32)
///   args[1] = duped HANDLE on success (u64), 0 on rejection
pub const OP_BROKER_OPEN: u64 = 102;

/// Phase N-2: syscall ids for `OP_BROKER_OPEN`. Match the cdylib's
/// `BROKER_OPEN_NT_CREATE_FILE` / `_NT_OPEN_FILE` constants.
pub const BROKER_OPEN_NT_CREATE_FILE: u64 = 0;
pub const BROKER_OPEN_NT_OPEN_FILE: u64 = 1;

// ─── Phase K: trace-mode syscall IDs ───────────────────────────────
//
// Indexed into `IpcEnv.passthrough_trace` on the cdylib side and
// `TRACE_SYSCALL_NAMES` here. Order must match the cdylib's
// `TRACE_*` constants byte-for-byte.

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
// Phase L cycle 3: extend trace coverage to loader-time syscalls.
// The original 12 hooks (file/IOCTL/ALPC/registry/sync) emit zero
// trace lines for Cygwin targets — bash AVs before the first
// NtCreateFile fires. The loader's pre-DllMain bootstrap uses
// NtMapViewOfSection (every DLL load), NtCreateSection (Cygwin's
// shared-cygheap), and NtAllocateVirtualMemory (heap/stack init);
// adding these gives us a syscall trail right up to the AV.
pub const TRACE_NT_MAP_VIEW_OF_SECTION: u64 = 12;
pub const TRACE_NT_CREATE_SECTION: u64 = 13;
pub const TRACE_NT_ALLOCATE_VIRTUAL_MEMORY: u64 = 14;
// Phase N-5: Cygwin DllMain coverage. The 15 prior hooks left a
// trace coverage gap during cygwin1.dll's DllMain. These 15 cover
// section opens (H1: cygwin1S5-sect), token+process queries
// (H4-H6: PEB walks, env probes), file-control / metadata writes,
// directory enum, registry create, and handle close (continuity).
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

pub const TRACE_SYSCALL_COUNT: usize = 30;

/// (id → ntdll export name) lookup for the install path *and* the
/// log emitter. Indexed by the `TRACE_*` ids above.
pub const TRACE_SYSCALL_NAMES: [&str; TRACE_SYSCALL_COUNT] = [
    "NtCreateFile",
    "NtOpenFile",
    "NtDeviceIoControlFile",
    "NtAlpcConnectPort",
    "NtAlpcSendWaitReceivePort",
    "NtOpenKey",
    "NtOpenKeyEx",
    "NtQueryValueKey",
    "NtCreateEvent",
    "NtOpenEvent",
    "NtCreateMutant",
    "NtOpenMutant",
    "NtMapViewOfSection",
    "NtCreateSection",
    "NtAllocateVirtualMemory",
    // Phase N-5 additions.
    "NtOpenSection",
    "NtQueryInformationProcess",
    "NtOpenProcessToken",
    "NtOpenThreadToken",
    "NtQueryInformationToken",
    "NtQuerySystemInformation",
    "NtReadVirtualMemory",
    "NtClose",
    "NtCreateNamedPipeFile",
    "NtFsControlFile",
    "NtSetInformationFile",
    "NtQueryDirectoryFile",
    "NtCreateKey",
    "NtCreateMailslotFile",
    "NtUnmapViewOfSection",
];

/// Sentinel `r_status` the broker returns when the cdylib hook
/// should tail-call the saved-original syscall (the kernel handles
/// the open natively) instead of returning the broker's reply.
/// Used for `\Device\*` and any path the broker doesn't redirect.
pub const FS_PASSTHROUGH: i32 = 0xE0000001u32 as i32;

/// N-7 retry: section offset for the
/// `NtQuery{,Full}AttributesFile` result struct. Sized for the
/// larger of `FILE_BASIC_INFORMATION` (40 bytes) and
/// `FILE_NETWORK_OPEN_INFORMATION` (56 bytes). Past the `Wire`
/// trailer (0x88) — guaranteed not to overlap the request frame.
pub const ATTR_RESULT_OFF: usize = 0x90;
pub const ATTR_RESULT_LEN: usize = 56;

/// Section layout shared by every hook stub. The stub writes `op`
/// + `args`; the broker writes the `r*` fields. Field meaning is
/// op-dependent. Handle values are target-side; pointer values
/// are target-VA.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Wire {
    pub op: u64,             // 0x00
    /// rcx,rdx,r8,r9,[rsp+0x28..0x60] — up to 12 raw arguments.
    pub args: [u64; 12],     // 0x08..0x68
    /// CPW: hProcess.    FS: out FileHandle (target-side).
    pub r0: u64,             // 0x68
    /// CPW: hThread.     FS: IO_STATUS_BLOCK.Information.
    pub r1: u64,             // 0x70
    /// CPW: dwProcessId. FS: unused.
    pub r2: u32,             // 0x78
    /// CPW: dwThreadId.
    pub r3: u32,             // 0x7c
    /// CPW: BOOL result. FS: NTSTATUS.
    pub r_status: i32,       // 0x80
    /// CPW: GetLastError on failure.
    pub r_error: u32,        // 0x84
}
const _: () = assert!(size_of::<Wire>() == 0x88);

pub const SECTION_SIZE: usize = 4096;

/// Target-side addresses the stub emitter needs. Copyable so the
/// broker can install hooks both before and after moving the
/// `Channel` into its service thread.
#[derive(Clone, Copy)]
pub struct StubAddrs {
    pub section: usize,
    pub ev_req: u64,
    pub ev_resp: u64,
    pub mutex: u64,
}

pub struct Channel {
    pub section: HANDLE,
    /// Broker-side mapped view.
    pub view: *mut Wire,
    /// Target-side mapped VA (where the stub will read/write).
    pub target_view: usize,
    /// Broker-side event handles.
    pub ev_req: HANDLE,
    pub ev_resp: HANDLE,
    /// Target-side handle values for the same events (post-DuplicateHandle).
    pub t_ev_req: u64,
    pub t_ev_resp: u64,
    /// Per-channel mutant. Broker side never waits on it; only
    /// the target-side stubs do (target-side handle below).
    pub mutex: HANDLE,
    pub t_mutex: u64,
    /// The target process this channel is bound to.
    pub target: HANDLE,
}
unsafe impl Send for Channel {}

impl Channel {
    /// Create the section + events in the broker, map the section
    /// into both the broker and the (suspended) target, and
    /// duplicate the event handles into the target so the stub can
    /// signal/wait on them by raw value.
    pub fn create(target: HANDLE) -> Result<Self> {
        unsafe {
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: false.into(),
            };
            let section = CreateFileMappingW(
                INVALID_HANDLE_VALUE, Some(&sa), PAGE_READWRITE,
                0, SECTION_SIZE as u32, None,
            ).context("CreateFileMappingW")?;
            let view = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, SECTION_SIZE);
            if view.Value.is_null() { bail!("MapViewOfFile (broker)"); }
            std::ptr::write_bytes(view.Value, 0, SECTION_SIZE);

            // Map into target via NtMapViewOfSection.
            let target_view = map_into_target(section, target)?;

            let ev_req = CreateEventW(Some(&sa), false, false, None)
                .context("CreateEventW(req)")?;
            let ev_resp = CreateEventW(Some(&sa), false, false, None)
                .context("CreateEventW(resp)")?;
            let mutex = CreateMutexW(Some(&sa), false, None)
                .context("CreateMutexW")?;
            let t_ev_req = dup_into(target, ev_req)?;
            let t_ev_resp = dup_into(target, ev_resp)?;
            let t_mutex = dup_into(target, mutex)?;

            Ok(Self {
                section,
                view: view.Value as *mut Wire,
                target_view,
                ev_req, ev_resp,
                t_ev_req, t_ev_resp,
                mutex, t_mutex,
                target,
            })
        }
    }

    /// Block until the stub signals a request (or `timeout_ms`
    /// elapses); copy the section into a local `Wire` so the target
    /// cannot mutate it mid-handle. Returns None on timeout.
    pub fn wait_request(&self, timeout_ms: u32) -> Option<Wire> {
        unsafe {
            let r = WaitForSingleObject(self.ev_req, timeout_ms);
            if r != windows::Win32::Foundation::WAIT_OBJECT_0 { return None; }
            Some(std::ptr::read_volatile(self.view))
        }
    }

    pub fn reply_cpw_ok(&self, hproc: u64, hthread: u64, pid: u32, tid: u32) {
        unsafe {
            (*self.view).r0 = hproc;
            (*self.view).r1 = hthread;
            (*self.view).r2 = pid;
            (*self.view).r3 = tid;
            (*self.view).r_status = 1;
            (*self.view).r_error  = 0;
            let _ = SetEvent(self.ev_resp);
        }
    }
    pub fn reply_cpw_err(&self, error: u32) {
        unsafe {
            (*self.view).r0 = 0; (*self.view).r1 = 0;
            (*self.view).r2 = 0; (*self.view).r3 = 0;
            (*self.view).r_status = 0;
            (*self.view).r_error  = error;
            let _ = SetEvent(self.ev_resp);
        }
    }
    pub fn reply_fs(&self, handle: u64, iosb_info: u64, status: i32) {
        unsafe {
            (*self.view).r0 = handle;
            (*self.view).r1 = iosb_info;
            (*self.view).r_status = status;
            let _ = SetEvent(self.ev_resp);
        }
    }

    /// Phase K: ACK a `OP_TRACE` request. Trace frames are one-way
    /// from a semantic standpoint (the broker only logs and doesn't
    /// modify caller state), but the cdylib's `ipc_roundtrip` still
    /// waits on `ev_resp` before releasing the per-channel mutant —
    /// without that wait, the next thread's frame would race the
    /// broker's read of the previous one. So we set `ev_resp` here
    /// without touching any reply fields.
    pub fn reply_trace_ack(&self) {
        unsafe { let _ = SetEvent(self.ev_resp); }
    }

    /// Phase N-0: ACK an `OP_DENIED_OPEN` request. Same one-way
    /// semantics as `reply_trace_ack` — broker logs and signals back
    /// without touching reply fields.
    pub fn reply_denylog_ack(&self) {
        unsafe { let _ = SetEvent(self.ev_resp); }
    }

    /// N-7 retry: reply to an `OP_NTQUERYATTR` / `OP_NTQUERYFULLATTR`
    /// frame. Writes the broker-issued result struct (≤56 bytes —
    /// `FILE_BASIC_INFORMATION` for the short variant,
    /// `FILE_NETWORK_OPEN_INFORMATION` for the full one) into the
    /// shared section past the `Wire` trailer at `ATTR_RESULT_OFF`,
    /// then signals `ev_resp`. The cdylib reads `r_status` plus the
    /// result bytes and copies them into the caller's output buffer
    /// before returning to ntdll.
    pub fn reply_attr_query(&self, status: i32, attrs: &[u8]) {
        unsafe {
            let len = attrs.len().min(ATTR_RESULT_LEN);
            let dst = (self.view as *mut u8).add(ATTR_RESULT_OFF);
            std::ptr::copy_nonoverlapping(attrs.as_ptr(), dst, len);
            (*self.view).r_status = status;
            let _ = SetEvent(self.ev_resp);
        }
    }

    /// Phase N-2: reply to an `OP_BROKER_OPEN` frame. Writes the
    /// resulting NTSTATUS into `args[0]` and the duped target-side
    /// handle (or 0) into `args[1]`, then signals `ev_resp`. The
    /// cdylib reads these back from its local `Wire` copy after
    /// `ipc_roundtrip` returns and writes the handle into the
    /// caller's `*FileHandle` if status >= 0.
    pub fn reply_broker_open(&self, status: i32, handle: u64) {
        unsafe {
            (*self.view).args[0] = status as u32 as u64;
            (*self.view).args[1] = handle;
            (*self.view).r_status = status;
            let _ = SetEvent(self.ev_resp);
        }
    }

    /// Duplicate a broker-owned handle into the target's table and
    /// return the target-side value.
    pub fn dup_to_target(&self, h: HANDLE) -> Result<u64> {
        dup_into(self.target, h)
    }

    pub fn stub_env_snapshot(&self) -> StubAddrs {
        StubAddrs {
            section: self.target_view,
            ev_req: self.t_ev_req,
            ev_resp: self.t_ev_resp,
            mutex: self.t_mutex,
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: self.view as *mut c_void });
            let _ = CloseHandle(self.section);
            let _ = CloseHandle(self.ev_req);
            let _ = CloseHandle(self.ev_resp);
            let _ = CloseHandle(self.mutex);
        }
    }
}

pub fn dup_into(target: HANDLE, src: HANDLE) -> Result<u64> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateHandle(
            GetCurrentProcess(), src, target, &mut out,
            0, false, DUPLICATE_SAME_ACCESS,
        ).context("DuplicateHandle into target")?;
        Ok(out.0 as u64)
    }
}

/// `NtMapViewOfSection` the section into the target's address space
/// (RW) and return the target-VA base.
fn map_into_target(section: HANDLE, target: HANDLE) -> Result<usize> {
    #[link(name = "ntdll")]
    extern "system" {
        fn NtMapViewOfSection(
            section: HANDLE, process: HANDLE, base: *mut *mut c_void,
            zero_bits: usize, commit: usize, offset: *mut i64,
            view_size: *mut usize, inherit: u32, alloc_type: u32, protect: u32,
        ) -> NTSTATUS;
    }
    unsafe {
        let mut base: *mut c_void = std::ptr::null_mut();
        let mut size: usize = 0;
        let mut off: i64 = 0;
        // MEM_TOP_DOWN: keep the IPC section out of the
        // address range Cygwin's fork() remaps the parent's
        // heap into.
        let st = NtMapViewOfSection(
            section, target, &mut base, 0, 0, &mut off, &mut size,
            2 /* ViewUnmap */, 0x00100000 /* MEM_TOP_DOWN */, PAGE_READWRITE.0,
        );
        if st.0 < 0 { bail!("NtMapViewOfSection: {:#x}", st.0); }
        Ok(base as usize)
    }
}
