//! One IPC channel per sandboxed process. The injected
//! `NtCreateUserProcess` stub spills its 11 raw arguments into the
//! shared section, signals `ev_req`, waits on `ev_resp`, then reads
//! back the broker-supplied process/thread handles + NTSTATUS. The
//! broker side maps the same section, ReadProcessMemory's the target
//! to chase the `ProcessParameters→CommandLine` pointer, performs
//! the spawn under its own token, `DuplicateHandle`s the results
//! into the target, and replies.
//!
//! No mutex in v1 — `cmd.exe` issues spawns serially on its main
//! thread, and there is one section per process so no cross-process
//! contention. Add the mutex when multi-threaded targets show up.

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
    CreateEventW, GetCurrentProcess, SetEvent, WaitForSingleObject,
};

/// Section layout. The stub writes [0..0x58); the broker writes
/// [0x60..0x80). All fields are raw 64-bit values (handles are
/// target-side handle table entries; pointers are target-VA).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Wire {
    pub args: [u64; 11],     // 0x00..0x58: rcx,rdx,r8,r9,[rsp+0x28..0x58]
    pub _pad: u64,           // 0x58
    pub out_process: u64,    // 0x60: target-side HANDLE
    pub out_thread: u64,     // 0x68
    pub out_status: i32,     // 0x70: NTSTATUS
    pub out_pid: u32,        // 0x74
}
const _: () = assert!(size_of::<Wire>() == 0x78);

pub const SECTION_SIZE: usize = 4096;

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
            let t_ev_req = dup_into(target, ev_req)?;
            let t_ev_resp = dup_into(target, ev_resp)?;

            Ok(Self {
                section,
                view: view.Value as *mut Wire,
                target_view,
                ev_req, ev_resp,
                t_ev_req, t_ev_resp,
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

    pub fn reply(&self, out_process: u64, out_thread: u64, status: i32, pid: u32) {
        unsafe {
            (*self.view).out_process = out_process;
            (*self.view).out_thread  = out_thread;
            (*self.view).out_status  = status;
            (*self.view).out_pid     = pid;
            let _ = SetEvent(self.ev_resp);
        }
    }

    /// Duplicate a broker-owned handle into the target's table and
    /// return the target-side value.
    pub fn dup_to_target(&self, h: HANDLE) -> Result<u64> {
        dup_into(self.target, h)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: self.view as *mut c_void });
            let _ = CloseHandle(self.section);
            let _ = CloseHandle(self.ev_req);
            let _ = CloseHandle(self.ev_resp);
        }
    }
}

fn dup_into(target: HANDLE, src: HANDLE) -> Result<u64> {
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
        let st = NtMapViewOfSection(
            section, target, &mut base, 0, 0, &mut off, &mut size,
            2 /* ViewUnmap */, 0, PAGE_READWRITE.0,
        );
        if st.0 < 0 { bail!("NtMapViewOfSection: {:#x}", st.0); }
        Ok(base as usize)
    }
}
