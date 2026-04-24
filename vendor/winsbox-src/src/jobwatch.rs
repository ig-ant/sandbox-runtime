//! Re-apply the initial impersonation token to grandchildren via
//! Job-object completion-port notifications. When any process in the
//! Job spawns a child, the kernel auto-assigns it to the Job and posts
//! `JOB_OBJECT_MSG_NEW_PROCESS(pid)` to the port; the broker opens the
//! new process, suspends it, finds its main thread, SetThreadToken's
//! the initial impersonation, and resumes. There is a small race
//! (the child may run a few instructions before suspend), but for
//! cooperative targets the loader's first file open typically lands
//! after the broker has acted. Full ntdll interception (Phase-2b
//! follow-up) closes the race for adversarial targets.

use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows::Win32::System::JobObjects::{
    SetInformationJobObject, JobObjectAssociateCompletionPortInformation,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
};
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, SetThreadToken, PROCESS_ALL_ACCESS,
    THREAD_SET_THREAD_TOKEN, THREAD_SUSPEND_RESUME,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(h: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(h: HANDLE) -> NTSTATUS;
}

pub struct JobWatch {
    port: HANDLE,
}
// HANDLE wraps *mut c_void which isn't Send; the value is just an
// opaque kernel handle and is safe to use from another thread.
unsafe impl Send for JobWatch {}

impl JobWatch {
    pub fn attach(job: HANDLE) -> Result<Self> {
        unsafe {
            let port = CreateIoCompletionPort(
                windows::Win32::Foundation::INVALID_HANDLE_VALUE, None, 0, 1,
            ).context("CreateIoCompletionPort")?;
            let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: job.0 as *mut c_void,
                CompletionPort: port,
            };
            SetInformationJobObject(
                job, JobObjectAssociateCompletionPortInformation,
                &assoc as *const _ as *const c_void,
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            ).context("SetInformationJobObject(CompletionPort)")?;
            Ok(Self { port })
        }
    }

    /// Blocks servicing notifications until `stop` becomes true. For
    /// each NEW_PROCESS, suspend → SetThreadToken(initial) on every
    /// thread → resume. `skip` PIDs (the immediate target and the
    /// inside-relay) already have impersonation set by the launch
    /// path and must not be re-suspended.
    pub fn run(
        &self,
        initial: HANDLE,
        skip: &[u32],
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        unsafe {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let mut bytes = 0u32;
                let mut key = 0usize;
                let mut ov = std::ptr::null_mut();
                let ok = GetQueuedCompletionStatus(
                    self.port, &mut bytes, &mut key, &mut ov, 250,
                );
                if ok.is_err() { continue; } // timeout or shutdown
                if bytes != JOB_OBJECT_MSG_NEW_PROCESS { continue; }
                let pid = ov as u32;
                if pid == 0 || skip.contains(&pid) { continue; }
                eprintln!("[sbox-exec] jobwatch: new process pid={pid}, re-impersonating");
                let _ = reimpersonate(pid, initial);
            }
        }
    }
}

impl Drop for JobWatch {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.port); } }
}

fn reimpersonate(pid: u32, initial: HANDLE) -> Result<()> {
    unsafe {
        let proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .context("OpenProcess")?;
        // Stop the process so the loader doesn't race us.
        let _ = NtSuspendProcess(proc);
        // Set the impersonation on every thread (typically one at
        // this point — the initial thread).
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .context("CreateToolhelp32Snapshot")?;
        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    if let Ok(th) = OpenThread(
                        THREAD_SET_THREAD_TOKEN | THREAD_SUSPEND_RESUME, false, te.th32ThreadID,
                    ) {
                        let _ = SetThreadToken(Some(&th), initial);
                        let _ = CloseHandle(th);
                    }
                }
                if Thread32Next(snap, &mut te).is_err() { break; }
            }
        }
        let _ = CloseHandle(snap);
        let _ = NtResumeProcess(proc);
        let _ = CloseHandle(proc);
        Ok(())
    }
}
