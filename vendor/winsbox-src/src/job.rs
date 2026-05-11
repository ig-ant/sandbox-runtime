// Cribbed from `winsbox-msys2-iter` branch, lowbox/AC paths removed.
//! Job object wrapper. Used purely for KILL_ON_JOB_CLOSE process
//! containment (so the sandboxed child tree dies with the broker).
//!
//! UI restrictions are intentionally NOT set for v1 — the WFP+SID
//! design targets "max compat", and Cygwin/PowerShell exercise paths
//! (clipboard, global atoms) that benefit from a normal Win32 session.
//
// TODO(phase2): revisit UI restrictions once the network sandbox is
// working — they're free-ish containment if compat allows.

use anyhow::{Context, Result};
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub struct Job(HANDLE);

impl Job {
    pub fn handle(&self) -> HANDLE { self.0 }
    pub fn new() -> Result<Self> {
        unsafe {
            let h = CreateJobObjectW(None, None).context("CreateJobObjectW")?;
            let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h, JobObjectExtendedLimitInformation,
                &ext as *const _ as *const std::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ).context("SetInformationJobObject(KILL_ON_JOB_CLOSE)")?;

            // TODO(phase2): revisit UI restrictions. Donor branch set:
            //   JOB_OBJECT_UILIMIT_{DESKTOP,DISPLAYSETTINGS,EXITWINDOWS,
            //   GLOBALATOMS,HANDLES,READCLIPBOARD,WRITECLIPBOARD,
            //   SYSTEMPARAMETERS}
            // Disabled for now — see module docstring.

            Ok(Self(h))
        }
    }
    pub fn assign(&self, proc: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.0, proc).context("AssignProcessToJobObject") }
    }
}

impl Drop for Job {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } }
}
