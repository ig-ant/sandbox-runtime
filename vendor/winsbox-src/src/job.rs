// Cribbed from `winsbox-msys2-iter` branch, lowbox/AC paths removed.
//! Job object wrapper.
//!
//! Two roles:
//!  1. `KILL_ON_JOB_CLOSE` process containment so the sandboxed child
//!     tree dies with the broker.
//!  2. Phase 4.5 v3 Layer 3: `JobObjectBasicUIRestrictions` UI lockdown
//!     (clipboard, global atoms, system params, display, desktop,
//!     exit-windows, and cross-job USER/GDI handle access).
//!
//! UI bits are listed individually (rather than `UILIMIT_ALL`) so the
//! enforced surface is auditable from the call site.

use anyhow::{Context, Result};
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
    JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};

pub struct Job(HANDLE);

impl Job {
    #[allow(dead_code)]
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

            // Phase 4.5 v3 Layer 3: basic UI restrictions. Must be set
            // before `AssignProcessToJobObject` so the bits are in
            // effect from the moment the suspended child is assigned
            // (caller resumes the thread only after assign). The bits
            // below are equivalent to JOB_OBJECT_UILIMIT_ALL but
            // enumerated for auditability:
            //   READCLIPBOARD     — block OpenClipboard for read
            //   WRITECLIPBOARD    — block SetClipboardData
            //   HANDLES           — block USER/GDI handles from outside the job
            //   GLOBALATOMS       — block GlobalAddAtom (atom-table IPC)
            //   SYSTEMPARAMETERS  — block SystemParametersInfoW(SPI_SET*)
            //   DISPLAYSETTINGS   — block ChangeDisplaySettings
            //   DESKTOP           — block SwitchDesktop/SetThreadDesktop
            //   EXITWINDOWS       — block sandbox-initiated logoff/shutdown
            let ui_bits = JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS;
            let ui_info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: ui_bits,
            };
            SetInformationJobObject(
                h, JobObjectBasicUIRestrictions,
                &ui_info as *const _ as *const std::ffi::c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ).context("SetInformationJobObject(BasicUIRestrictions)")?;

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
