use anyhow::{Context, Result};
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
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

            let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass:
                    JOB_OBJECT_UILIMIT_DESKTOP
                    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                    | JOB_OBJECT_UILIMIT_EXITWINDOWS
                    | JOB_OBJECT_UILIMIT_GLOBALATOMS
                    | JOB_OBJECT_UILIMIT_HANDLES
                    | JOB_OBJECT_UILIMIT_READCLIPBOARD
                    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            };
            SetInformationJobObject(
                h, JobObjectBasicUIRestrictions,
                &ui as *const _ as *const std::ffi::c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ).context("SetInformationJobObject(UIRestrictions)")?;
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
