use crate::util::{from_pwstr, pcwstr, wstr};
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::path::PathBuf;
use windows::core::PWSTR;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows::Win32::Security::{FreeSid, PSID};

pub struct AppContainer {
    pub name: String,
    pub sid: PSID,
    pub sid_string: String,
    /// `%LOCALAPPDATA%\Packages\<name>\AC` — readable by both broker and
    /// the AC process; used for the AF_UNIX bridge sockets.
    pub folder: PathBuf,
}

impl AppContainer {
    pub fn create(tag: &str) -> Result<Self> {
        // Profile names must be ≤64 chars, no path separators.
        let name = format!("srt.{}.{}", tag, std::process::id());
        let wname = wstr(&name);
        unsafe {
            let _ = DeleteAppContainerProfile(pcwstr(&wname));
            let sid = match CreateAppContainerProfile(
                pcwstr(&wname), pcwstr(&wname), pcwstr(&wname), None,
            ) {
                Ok(s) => s,
                Err(e) if e.code().0 as u32 == 0x800700B7 => {
                    DeriveAppContainerSidFromAppContainerName(pcwstr(&wname))
                        .context("derive existing AC sid")?
                }
                Err(e) => bail!("CreateAppContainerProfile({name}): {e}"),
            };
            let mut sp = PWSTR::null();
            ConvertSidToStringSidW(sid, &mut sp).context("ConvertSidToStringSidW")?;
            let sid_string = from_pwstr(sp);
            crate::util::local_free(sp.0 as *mut c_void);

            let fp = GetAppContainerFolderPath(pcwstr(&wstr(&sid_string)))
                .context("GetAppContainerFolderPath")?;
            let folder = PathBuf::from(from_pwstr(fp));
            windows::Win32::System::Com::CoTaskMemFree(Some(fp.0 as *const c_void));
            std::fs::create_dir_all(&folder).ok();

            Ok(Self { name, sid, sid_string, folder })
        }
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.0.is_null() { FreeSid(self.sid); }
            let _ = DeleteAppContainerProfile(pcwstr(&wstr(&self.name)));
        }
    }
}
