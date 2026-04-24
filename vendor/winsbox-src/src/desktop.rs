use crate::util::{pcwstr, wstr};
use anyhow::{Context, Result};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, DESKTOP_CREATEWINDOW, HDESK,
};

pub struct AltDesktop {
    pub name: String,
    h: HDESK,
}

impl AltDesktop {
    pub fn new() -> Result<Self> {
        let name = format!("srt_alt_{}", std::process::id());
        let wname = wstr(&name);
        let h = unsafe {
            CreateDesktopW(
                pcwstr(&wname), None, None,
                Default::default(), DESKTOP_CREATEWINDOW.0, None,
            ).context("CreateDesktopW")?
        };
        Ok(Self { name, h })
    }
    /// `WinSta0\<desktop>` — value for STARTUPINFOW.lpDesktop.
    pub fn qualified_name(&self) -> String {
        // Reusing the broker's window station avoids needing
        // CreateWindowStationW (which wants more privilege).
        let _ = &self.h;
        format!("WinSta0\\{}", self.name)
    }
}

impl Drop for AltDesktop {
    fn drop(&mut self) { unsafe { let _ = CloseDesktop(self.h); } }
}
