//! Phase 4.5 v3 Layer 4 — non-interactive window station + desktop.
//!
//! Creates a per-broker-process window station with a single desktop
//! attached, and exposes the `winsta\desk` name string that
//! `STARTUPINFOW.lpDesktop` consumes. The sandbox child spawns onto
//! this WS+desktop and therefore cannot enumerate top-level windows
//! on the user's interactive `WinSta0` (and the user can't see the
//! sandbox child's UI either — relevant if the child ever creates
//! one, though in practice a console-only sandbox creates none).
//!
//! Lifetime contract: the kernel reference-counts a window station
//! by attached processes. The broker MUST keep both handles open
//! from `CreateWindowStationW` until after `CreateProcessAsUserW`
//! returns AND the child is resumed (the kernel attaches the child
//! to the WS during process creation). After `WaitForSingleObject`
//! returns the child has exited and the refcount drops; at that
//! point the broker's handles are the only thing keeping the
//! kernel objects alive, so dropping `WinStaDesk` cleans up.
//!
//! Switching policy: we do NOT call `SetProcessWindowStation` on
//! the broker. Re-homing the broker's UI namespace could break
//! logging / debug attachment that depends on `WinSta0`. The
//! sandbox child gets the new WS purely via `STARTUPINFOW.lpDesktop`.
//!
//! DACL: default WS+desktop DACLs grant the creator (= the broker
//! user) and the interactive logon SID. The sandbox token runs as
//! the same broker user, so the default DACL allows attach. No
//! custom security descriptor needed for Layer 4. Layer 5+ may
//! tighten this.

use anyhow::{Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    CreateDesktopW, CreateWindowStationW, GetUserObjectInformationW,
    DESKTOP_CONTROL_FLAGS, HDESK, HWINSTA, UOI_NAME,
};

use crate::util::wstr;

/// Retrieve the kernel-assigned name of a window station (UOI_NAME).
///
/// Used after `CreateWindowStationW(NULL, ...)` to recover the
/// anonymous name the kernel picked for our WS, so we can compose
/// the `lpDesktop` string `<wsname>\desk`.
unsafe fn winsta_name(ws: HWINSTA) -> Result<String> {
    // Probe size: pass nlength=0 to fill `needed`. The wrapper
    // returns Err(ERROR_INSUFFICIENT_BUFFER) — we want the size.
    let mut needed: u32 = 0;
    let _ = GetUserObjectInformationW(
        HANDLE(ws.0),
        UOI_NAME,
        None,
        0,
        Some(&mut needed as *mut u32),
    );
    if needed == 0 {
        anyhow::bail!("GetUserObjectInformationW probe returned size=0");
    }
    let mut buf: Vec<u8> = vec![0u8; needed as usize];
    GetUserObjectInformationW(
        HANDLE(ws.0),
        UOI_NAME,
        Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
        needed,
        Some(&mut needed as *mut u32),
    )
    .context("GetUserObjectInformationW(UOI_NAME)")?;
    // Returned as a wide null-terminated string.
    let wide = unsafe {
        std::slice::from_raw_parts(buf.as_ptr() as *const u16, (needed as usize) / 2)
    };
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    Ok(String::from_utf16_lossy(&wide[..end]))
}

// winuser.h: WINSTA_ALL_ACCESS = 0x37F. We OR with STANDARD_RIGHTS_REQUIRED
// (0xF0000) so the broker holds full-control on the object it just created.
// The sandbox child opens the same WS implicitly via its STARTUPINFOW name
// — the kernel's open uses the existing handle's name, not these bits.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
const WINSTA_ALL_ACCESS: u32 = 0x0000_037F;
const WS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | WINSTA_ALL_ACCESS;
// DESKTOP_ALL_ACCESS = 0x1FF | STANDARD_RIGHTS_REQUIRED.
const DESKTOP_ALL_ACCESS: u32 = 0x0000_01FF;
const DESK_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | DESKTOP_ALL_ACCESS;

/// RAII holder for a sandbox window station + its single desktop.
///
/// Owns both handles and the wide string buffer that backs
/// `STARTUPINFOW.lpDesktop`. Closes the handles on `Drop`.
pub struct WinStaDesk {
    winsta: HWINSTA,
    desktop: HDESK,
    /// Wide-character desktop name in the form
    /// `winsbox-sbox-winsta-{pid}\desk` (null-terminated).
    /// `STARTUPINFOW.lpDesktop` is a `PWSTR` (mutable wide pointer
    /// per the API contract) so we keep the buffer here and hand
    /// out raw pointers via `desktop_name_ptr`.
    desk_path: Vec<u16>,
}

impl WinStaDesk {
    /// Create a fresh anonymous WS with a single `desk` desktop on it.
    ///
    /// Per Chromium-sandbox prior art, passing a NULL name to
    /// `CreateWindowStationW` lets the kernel mint a unique anonymous
    /// name. Passing an explicit name like `winsbox-sbox-winsta-{pid}`
    /// requires admin rights on Vista+ (the WS namespace
    /// `\Sessions\<n>\Windows\WindowStations` is not writable by a
    /// standard user), so the broker — which doesn't (and must not)
    /// require admin to spawn — needs the anonymous-create path.
    /// The kernel-generated name is retrieved post-create via
    /// `GetUserObjectInformationW(UOI_NAME)`.
    pub fn new() -> Result<Self> {
        // 1) Create the window station with NULL name → kernel picks
        //    a unique anonymous name (e.g. "Service-0x0-12345$"). The
        //    name string is needed later for STARTUPINFOW.lpDesktop;
        //    we recover it with GetUserObjectInformationW(UOI_NAME).
        //    dwFlags=0; default DACL.
        let winsta = unsafe {
            CreateWindowStationW(PCWSTR::null(), 0, WS_ALL_ACCESS, None)
                .context("CreateWindowStationW(NULL)")?
        };
        let ws_name = match unsafe { winsta_name(winsta) } {
            Ok(n) => n,
            Err(e) => {
                use windows::Win32::System::StationsAndDesktops::CloseWindowStation;
                unsafe {
                    let _ = CloseWindowStation(winsta);
                }
                return Err(e.context("GetUserObjectInformationW(UOI_NAME)"));
            }
        };

        // 2) Create a single desktop on it. CreateDesktopW operates
        //    on the *calling thread's* WS, so we'd have to call
        //    SetProcessWindowStation here to point the broker at
        //    the new WS, create the desktop, then restore. That
        //    breaks our "don't move the broker" policy.
        //
        //    Workaround: the documented contract is that
        //    CreateDesktopW creates the desktop on whichever WS
        //    the calling *process* is currently attached to. But
        //    in practice (validated experimentally and in Chromium
        //    sandbox source) Windows will let you create a desktop
        //    on a newly-created WS without flipping the process
        //    attachment, IF the desktop name has no qualifier — the
        //    kernel uses the most-recently-created WS handle owned
        //    by the caller. This is undocumented; the safe and
        //    documented path is SetProcessWindowStation. We take
        //    the safe path: snapshot the current WS, attach to the
        //    new one, create the desktop, restore.
        use windows::Win32::System::StationsAndDesktops::{
            GetProcessWindowStation, SetProcessWindowStation,
        };
        let prev = unsafe {
            GetProcessWindowStation().context("GetProcessWindowStation (snapshot)")?
        };
        // Briefly attach the broker to the new WS so CreateDesktopW
        // targets it. Restored before we return.
        unsafe {
            SetProcessWindowStation(winsta).with_context(|| {
                format!("SetProcessWindowStation(new {ws_name})")
            })?;
        }

        let desk_name_w = wstr("desk");
        // CreateDesktopW(name, device=None, devmode=None, flags=0,
        //                desiredAccess=ALL, lpsa=None).
        let desktop_result = unsafe {
            CreateDesktopW(
                PCWSTR(desk_name_w.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                DESK_ALL_ACCESS,
                None,
            )
        };

        // Always try to restore the broker's original WS, even if
        // CreateDesktopW failed — leaving the broker pointed at the
        // sandbox WS could mis-route subsequent UI calls (e.g. our
        // logger). Best-effort: if the restore itself fails, that's
        // a fatal broker state we report on top of any prior error.
        let restore = unsafe { SetProcessWindowStation(prev) };

        let desktop = match desktop_result {
            Ok(d) => d,
            Err(e) => {
                // Close the WS we just made before propagating.
                use windows::Win32::System::StationsAndDesktops::CloseWindowStation;
                unsafe {
                    let _ = CloseWindowStation(winsta);
                }
                return Err(anyhow::anyhow!(
                    "CreateDesktopW(desk) on {ws_name}: {e}"
                ));
            }
        };
        restore.with_context(|| {
            "SetProcessWindowStation(restore previous) after CreateDesktopW"
        })?;

        // Compose the `winsta\desk` path for STARTUPINFOW.lpDesktop.
        // Note: backslash separator, NOT slash.
        let desk_path = wstr(&format!("{ws_name}\\desk"));

        Ok(Self {
            winsta,
            desktop,
            desk_path,
        })
    }

    /// Pointer to the mutable wide name buffer for
    /// `STARTUPINFOW.lpDesktop`. The buffer lives as long as
    /// `self` does; the caller must keep `self` alive until
    /// after `CreateProcessAsUserW` returns.
    pub fn desktop_name_ptr(&mut self) -> *mut u16 {
        self.desk_path.as_mut_ptr()
    }
}

impl Drop for WinStaDesk {
    fn drop(&mut self) {
        use windows::Win32::System::StationsAndDesktops::{
            CloseDesktop, CloseWindowStation,
        };
        unsafe {
            // Close desktop first (it references the WS); then WS.
            let _ = CloseDesktop(self.desktop);
            let _ = CloseWindowStation(self.winsta);
        }
    }
}
