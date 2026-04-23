//! P9: GetFinalPathNameByHandleW does NOT canonicalize hardlinks; verify
//! that, and that nNumberOfLinks + FindFirstFileNameW give us enough to
//! detect the fan-in.

use crate::common::*;
use anyhow::{Context, Result};
use std::os::windows::io::AsRawHandle;
use windows::core::PWSTR;
use windows::Win32::Foundation::{HANDLE, MAX_PATH};
use windows::Win32::Storage::FileSystem::{
    CreateHardLinkW, FindClose, FindFirstFileNameW, FindNextFileNameW,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_NAME_NORMALIZED,
};

pub fn run() -> Result<ProbeOutcome> {
    let base = std::env::temp_dir().join(format!("srt-p9-{}", std::process::id()));
    let a = base.join("A"); let b = base.join("B");
    std::fs::create_dir_all(&a)?; std::fs::create_dir_all(&b)?;
    let src = a.join("f.txt");
    let lnk = b.join("f.txt");
    std::fs::write(&src, b"x")?;

    unsafe {
        CreateHardLinkW(
            windows::core::PCWSTR(wstr(lnk.to_str().unwrap()).as_ptr()),
            windows::core::PCWSTR(wstr(src.to_str().unwrap()).as_ptr()),
            None,
        ).context("CreateHardLinkW")?;
    }

    let f = std::fs::File::open(&lnk)?;
    let h = HANDLE(f.as_raw_handle() as isize as *mut std::ffi::c_void);

    // 1. GetFinalPathNameByHandleW returns the B path, not A.
    let mut buf = [0u16; MAX_PATH as usize * 2];
    let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, FILE_NAME_NORMALIZED) };
    let final_path = String::from_utf16_lossy(&buf[..n as usize]);
    let final_is_b = final_path.to_lowercase()
        .contains(&b.file_name().unwrap().to_string_lossy().to_lowercase());

    // 2. nNumberOfLinks == 2.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    unsafe { GetFileInformationByHandle(h, &mut info).context("GetFileInformationByHandle")?; }
    let nlinks = info.nNumberOfLinks;

    // 3. FindFirstFileNameW enumerates both names.
    let mut names = Vec::<String>::new();
    unsafe {
        let mut len = (MAX_PATH * 2) as u32;
        let mut nbuf = vec![0u16; len as usize];
        let h_find = FindFirstFileNameW(
            windows::core::PCWSTR(wstr(lnk.to_str().unwrap()).as_ptr()),
            0, &mut len, PWSTR(nbuf.as_mut_ptr()),
        );
        if let Ok(h_find) = h_find {
            names.push(String::from_utf16_lossy(&nbuf[..len as usize]).trim_end_matches('\0').to_string());
            loop {
                len = (MAX_PATH * 2) as u32;
                nbuf.iter_mut().for_each(|c| *c = 0);
                if FindNextFileNameW(h_find, &mut len, PWSTR(nbuf.as_mut_ptr())).is_err() { break; }
                names.push(String::from_utf16_lossy(&nbuf[..len as usize]).trim_end_matches('\0').to_string());
            }
            let _ = FindClose(h_find);
        }
    }
    drop(f);
    let _ = std::fs::remove_dir_all(&base);

    let detail = format!(
        "final={} (via_B={}); nlinks={}; enum=[{}]",
        final_path, final_is_b, nlinks, names.join(", ")
    );
    let pass = final_is_b && nlinks == 2 && names.len() == 2;
    Ok(if pass {
        ProbeOutcome::pass(format!("hardlink fan-in detectable: {detail}"))
    } else {
        ProbeOutcome::fail(format!("unexpected hardlink behaviour: {detail}"))
    })
}
