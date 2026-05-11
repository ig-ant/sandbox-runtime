//! `sbox-exec install` subcommand. Elevation required.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::process::Command;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::wfp;

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret: u32 = 0;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        Ok(elev.TokenIsElevated != 0)
    }
}

fn require_elevated() -> Result<()> {
    if !is_elevated()? {
        return Err(anyhow!("must run elevated; right-click and 'Run as administrator'"));
    }
    Ok(())
}

const DEFAULT_PORT: u16 = 60080;

/// `sbox-exec install` (default port `60080` if `None`).
pub fn install(port: Option<u16>) -> Result<()> {
    require_elevated()?;
    let port = port.unwrap_or(DEFAULT_PORT);
    eprintln!("[sbox-exec] install: port={port}");

    wfp::install_persistent(port).context("wfp::install_persistent")?;
    eprintln!("[sbox-exec] WFP filters installed.");

    // netsh excludedportrange — non-fatal on failure.
    let out = Command::new("netsh")
        .args([
            "int", "ipv4", "add", "excludedportrange",
            "protocol=tcp",
            &format!("startport={port}"),
            "numberofports=1",
            "store=persistent",
        ])
        .output();
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!(
                    "[sbox-exec] WARNING: netsh excludedportrange exit={}: {}{}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr),
                );
            } else {
                eprintln!("[sbox-exec] netsh: reserved port {port}");
            }
        }
        Err(e) => {
            eprintln!("[sbox-exec] WARNING: netsh failed to spawn: {e}");
        }
    }

    eprintln!("[sbox-exec] install complete: port={port}, filters=6");
    Ok(())
}

/// `sbox-exec install --remove`.
pub fn remove() -> Result<()> {
    require_elevated()?;
    let port = wfp::is_installed()?.unwrap_or(DEFAULT_PORT);

    // netsh delete — non-fatal.
    let out = Command::new("netsh")
        .args([
            "int", "ipv4", "delete", "excludedportrange",
            "protocol=tcp",
            &format!("startport={port}"),
            "numberofports=1",
            "store=persistent",
        ])
        .output();
    if let Ok(o) = out {
        if !o.status.success() {
            eprintln!(
                "[sbox-exec] netsh delete (non-fatal) exit={}: {}{}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
            );
        } else {
            eprintln!("[sbox-exec] netsh: removed reservation for port {port}");
        }
    }

    wfp::uninstall_persistent().context("wfp::uninstall_persistent")?;
    eprintln!("[sbox-exec] WFP filters removed.");
    Ok(())
}

/// `sbox-exec install --check`.
pub fn check() -> Result<()> {
    match wfp::marker_info()? {
        Some((port, sublayer_guid)) => {
            println!("installed: port={port}, sublayer_guid={sublayer_guid}");
        }
        None => {
            println!("not installed");
        }
    }
    Ok(())
}
