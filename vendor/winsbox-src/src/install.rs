//! `sbox-exec install` subcommand. Elevation required for install /
//! remove (NetLocalGroup* + WFP both require admin); `--check` and
//! `--verify` are unprivileged.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::process::Command;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::{sid, wfp};

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
        return Err(anyhow!(
            "must run elevated; right-click and 'Run as administrator'"
        ));
    }
    Ok(())
}

const DEFAULT_PORT: u16 = 60080;

/// `sbox-exec install` — provision local group, install WFP filters,
/// reserve port, write marker.
pub fn install(port: Option<u16>) -> Result<()> {
    require_elevated()?;
    let port = port.unwrap_or(DEFAULT_PORT);
    eprintln!("[sbox-exec] install: port={port}");

    // 1) Local group.
    wfp::ensure_group_exists().context("ensure local group")?;
    eprintln!("[sbox-exec] local group present: {}", wfp::GROUP_NAME);

    // 2) Resolve broker user SID, add to group.
    let user_sid = sid::current_user_sid().context("current_user_sid")?;
    wfp::add_user_to_group(&user_sid)
        .with_context(|| format!("add {user_sid} to {}", wfp::GROUP_NAME))?;
    eprintln!("[sbox-exec] user {user_sid} added to group");

    // 3) Resolve group SID.
    let group_sid = sid::lookup_local_account_sid(wfp::GROUP_NAME)
        .with_context(|| format!("LookupAccountNameW({})", wfp::GROUP_NAME))?;
    eprintln!("[sbox-exec] group_sid={group_sid}");

    // 4) WFP filters.
    wfp::install_filters(port, &group_sid, &user_sid)
        .context("wfp::install_filters")?;
    eprintln!("[sbox-exec] WFP filters installed.");

    // 5) Marker file.
    let marker = wfp::Marker {
        port,
        sublayer_guid: wfp::sublayer_guid_string(),
        group_name: wfp::GROUP_NAME.to_string(),
        group_sid,
        user_sid,
    };
    wfp::write_install_marker(&marker).context("write marker")?;

    // 6) Port reservation — non-fatal.
    let out = Command::new("netsh")
        .args([
            "int",
            "ipv4",
            "add",
            "excludedportrange",
            "protocol=tcp",
            &format!("startport={port}"),
            "numberofports=1",
            "store=persistent",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            eprintln!("[sbox-exec] netsh: reserved port {port}");
        }
        Ok(o) => {
            eprintln!(
                "[sbox-exec] WARNING: netsh excludedportrange exit={}: {}{}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
            );
        }
        Err(e) => {
            eprintln!("[sbox-exec] WARNING: netsh failed to spawn: {e}");
        }
    }

    eprintln!("[sbox-exec] install complete: port={port}, filters=6");
    eprintln!();
    eprintln!("  *** Log out and log back in to activate sandbox membership. ***");
    eprintln!("  The new group SID is built into TokenGroups at logon; existing");
    eprintln!("  sessions (including this one) won't see it until you re-login.");
    Ok(())
}

/// `sbox-exec install --remove [--keep-group]`.
pub fn remove(keep_group: bool) -> Result<()> {
    require_elevated()?;

    let marker = wfp::read_install_marker().ok().flatten();
    let port = marker.as_ref().map(|m| m.port).unwrap_or(DEFAULT_PORT);

    // 1) netsh delete — non-fatal.
    let out = Command::new("netsh")
        .args([
            "int",
            "ipv4",
            "delete",
            "excludedportrange",
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

    // 2) WFP filters.
    wfp::uninstall_filters().context("wfp::uninstall_filters")?;
    eprintln!("[sbox-exec] WFP filters removed.");

    // 3) Group. The cascade in NetLocalGroupDel removes memberships; we
    // don't separately remove the user.
    if !keep_group {
        wfp::delete_group().context("delete local group")?;
        eprintln!("[sbox-exec] local group {} deleted.", wfp::GROUP_NAME);
    } else {
        eprintln!(
            "[sbox-exec] --keep-group: leaving local group {} intact.",
            wfp::GROUP_NAME
        );
    }

    // 4) Marker.
    wfp::remove_install_marker().context("remove marker")?;
    eprintln!("[sbox-exec] marker file removed.");
    Ok(())
}

/// `sbox-exec install --check` — print marker contents (terse).
pub fn check() -> Result<()> {
    match wfp::read_install_marker()? {
        Some(m) => {
            println!(
                "installed: port={} sublayer_guid={} group={} group_sid={} user_sid={}",
                m.port, m.sublayer_guid, m.group_name, m.group_sid, m.user_sid,
            );
        }
        None => {
            println!("not installed");
        }
    }
    Ok(())
}

/// `sbox-exec install --verify` — deeper-than-check: confirms the
/// current user's token has the group present + enabled, the local
/// group exists in SAM, and the marker is consistent.
pub fn verify() -> Result<()> {
    let marker = match wfp::read_install_marker()? {
        Some(m) => m,
        None => {
            println!("verify: NOT INSTALLED (no marker file)");
            return Ok(());
        }
    };
    println!(
        "marker: port={} group={} group_sid={} user_sid={}",
        marker.port, marker.group_name, marker.group_sid, marker.user_sid
    );

    let user_sid = sid::current_user_sid().context("current_user_sid")?;
    println!("current user SID: {user_sid}");
    if user_sid != marker.user_sid {
        println!(
            "  WARNING: current user SID does not match marker user_sid \
             ({user_sid} vs {})",
            marker.user_sid
        );
    } else {
        println!("  ok: current user matches marker");
    }

    let group_exists = wfp::group_exists()?;
    println!("local group {} exists: {group_exists}", marker.group_name);

    let state = sid::group_state_for_self(&marker.group_sid)?;
    println!("group state in current TokenGroups: {state:?}");
    match state {
        sid::GroupState::Enabled => {
            println!("  ok: group is enabled — broker can launch sandbox children");
        }
        sid::GroupState::DenyOnly => {
            println!(
                "  WARNING: group is deny-only — this token is already \
                 sandbox-flagged. Broker must not run from inside a sandbox child."
            );
        }
        sid::GroupState::Present => {
            println!(
                "  WARNING: group is present but neither enabled nor deny-only \
                 (unexpected attribute state)."
            );
        }
        sid::GroupState::Absent => {
            println!(
                "  WARNING: group is ABSENT from TokenGroups. The new \
                 membership only takes effect after the next logon — \
                 log out and log back in, then re-run --verify."
            );
        }
    }
    Ok(())
}
