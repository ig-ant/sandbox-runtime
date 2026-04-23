//! P4: Children of an AppContainer process inherit the AC. AC child spawns
//! a grandchild (plain CreateProcess); grandchild verifies it is also in
//! the AC and that a write outside the granted area still fails.

use crate::common::*;
use anyhow::Result;

pub fn run() -> Result<ProbeOutcome> {
    let ac = create_appcontainer("p4")?;
    grant_sid_on_path(&self_exe(), ac.sid, 0x1200A9)?;

    let base = std::env::temp_dir().join(format!("srt-p4-{}", std::process::id()));
    let denied = base.join("denied");
    std::fs::create_dir_all(&denied)?;
    grant_sid_on_path(&base, ac.sid, 0x1200A9)?;
    let denied_target = denied.join("no.txt").to_string_lossy().to_string();

    let child = spawn_in_ac(&ac, &self_exe(),
        &["child", "p4-spawn", &self_exe().to_string_lossy(), &denied_target], false)?;
    let code = child.wait()?;
    let _ = std::fs::remove_dir_all(&base);

    Ok(match code {
        0 => ProbeOutcome::pass("grandchild inherits AppContainer; denied write blocked"),
        20 => ProbeOutcome::fail("grandchild reports NOT in AppContainer — inheritance broken"),
        21 => ProbeOutcome::fail("grandchild wrote to denied dir — AC not enforced on grandchild"),
        c  => ProbeOutcome::fail(format!("child exit {c}")),
    })
}

pub fn child_spawn(args: &[String]) -> Result<i32> {
    if !process_is_appcontainer() { return Ok(92); }
    let exe = std::path::PathBuf::from(args.get(0).cloned().unwrap_or_default());
    let denied = args.get(1).cloned().unwrap_or_default();
    let gc = spawn_plain(&exe, &["child", "p4-grandchild", &denied], false)?;
    Ok(gc.wait()? as i32)
}

pub fn child_grandchild(args: &[String]) -> Result<i32> {
    if !process_is_appcontainer() {
        eprintln!("p4: grandchild NOT in AppContainer");
        return Ok(20);
    }
    let denied = args.get(0).cloned().unwrap_or_default();
    match std::fs::write(&denied, b"x") {
        Ok(()) => { eprintln!("p4: grandchild wrote to {denied}"); Ok(21) }
        Err(_) => Ok(0),
    }
}
