//! P3: Grant the AppContainer SID modify access on a temp dir; verify the
//! AC child can write there but cannot write to a sibling dir without the
//! grant.

use crate::common::*;
use anyhow::Result;

const FILE_GENERIC_READ_EXECUTE: u32 = 0x1200A9;
const FILE_ALL_ACCESS: u32 = 0x1F01FF;

pub fn run() -> Result<ProbeOutcome> {
    let ac = create_appcontainer("p3")?;
    grant_sid_on_path(&self_exe(), ac.sid, FILE_GENERIC_READ_EXECUTE)?;

    let base = std::env::temp_dir().join(format!("srt-p3-{}", std::process::id()));
    let allowed = base.join("allowed");
    let denied  = base.join("denied");
    std::fs::create_dir_all(&allowed)?;
    std::fs::create_dir_all(&denied)?;
    // AC needs traverse on the parent to reach `allowed` at all.
    grant_sid_on_path(&base, ac.sid, FILE_GENERIC_READ_EXECUTE)?;
    grant_sid_on_path(&allowed, ac.sid, FILE_ALL_ACCESS)?;

    let allowed_target = allowed.join("ok.txt").to_string_lossy().to_string();
    let denied_target  = denied.join("no.txt").to_string_lossy().to_string();

    let c1 = spawn_in_ac(&ac, &self_exe(), &["child", "p3-write", &allowed_target], false)?;
    let r1 = c1.wait()?;
    let c2 = spawn_in_ac(&ac, &self_exe(), &["child", "p3-write", &denied_target], false)?;
    let r2 = c2.wait()?;

    let _ = std::fs::remove_dir_all(&base);

    match (r1, r2) {
        (0, c) if c != 0 => Ok(ProbeOutcome::pass(format!(
            "ACL grant effective: write allowed→ok, write denied→exit {c}"))),
        (0, 0) => Ok(ProbeOutcome::fail(
            "AC child wrote to a dir WITHOUT an ACL grant — AppContainer not enforcing")),
        (a, _) => Ok(ProbeOutcome::fail(format!(
            "AC child could NOT write to ACL-granted dir (exit {a})"))),
    }
}

pub fn child_write(args: &[String]) -> Result<i32> {
    if !process_is_appcontainer() { return Ok(92); }
    let path = args.get(0).cloned().unwrap_or_default();
    match std::fs::write(&path, b"x") {
        Ok(()) => Ok(0),
        Err(e) => { eprintln!("p3 write {path}: {e}"); Ok(13) }
    }
}
