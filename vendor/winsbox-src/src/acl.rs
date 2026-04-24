use anyhow::{bail, Result};
use std::process::Command;

pub const READ_EXECUTE: &str = "RX";
pub const MODIFY: &str = "M";
pub const FULL: &str = "F";

/// Tracks every ACE we add so they can be reverted on exit.
#[derive(Default)]
pub struct AclJournal {
    entries: Vec<(String, String)>, // (path, sid_string)
}

impl AclJournal {
    pub fn grant(&mut self, path: &str, sid_str: &str, perm: &str) -> Result<()> {
        // (OI)(CI) only valid on directories.
        let spec = if std::path::Path::new(path).is_dir() {
            format!("*{sid_str}:(OI)(CI)({perm})")
        } else {
            format!("*{sid_str}:({perm})")
        };
        run_icacls(&[path, "/grant", &spec])?;
        self.entries.push((path.to_string(), sid_str.to_string()));
        Ok(())
    }
    pub fn deny(&mut self, path: &str, sid_str: &str, perm: &str) -> Result<()> {
        // /deny perm spec must be the simple "(F)" form — including
        // inheritance flags here yields an allow-mask-0 ACE instead
        // of an ACCESS_DENIED_ACE. Use /T to recurse to existing
        // children. Deny both the package SID and ALL APPLICATION
        // PACKAGES (S-1-15-2-1) since the AC token carries both.
        for s in [sid_str, "S-1-15-2-1"] {
            run_icacls(&[path, "/deny", &format!("*{s}:({perm})"), "/T", "/C"])?;
            self.entries.push((path.to_string(), s.to_string()));
        }
        Ok(())
    }
    pub fn revert_all(&mut self) {
        for (path, sid_str) in self.entries.drain(..) {
            let _ = run_icacls(&[&path, "/remove", &format!("*{sid_str}"), "/T", "/C"]);
        }
    }
}

impl Drop for AclJournal {
    fn drop(&mut self) { self.revert_all(); }
}

fn run_icacls(args: &[&str]) -> Result<()> {
    let out = Command::new("icacls").args(args).output()?;
    if !out.status.success() {
        bail!(
            "icacls {:?}: exit {} {}",
            args,
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(())
}

pub fn dump(path: &str) -> String {
    Command::new("icacls").arg(path).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
