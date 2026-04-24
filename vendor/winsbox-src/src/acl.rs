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
        // Simple rights (F, M, RX) are BARE letters in icacls — wrapping
        // in parens makes icacls parse them as a (bogus) specific-rights
        // list and emit a mask-0 ACE. (OI)(CI) only valid on directories.
        let spec = if std::path::Path::new(path).is_dir() {
            format!("*{sid_str}:(OI)(CI){perm}")
        } else {
            format!("*{sid_str}:{perm}")
        };
        run_icacls(&[path, "/grant", &spec])?;
        self.entries.push((path.to_string(), sid_str.to_string()));
        Ok(())
    }
    pub fn deny(&mut self, path: &str, sid_str: &str, perm: &str) -> Result<()> {
        // Deny both the package SID and ALL APPLICATION PACKAGES
        // (S-1-15-2-1) — the AC token carries both. (OI)(CI) so new
        // children inherit; /T to also stamp existing children.
        let inh = if std::path::Path::new(path).is_dir() { "(OI)(CI)" } else { "" };
        for s in [sid_str, "S-1-15-2-1"] {
            run_icacls(&[path, "/deny", &format!("*{s}:{inh}{perm}"), "/T", "/C"])?;
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
