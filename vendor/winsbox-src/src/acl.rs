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
    pub fn deny(&mut self, path: &str, sid_str: &str, _perm: &str) -> Result<()> {
        // Break inheritance (copying existing ACEs as explicit) so the
        // allow-RX inherited from the allowRead parent stops flowing
        // here, then strip every AppContainer-related ACE. The AC's
        // second-pass access check then finds no grant → denied.
        // Avoids the icacls /deny display ambiguity entirely.
        run_icacls(&[path, "/inheritance:d"])?;
        for s in [sid_str, "S-1-15-2-1", "S-1-15-2-2" /* ALL RESTRICTED APP PACKAGES */] {
            let _ = run_icacls(&[path, "/remove", &format!("*{s}"), "/T", "/C"]);
        }
        // Journal so revert_all re-enables inheritance.
        self.entries.push((path.to_string(), format!("inheritance:{sid_str}")));
        Ok(())
    }
    pub fn revert_all(&mut self) {
        for (path, sid_str) in self.entries.drain(..) {
            if let Some(_) = sid_str.strip_prefix("inheritance:") {
                let _ = run_icacls(&[&path, "/inheritance:e"]);
            } else {
                let _ = run_icacls(&[&path, "/remove", &format!("*{sid_str}"), "/T", "/C"]);
            }
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
