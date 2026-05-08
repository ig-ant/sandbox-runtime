mod policy;
#[cfg(windows)] mod util;
#[cfg(windows)] mod appcontainer;
#[cfg(windows)] mod acl;
#[cfg(windows)] mod job;
#[cfg(windows)] mod desktop;
#[cfg(windows)] mod netbridge;
#[cfg(windows)] mod token;
#[cfg(windows)] mod ipc;
#[cfg(all(windows, target_arch = "x86_64"))] mod interception_x64;
#[cfg(all(windows, target_arch = "aarch64"))] mod interception_arm64;
#[cfg(windows)] mod interception;
#[cfg(windows)] mod entry_trampoline;
#[cfg(windows)] mod policy_engine;
#[cfg(windows)] mod cdylib_inject;
#[cfg(windows)] mod acl_stamper;
#[cfg(windows)] mod stamp_manifest;
#[cfg(windows)] mod launch;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::Read;

#[derive(Parser)]
#[command(name = "sbox-exec", version)]
struct Cli {
    #[arg(long, conflicts_with = "policy_stdin")]
    policy: Option<std::path::PathBuf>,
    #[arg(long)]
    policy_stdin: bool,
    /// Revert any leaked per-instance ACL grants.
    #[arg(long)]
    cleanup: bool,
    /// Internal: run as the inside-AC TCP→AF_UNIX relay. Args are the
    /// AF_UNIX socket paths (http, then optional socks).
    #[arg(long, num_args = 1..=2)]
    relay_inside: Vec<String>,
    /// Phase D: directory storing per-AC-SID stamp manifests.
    /// Falls back to `WINSBOX_STAMP_DIR` env var, then
    /// `%LOCALAPPDATA%\sbox-exec\stamps\` if neither is set.
    #[arg(long)]
    manifest_dir: Option<std::path::PathBuf>,
}

fn load_policy(cli: &Cli) -> Result<policy::Policy> {
    let raw = if let Some(p) = &cli.policy {
        std::fs::read_to_string(p).with_context(|| format!("read policy {}", p.display()))?
    } else if cli.policy_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).context("read policy from stdin")?;
        s
    } else {
        anyhow::bail!("one of --policy or --policy-stdin is required");
    };
    serde_json::from_str(&raw).context("parse policy JSON")
}

#[cfg(windows)]
fn resolve_manifest_dir(cli: &Cli) -> std::path::PathBuf {
    if let Some(p) = cli.manifest_dir.clone() {
        return p;
    }
    if let Ok(p) = std::env::var("WINSBOX_STAMP_DIR") {
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    let base = std::env::var("LOCALAPPDATA").ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("sbox-exec").join("stamps")
}

#[cfg(windows)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    if !cli.relay_inside.is_empty() {
        return netbridge::run_inside_relay(&cli.relay_inside);
    }
    if cli.cleanup {
        // Phase 1: ACLs are reverted by the broker on exit; a separate
        // crash-recovery journal is a Phase-1 follow-up.
        return Ok(());
    }
    let pol = load_policy(&cli)?;
    let manifest_dir = resolve_manifest_dir(&cli);
    let code = launch::run(&pol, &manifest_dir)?;
    std::process::exit(code as i32);
}

#[cfg(not(windows))]
fn main() {
    let _ = Cli::parse();
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
