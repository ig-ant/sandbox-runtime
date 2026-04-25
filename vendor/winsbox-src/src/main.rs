mod policy;
#[cfg(windows)] mod util;
#[cfg(windows)] mod appcontainer;
#[cfg(windows)] mod acl;
#[cfg(windows)] mod job;
#[cfg(windows)] mod desktop;
#[cfg(windows)] mod netbridge;
#[cfg(windows)] mod token;
#[cfg(windows)] mod ipc;
#[cfg(windows)] mod interception;
#[cfg(windows)] mod entry_trampoline;
#[cfg(windows)] mod policy_engine;
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
    let code = launch::run(&pol)?;
    std::process::exit(code as i32);
}

#[cfg(not(windows))]
fn main() {
    let _ = Cli::parse();
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
