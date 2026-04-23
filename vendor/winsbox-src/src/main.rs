mod policy;
#[cfg(windows)]
mod launch;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::Read;

#[derive(Parser)]
#[command(name = "sbox-exec", version)]
struct Cli {
    /// Path to a JSON policy file.
    #[arg(long, conflicts_with = "policy_stdin")]
    policy: Option<std::path::PathBuf>,
    /// Read JSON policy from stdin.
    #[arg(long)]
    policy_stdin: bool,
    /// Revert any leaked per-instance state (no-op in stub mode).
    #[arg(long)]
    cleanup: bool,
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
    if cli.cleanup {
        // Phase 0.5: nothing persistent to revert. Phase 1 wires acl::revert_all here.
        return Ok(());
    }
    let pol = load_policy(&cli)?;
    let code = launch::run(&pol)?;
    std::process::exit(code as i32);
}

#[cfg(not(windows))]
fn main() {
    // Allow `cargo check` on non-Windows dev hosts.
    let _ = Cli::parse();
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
