//! `sbox-exec` — CLI front-end for the WFP+SID network sandbox.
//!
//! Subcommands:
//!   - (none) — run a policy and exec target.
//!   - `install [--port N] [--remove] [--check]` — manage persistent
//!     WFP filters (requires admin).

mod policy;
#[cfg(windows)] mod util;
#[cfg(windows)] mod token;
#[cfg(windows)] mod job;
#[cfg(windows)] mod sid;
#[cfg(windows)] mod wfp;
#[cfg(windows)] mod proxy;
#[cfg(windows)] mod install;
#[cfg(windows)] mod launch;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sbox-exec", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Path to JSON policy file. Mutually exclusive with --policy-stdin.
    #[arg(long)] policy: Option<std::path::PathBuf>,
    /// Read JSON policy from stdin.
    #[arg(long)] policy_stdin: bool,
    /// Target program + args (when no subcommand). Everything after `--`.
    #[arg(trailing_var_arg = true)] target: Vec<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install / remove / inspect persistent WFP filters.
    Install {
        /// Proxy port to allow on loopback (default 60080).
        #[arg(long)] port: Option<u16>,
        /// Uninstall instead of installing.
        #[arg(long)] remove: bool,
        /// Print install state without modifying.
        #[arg(long)] check: bool,
    },
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    todo!("phase 2: dispatch to install/run")
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
