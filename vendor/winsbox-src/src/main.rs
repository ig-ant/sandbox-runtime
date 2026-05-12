//! `sbox-exec` — CLI front-end for the WFP+SID network sandbox.
//!
//! Subcommands:
//!   - (none) — run a policy and exec target.
//!   - `install [--port N] [--remove] [--check] [--verify] [--keep-group]`
//!     — manage persistent WFP filters + local group (admin required
//!     for install/remove; `--check` and `--verify` are unprivileged).

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
    /// Install / remove / inspect persistent WFP filters + local group.
    Install {
        /// Proxy port to allow on loopback (default 60080).
        #[arg(long)] port: Option<u16>,
        /// Uninstall instead of installing.
        #[arg(long)] remove: bool,
        /// Print install state without modifying.
        #[arg(long)] check: bool,
        /// Deep-verify: token group membership + SAM + marker consistency.
        #[arg(long)] verify: bool,
        /// On --remove, leave the local group intact (default deletes).
        #[arg(long)] keep_group: bool,
    },
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Install { check: true, .. }) => install::check(),
        Some(Cmd::Install { verify: true, .. }) => install::verify(),
        Some(Cmd::Install { remove: true, keep_group, .. }) => install::remove(keep_group),
        Some(Cmd::Install { port, .. }) => install::install(port),
        None => {
            // Build a policy.
            let mut pol: policy::Policy = if cli.policy_stdin {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                    .context("read policy from stdin")?;
                serde_json::from_str(&buf).context("parse stdin policy")?
            } else if let Some(p) = &cli.policy {
                let s = std::fs::read_to_string(p)
                    .with_context(|| format!("read {}", p.display()))?;
                serde_json::from_str(&s)
                    .with_context(|| format!("parse {}", p.display()))?
            } else if !cli.target.is_empty() {
                policy::Policy::default()
            } else {
                return Err(anyhow!(
                    "no policy and no target: pass --policy <file> or -- <target> [args...]"
                ));
            };

            if !cli.target.is_empty() {
                pol.target_exe = std::path::PathBuf::from(&cli.target[0]);
                pol.target_args = cli.target[1..].to_vec();
            }
            if pol.target_exe.as_os_str().is_empty() {
                return Err(anyhow!("policy.target_exe is empty"));
            }

            let code = launch::run(&pol)?;
            std::process::exit(code as i32);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
