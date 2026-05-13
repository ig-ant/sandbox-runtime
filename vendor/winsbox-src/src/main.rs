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
#[cfg(windows)] mod winsta;
#[cfg(windows)] mod self_protect;
#[cfg(windows)] mod share_mode;
mod lock_db;

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
            // Phase 4.5 v3 Layer 5: rewrite the broker's own process
            // DACL before any sandbox child is spawned. Gated on
            // WINSBOX_BROKER_PROTECT=0 for diagnostic harnesses. We
            // do this BEFORE loading the policy so policy-load errors
            // can't leak an unprotected broker window.
            if let Err(e) = self_protect::install_broker_dacl() {
                eprintln!(
                    "[sbox-exec] WARNING: install_broker_dacl failed: {e:#}"
                );
            }

            // Phase 5A: open the per-user state DB, run crash
            // recovery, and register our session. Gated on
            // WINSBOX_PHASE5_DB=0 (default ON). If open fails (disk
            // full, perms), we log and continue without coordination
            // — broker still works, just no cross-broker FS isolation
            // coordination. Mark internally as "phase 5 degraded".
            let phase5_db_enabled = !matches!(
                std::env::var_os("WINSBOX_PHASE5_DB"),
                Some(v) if v == "0"
            );
            let db_session: Option<(lock_db::LockDb, u32)> = if phase5_db_enabled {
                match lock_db::LockDb::open() {
                    Ok(db) => {
                        match db.crash_recovery_scan() {
                            Ok(0) => {}
                            Ok(n) => eprintln!(
                                "[sbox-exec] phase5: pruned {n} dead session(s) from state DB"
                            ),
                            Err(e) => eprintln!(
                                "[sbox-exec] WARNING: crash_recovery_scan failed: {e:#}"
                            ),
                        }
                        let pid = std::process::id();
                        let pipe_name =
                            format!(r"\\.\pipe\winsbox-broker-{pid}");
                        match db.begin_session(pid, &pipe_name) {
                            Ok(()) => Some((db, pid)),
                            Err(e) => {
                                eprintln!(
                                    "[sbox-exec] WARNING: begin_session failed: {e:#} \
                                     (phase 5 degraded)"
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[sbox-exec] WARNING: opening state DB failed: {e:#} \
                             (phase 5 degraded)"
                        );
                        None
                    }
                }
            } else {
                None
            };

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

            let run_result = launch::run(
                &pol,
                db_session.as_ref().map(|(db, _)| db),
            );

            // Phase 5A: graceful end-of-session, both on success and
            // on error. CASCADE will also clean up any path_locks we
            // held (none yet in 5A). On error we still try the
            // cleanup before propagating.
            if let Some((db, pid)) = &db_session {
                if let Err(e) = db.end_session(*pid) {
                    eprintln!(
                        "[sbox-exec] WARNING: end_session failed: {e:#}"
                    );
                }
            }

            let code = run_result?;
            std::process::exit(code as i32);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sbox-exec: Windows only");
    std::process::exit(2);
}
