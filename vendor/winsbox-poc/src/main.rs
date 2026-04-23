//! winsbox-poc: empirical probes for the Windows sandbox design.
//!
//! Each probe validates one risky assumption from the plan. A probe returns
//! `ProbeOutcome { pass, detail }`; an `Err` means the probe itself crashed
//! (infra failure), distinct from a clean FAIL verdict. `all` runs every
//! probe, writes RESULTS.md, and exits 0 unless a probe *errored* — a FAIL
//! verdict is data, not a CI failure, so the artifact still uploads.

#[cfg(not(windows))]
fn main() {
    eprintln!("winsbox-poc: Windows only (built on {} for parse-check)", std::env::consts::OS);
    std::process::exit(2);
}

#[cfg(windows)]
mod common;
#[cfg(windows)]
mod p1_loopback;
#[cfg(windows)]
mod p2_afunix;
#[cfg(windows)]
mod p3_acl;
#[cfg(windows)]
mod p4_inherit;
#[cfg(windows)]
mod p5_lowbox;
#[cfg(windows)]
mod p6_patch;
#[cfg(windows)]
mod p7_entry;
#[cfg(windows)]
mod p8_createproc;
#[cfg(windows)]
mod p9_hardlink;

#[cfg(windows)]
fn main() {
    use clap::{Parser, Subcommand};
    use std::fmt::Write as _;

    #[derive(Parser)]
    #[command(name = "winsbox-poc")]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(Subcommand, Clone)]
    enum Cmd {
        /// Run every probe and write RESULTS.md
        All,
        P1, P2, P3, P4, P5, P6, P7, P8, P9,
        /// Internal: re-exec'd inside an AppContainer by probes that need
        /// in-AC behaviour. Not for direct use.
        #[command(hide = true)]
        Child { which: String, #[arg(trailing_var_arg = true)] args: Vec<String> },
    }

    type ProbeFn = fn() -> anyhow::Result<common::ProbeOutcome>;
    let probes: &[(&str, &str, ProbeFn)] = &[
        ("P1", "ac-loopback-self",        p1_loopback::run),
        ("P2", "ac-afunix-cross",         p2_afunix::run),
        ("P3", "ac-acl-rw",               p3_acl::run),
        ("P4", "ac-inherit",              p4_inherit::run),
        ("P5", "lowbox-restricted-launch",p5_lowbox::run),
        ("P6", "suspended-ntdll-patch",   p6_patch::run),
        ("P7", "entry-trampoline",        p7_entry::run),
        ("P8", "intercept-createprocess", p8_createproc::run),
        ("P9", "finalpath-hardlink",      p9_hardlink::run),
    ];

    let cli = Cli::parse();

    if let Cmd::Child { which, args } = &cli.cmd {
        std::process::exit(common::dispatch_child(which, args));
    }

    let selected: Vec<&(&str, &str, ProbeFn)> = match cli.cmd {
        Cmd::All => probes.iter().collect(),
        Cmd::P1 => vec![&probes[0]], Cmd::P2 => vec![&probes[1]],
        Cmd::P3 => vec![&probes[2]], Cmd::P4 => vec![&probes[3]],
        Cmd::P5 => vec![&probes[4]], Cmd::P6 => vec![&probes[5]],
        Cmd::P7 => vec![&probes[6]], Cmd::P8 => vec![&probes[7]],
        Cmd::P9 => vec![&probes[8]],
        Cmd::Child { .. } => unreachable!(),
    };

    let mut md = String::new();
    let arch = std::env::consts::ARCH;
    let winver = common::win_version_string();
    writeln!(md, "# winsbox-poc results\n").ok();
    writeln!(md, "- arch: `{arch}`").ok();
    writeln!(md, "- windows: `{winver}`\n").ok();
    writeln!(md, "| # | probe | verdict | detail |").ok();
    writeln!(md, "|---|---|---|---|").ok();

    let mut errored = false;
    for (id, name, f) in selected {
        eprintln!("==> {id} {name}");
        let row = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(Ok(o)) => {
                let v = if o.pass { "PASS" } else { "FAIL" };
                eprintln!("    {v}: {}", o.detail);
                format!("| {id} | `{name}` | **{v}** | {} |", md_escape(&o.detail))
            }
            Ok(Err(e)) => {
                errored = true;
                eprintln!("    ERROR: {e:?}");
                format!("| {id} | `{name}` | ERROR | {} |", md_escape(&format!("{e:?}")))
            }
            Err(p) => {
                errored = true;
                let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".into());
                eprintln!("    PANIC: {msg}");
                format!("| {id} | `{name}` | ERROR | panic: {} |", md_escape(&msg))
            }
        };
        writeln!(md, "{row}").ok();
    }

    if matches!(cli.cmd, Cmd::All) {
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("RESULTS.md");
        std::fs::write(&out, &md).expect("write RESULTS.md");
        eprintln!("\nwrote {}", out.display());
    }
    print!("{md}");
    std::process::exit(if errored { 1 } else { 0 });
}

#[cfg(windows)]
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}
