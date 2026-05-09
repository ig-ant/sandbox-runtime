//! Phase D-4: **known-failing** end-to-end MSYS2 bash workload smoke test.
//!
//! Status as of D-4 (the network-sandbox / native-PE release): **bash
//! does not work inside the sandbox.** The architecture works for
//! native PE workloads (smoke_cdylib passes consistently); MSYS2/Cygwin
//! still segfaults inside cygwin1.dll's DLL_PROCESS_ATTACH. This file
//! is retained as a harness so the diagnostic trail isn't lost and so
//! a future bash-fixing branch has a known-shape regression test to
//! flip green.
//!
//! Diagnostic trail (in commit order):
//!
//!   * Phase E-5a (`069396b`) — soft-fail policy stamps when the
//!     target path is already AC-accessible via inherited ALLOW; reorder
//!     `serve_ipc` thread to spawn before resume so the loader's first
//!     `NtOpenSection` doesn't deadlock on the broker's reply.
//!   * Phase E-5b (`592b0d3`) — `FS_PASSTHROUGH` tail-call infrastructure
//!     in the cdylib so syscalls outside the broker's namespace go to
//!     the kernel directly via saved-original passthrough thunks (was
//!     previously `STATUS_NOT_IMPLEMENTED`).
//!   * Phase E-5c (`fa150bc` + `c0209d1`) — switch the cdylib token from
//!     USER_LOCKDOWN to USER_LIMITED so CRYPTBASE/CNG/LSA can reach the
//!     `BUILTIN\Users:RX` inherited ACEs they need; cdylib goes
//!     `#![no_std]` to drop the 127KB std rt that the manual-map loader
//!     can't initialise.
//!
//! Where it currently breaks:
//!   * `0xC0000005` access violation inside CRYPTBASE / CNG / LSA
//!     bootstrap during cygwin1.dll DllMain. The hooks are firing and
//!     IPC roundtrips work, but Cygwin's loader-time syscall mix hits
//!     a corner the broker isn't covering.
//!
//! Phase L (cycles 1–4) findings — two independent walls:
//!
//!   * **Wall 1 — Cygwin DllMain in bare AC.** `bash.exe`, `true.exe`,
//!     `cygpath.exe` (all x86-64 Cygwin) AV `0xC0000005` inside an AC
//!     even with NO cdylib injected (no manual-map, no ntdll patches).
//!     Pure ARM64 Win32 binaries (`cmd.exe`, `git.exe` from Git's
//!     `cmd\`) work fine in the same AC. An x86-64 native-Rust target
//!     (rebuilt sleep_target for `x86_64-pc-windows-msvc`) ALSO works
//!     in bare AC. So the AV is not "x64 emulator can't bootstrap in
//!     AC" — it's specific to cygwin1.dll/msys-2.0.dll's DllMain.
//!     Setting token IL to LOW vs UNTRUSTED, dropping USER_LIMITED
//!     restrictions (bare-AC mode), and extending trace coverage to
//!     15 syscalls (file/IOCTL/ALPC/registry/sync + map/create-section
//!     + alloc-vmem) all leave zero `[sbox-trace]` lines before AV —
//!     the loader doesn't reach any hooked syscall before cygwin1.dll
//!     dies.
//!
//!   * **Wall 2 — ARM64 cdylib into x64 target.** Even if Wall 1 is
//!     bypassed (by the kernel mapping a x64 cygwin DLL successfully),
//!     our manual-mapped ARM64 cdylib's hook bodies are ARM64
//!     bytecode. When patched into the target's x64 `ntdll!Nt*`
//!     stubs, the x64 syscall caller jumps to ARM64 code → AV. Test:
//!     x86-64 `sleep_target.exe` runs cleanly without cdylib in the
//!     AC, but AVs the moment the cdylib is manual-mapped.
//!
//! Implication: making bash work needs (a) an arch-matched cdylib
//! (build x86-64 `ac_cdylib.dll` when target is x86-64) AND (b) a
//! workaround for cygwin1.dll's bare-AC DllMain crash.
//!
//! Cycle 5 verified that cross-building the x86-64 cdylib is easy
//! (`cargo build --target x86_64-pc-windows-msvc -p ac-cdylib` produces
//! a 17 KB x64 PE32+ DLL), BUT the ARM64 broker cannot `LoadLibraryW`
//! the x64 dll for export resolution (`%1 is not a valid Win32
//! application`, 0x800700C1). `manual_map.rs::manual_map_cdylib`
//! depends on LoadLibrary in the broker to resolve `hook_*` export
//! VAs. Fixing (a) means parsing the PE export table directly without
//! LoadLibrary — ~150 LOC in `manual_map.rs`, not the ~50 estimated
//! before cycle 5.
//!
//! (b) is a research project — likely needs running bash WITHOUT the
//! AC at all (use the restricted token directly without
//! `CreateProcessAsUserW + AC capabilities`), which loses the AC SID
//! ACL stamping foundation entirely.
//!
//! Recommend a separate plan to address (a)+(b) together. For now,
//! the harness is wired so a future branch can re-run with both
//! walls fixed and flip green.
//!
//! How to use this file:
//!   * **Phase L stance** (re-enabled, expects FAIL): runs the 3
//!     sub-tests; all currently fail with `0xC0000005`. The harness
//!     itself works — broker spawns, ACL stamps, hooks patch, x64
//!     emulation initialises — only Cygwin's DllMain dies.
//!   * To skip: env var `WINSBOX_SKIP_BASH_SMOKE=1` (caller-side
//!     opt-out for CI / known-failing branches).
//!
//! New env vars (Phase N-0):
//!   WINSBOX_LOG_DENIES=0     — disable always-on denied-open logging
//!   WINSBOX_STAMP_VERBOSE=1  — per-path acl_stamper outcomes
//!   WINSBOX_DEBUG=1          — TS-side resolved-policy snapshot

#[cfg(not(windows))]
fn main() {
    eprintln!("smoke_bash: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    // Phase L: harness re-enabled to drive MSYS2 compat iteration. The
    // 3 sub-tests are EXPECTED to FAIL pending the dual-wall fix
    // documented above (arch-matched cdylib + bare-AC cygwin1.dll
    // workaround). Setting `WINSBOX_SKIP_BASH_SMOKE=1` opts out for
    // CI / branches that haven't picked up the fix yet.
    if std::env::var("WINSBOX_SKIP_BASH_SMOKE").is_ok() {
        eprintln!(
            "[smoke_bash] SKIP (WINSBOX_SKIP_BASH_SMOKE=1): see file \
             header for the dual-wall finding from Phase L."
        );
        std::process::exit(0);
    }
    use std::path::PathBuf;
    use std::time::Instant;

    macro_rules! log { ($($a:tt)*) => { eprintln!("[smoke_bash] {}", format!($($a)*)) } }

    fn locate_broker() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WINSBOX_SBOX") {
            let pb = PathBuf::from(p);
            if pb.exists() { return Some(pb); }
        }
        let exe = std::env::current_exe().ok()?;
        // examples/smoke_bash lives in target/<profile>/examples/.
        // sbox-exec.exe lives in target/<profile>/.
        let parent = exe.parent()?.parent()?.to_path_buf();
        for c in [
            parent.join("sbox-exec.exe"),
            parent.join("debug").join("sbox-exec.exe"),
            parent.join("release").join("sbox-exec.exe"),
        ] {
            if c.exists() { return Some(c); }
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            for sub in ["debug", "release"] {
                let p = PathBuf::from(&td).join(sub).join("sbox-exec.exe");
                if p.exists() { return Some(p); }
            }
        }
        None
    }

    fn locate_cdylib(broker: &PathBuf) -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WINSBOX_CDYLIB") {
            let pb = PathBuf::from(p);
            if pb.exists() { return Some(pb); }
        }
        // Sibling of the broker — that's where cargo emits it.
        let sib = broker.parent()?.join("ac_cdylib.dll");
        if sib.exists() { return Some(sib); }
        None
    }

    fn locate_bash() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WINSBOX_BASH") {
            let pb = PathBuf::from(p);
            if pb.exists() { return Some(pb); }
        }
        let p = PathBuf::from(r"C:\Program Files\Git\usr\bin\bash.exe");
        if p.exists() { return Some(p); }
        None
    }

    let broker = match locate_broker() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_bash] FAIL: sbox-exec.exe not found.\n\
                 Build with: cargo build --bin sbox-exec\n\
                 Or set WINSBOX_SBOX=<absolute path>."
            );
            std::process::exit(1);
        }
    };
    log!("broker = {}", broker.display());

    let cdylib = match locate_cdylib(&broker) {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_bash] FAIL: ac_cdylib.dll not found.\n\
                 Build with: cargo build -p ac-cdylib\n\
                 Or set WINSBOX_CDYLIB=<absolute path>."
            );
            std::process::exit(1);
        }
    };
    log!("cdylib = {}", cdylib.display());

    let bash = match locate_bash() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_bash] FAIL: bash.exe not found at \
                 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'.\n\
                 Install Git for Windows or set WINSBOX_BASH=<path>."
            );
            std::process::exit(1);
        }
    };
    log!("bash = {}", bash.display());

    // Resolve %USERPROFILE% / %TEMP% — broker policy doesn't expand
    // env vars itself.
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| String::from("C:\\Users\\Public"));
    let temp_dir = std::env::var("TEMP").unwrap_or_else(|_| String::from("C:\\Windows\\Temp"));
    let bash_smoke_dir = PathBuf::from(&temp_dir).join("bash-smoke");
    let _ = std::fs::create_dir_all(&bash_smoke_dir);
    let ssh_dir = PathBuf::from(&user_profile).join(".ssh");
    log!("user_profile = {}", user_profile);
    log!("temp_dir     = {}", temp_dir);
    log!("ssh_dir      = {} (exists={})", ssh_dir.display(), ssh_dir.exists());

    /// Invoke the broker once with a given bash command line. Returns
    /// (exit_code, stdout, stderr_combined).
    fn run_bash(
        broker: &PathBuf, cdylib: &PathBuf, bash: &PathBuf, user_profile: &str,
        temp_dir: &str, bash_smoke_dir: &PathBuf, ssh_dir: &std::path::Path,
        command: &str,
    ) -> (Option<i32>, String, String) {
        let cmdline = format!(
            "\"{}\" -c \"{}\"",
            bash.display(),
            command.replace('"', "\\\""),
        );
        // We give bash read access to:
        //   - C:\Program Files\Git (so it can find cygwin1.dll, libs, /usr/bin)
        //   - %USERPROFILE% (home dir, .gitconfig, etc.)
        //   - C:\Windows (kernelbase, ucrtbase, KnownDLLs that aren't in
        //     ALL APP PACKAGES default ACLs — most are, but ucrtbase
        //     occasionally needs explicit grants)
        // Plus a temp scratch dir for write.
        // We deny ~/.ssh to prove the deny path.
        let policy = serde_json::json!({
            "commandLine": cmdline,
            "cdylibPath": cdylib.to_string_lossy(),
            "allowRead": [
                "C:\\Program Files\\Git",
                user_profile,
                "C:\\Windows",
            ],
            "denyRead": [ ssh_dir.to_string_lossy() ],
            "allowWrite": [ bash_smoke_dir.to_string_lossy() ],
        });
        let pol_path = std::env::temp_dir().join(format!(
            "smoke-bash-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),
        ));
        std::fs::write(&pol_path, policy.to_string()).expect("write policy");

        let t0 = Instant::now();
        let out = std::process::Command::new(broker)
            .arg("--policy").arg(&pol_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output();
        let _ = std::fs::remove_file(&pol_path);
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[smoke_bash] spawn broker failed: {e:#}");
                return (None, String::new(), format!("spawn: {e}"));
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        eprintln!(
            "[smoke_bash] broker exited code={:?} ({} ms)",
            out.status.code(), t0.elapsed().as_millis(),
        );
        (out.status.code(), stdout, stderr)
    }

    let mut failures: Vec<String> = Vec::new();

    // ── Test 1: hello + uname.
    log!("─── Test 1: bash -c 'echo hello && /usr/bin/uname -a' ───");
    let (code, stdout, stderr) = run_bash(
        &broker, &cdylib, &bash, &user_profile, &temp_dir, &bash_smoke_dir,
        &ssh_dir, "echo hello && /usr/bin/uname -a",
    );
    eprintln!("--- stdout ---\n{}--- stderr ---\n{}--- end ---", stdout, stderr);
    if code != Some(0) {
        failures.push(format!("test1: expected exit 0, got {:?}", code));
    }
    if !stdout.contains("hello") {
        failures.push(format!("test1: stdout missing 'hello': {:?}", stdout));
    }
    for bad in ["0xc0000005", "0xc0000135"] {
        if stderr.contains(bad) {
            failures.push(format!("test1: crash code {} on stderr", bad));
        }
    }

    if failures.is_empty() {
        // ── Test 2: pipeline + fork (only if test 1 passed).
        log!("─── Test 2: bash -c 'ls /usr/bin | head -3' ───");
        let (code, stdout, stderr) = run_bash(
            &broker, &cdylib, &bash, &user_profile, &temp_dir, &bash_smoke_dir,
            &ssh_dir, "ls /usr/bin | head -3",
        );
        eprintln!("--- stdout ---\n{}--- stderr ---\n{}--- end ---", stdout, stderr);
        if code != Some(0) {
            failures.push(format!("test2: expected exit 0, got {:?}", code));
        }
        let out_lines: Vec<&str> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        if out_lines.is_empty() {
            failures.push(format!("test2: expected ≥1 stdout line, got 0"));
        }

        // ── Test 3: deny enforcement.
        log!("─── Test 3: bash -c 'cat ~/.ssh/id_rsa 2>&1; true' ───");
        let (code, stdout, stderr) = run_bash(
            &broker, &cdylib, &bash, &user_profile, &temp_dir, &bash_smoke_dir,
            &ssh_dir, "cat ~/.ssh/id_rsa 2>&1; true",
        );
        eprintln!("--- stdout ---\n{}--- stderr ---\n{}--- end ---", stdout, stderr);
        if code != Some(0) {
            failures.push(format!("test3: expected exit 0 (`; true`), got {:?}", code));
        }
        // We accept any of: "Permission denied", "No such file"
        // (when ~/.ssh doesn't exist), or "cannot open" — what we
        // do NOT want is bash succeeding silently or printing the
        // file's contents.
        let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();
        let any_denial = combined.contains("permission denied")
            || combined.contains("no such file")
            || combined.contains("cannot open")
            || combined.contains("operation not permitted");
        if !any_denial {
            failures.push(format!(
                "test3: expected deny diagnostic; combined output:\n{}\n{}",
                stdout, stderr,
            ));
        }
    }

    if failures.is_empty() {
        log!("PASS — all 3 sub-tests succeeded");
        std::process::exit(0);
    } else {
        log!("FAIL — {} sub-test failure(s):", failures.len());
        for f in &failures {
            log!("  - {}", f);
        }
        std::process::exit(2);
    }
}
