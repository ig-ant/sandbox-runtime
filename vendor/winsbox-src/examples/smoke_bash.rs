//! Phase E-4: end-to-end MSYS2 bash workload smoke test.
//!
//! Spawns the broker (`sbox-exec`) with a policy that runs Git's
//! `bash.exe` under the AppContainer + cdylib + ACL-stamps path, and
//! checks the basic invariants:
//!
//!  1. `bash -c "echo hello && /usr/bin/uname -a"` exits 0 with `hello`
//!     on stdout and no `0xc000...` crash codes on stderr.
//!  2. `bash -c "ls /usr/bin | head -3"` (a pipeline + fork) exits 0
//!     with at least one line of stdout.
//!  3. `bash -c "cat ~/.ssh/id_rsa 2>&1; true"` produces some
//!     "Permission denied" / "No such file" diagnostic and exits 0
//!     (because of `; true`), confirming the deny stamp / default-closed
//!     ACL is enforcing.
//!
//! Pre-reqs:
//!  - `sbox-exec.exe` and `ac_cdylib.dll` built and findable
//!    (env-var `WINSBOX_SBOX` / `WINSBOX_CDYLIB`, alongside this
//!    example's binary, or under `<CARGO_TARGET_DIR>/<profile>/`).
//!  - Git for Windows installed at the standard location
//!    (`C:\Program Files\Git\usr\bin\bash.exe`); override via the
//!    `WINSBOX_BASH` env var.
//!
//! Exit codes:
//!  0 — all three sub-tests pass
//!  1 — setup error
//!  2 — sub-test failure
//!
//! Usage:
//!
//! ```pwsh
//! $env:CARGO_TARGET_DIR = "C:\Users\ig\winsbox-target"
//! & "$env:USERPROFILE\.cargo\bin\cargo.exe" run --example smoke_bash
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("smoke_bash: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
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
