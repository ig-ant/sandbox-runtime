//! Phase B smoke test: spawn `cmd.exe` under AppContainer with cdylib
//! injection enabled, verify the cdylib reported back via the shared
//! section + event protocol.
//!
//! This is an `examples/` binary rather than `tests/` because it
//! produces visible stderr output and exercises real Win32 surface;
//! `cargo test` capture would hide most of the diagnostic context
//! that's the value-add of the smoke run.
//!
//! Usage:
//!
//!   cargo run --example smoke-cdylib --release
//!
//! Pre-reqs:
//!   * `ac_cdylib.dll` exists at `<CARGO_TARGET_DIR>/release/ac_cdylib.dll`
//!     or alongside the example binary, or on `WINSBOX_CDYLIB`.
//!   * Run from a directory the AC can access (test uses `cmd /c`).
//!
//! Race mitigation: we use
//!   `cmd.exe /c "ping -n 2 127.0.0.1 > nul && exit 0"`
//! so the target stays alive ~1.5–2 s — well past the 150 ms settle
//! and the typical sub-100 ms LoadLibraryW + DllMain latency. With
//! `cmd /c exit 0` the process can exit before the remote thread
//! fires; we mitigate by holding it with `ping`. See B0's notes.
//!
//! Exit codes:
//!   0 — pass (cdylib reported back, init OK, sentinel OK)
//!   1 — setup error (couldn't locate dll, couldn't build policy, etc.)
//!   2 — cdylib injection failed (see stderr for the underlying error)

#[cfg(not(windows))]
fn main() {
    eprintln!("smoke-cdylib: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    use std::time::Instant;

    macro_rules! log { ($($a:tt)*) => { eprintln!("[smoke-cdylib] {}", format!($($a)*)) } }

    // Locate the cdylib; mirrors what cdylib_inject::locate_cdylib does
    // but lives outside the broker binary, so we re-implement the
    // search here rather than depend on a private module.
    fn locate_sleep_target() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent()?;
        // smoke_cdylib + sleep_target both end up in target/<profile>/examples/
        let cand = exe_dir.join("sleep_target.exe");
        if cand.exists() { Some(cand.canonicalize().unwrap_or(cand)) }
        else { None }
    }

    fn locate_cdylib() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WINSBOX_CDYLIB") {
            let pb = PathBuf::from(p);
            if pb.exists() { return Some(pb); }
        }
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent()?;
        for c in [
            exe_dir.join("ac_cdylib.dll"),
            exe_dir.parent().map(|p| p.join("release").join("ac_cdylib.dll"))
                .unwrap_or_default(),
        ] {
            if c.exists() {
                return Some(c.canonicalize().unwrap_or(c));
            }
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            let p = std::path::Path::new(&td).join("release").join("ac_cdylib.dll");
            if p.exists() { return Some(p); }
        }
        None
    }

    let dll = match locate_cdylib() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke-cdylib] FAIL: ac_cdylib.dll not found. Build with:\n\
                 \n  cargo build -p ac-cdylib --release\n\n\
                 Then re-run, or pass WINSBOX_CDYLIB=<absolute path>."
            );
            std::process::exit(1);
        }
    };
    log!("dll = {}", dll.display());

    // Build a minimal policy invoking sbox-exec with cdylib_path set.
    // We invoke the broker binary as a child so this example exercises
    // the *real* launch path (run_confined) rather than reaching into
    // private modules.
    let sbox = match std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        .map(|d| {
            // examples/smoke-cdylib lives under target/<profile>/examples/
            // sbox-exec.exe lives under target/<profile>/. Walk up.
            let parent = d.parent().map(|p| p.to_path_buf()).unwrap_or(d.clone());
            parent.join("sbox-exec.exe")
        }) {
        Some(p) if p.exists() => p,
        _ => {
            // Fall back to CARGO_TARGET_DIR/debug/sbox-exec.exe since we
            // typically build the broker in debug.
            if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
                let p = std::path::Path::new(&td).join("debug").join("sbox-exec.exe");
                if p.exists() { p } else {
                    eprintln!("[smoke-cdylib] FAIL: sbox-exec.exe not found; build with `cargo build --bin sbox-exec`.");
                    std::process::exit(1);
                }
            } else {
                eprintln!("[smoke-cdylib] FAIL: sbox-exec.exe not found; build with `cargo build --bin sbox-exec`.");
                std::process::exit(1);
            }
        }
    };
    log!("sbox-exec = {}", sbox.display());

    // Race mitigation: the user prompt notes that `cmd /c exit 0`
    // races the LoadLibraryW remote thread. Phase B uses the sibling
    // `sleep_target` example as a 2 s sleeper — bare native PE,
    // no stdin reads, no network. Found during bring-up that:
    //   * `cmd /c exit 0` exits before the 150 ms settle.
    //   * `cmd /c ping` needs network capabilities AC denies.
    //   * `cmd /c timeout` aborts on non-console stdin (NUL counts).
    //
    // The post-injection target exit code is whatever sleep_target
    // returns (0 if it slept the full 2s); we only assert on the
    // cdylib report-back log line.
    let sleep_exe = match locate_sleep_target() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke-cdylib] FAIL: sleep_target.exe not found. Build with:\n\
                 \n  cargo build --example sleep_target\n"
            );
            std::process::exit(1);
        }
    };
    log!("sleep target = {}", sleep_exe.display());

    let policy_json = serde_json::json!({
        "commandLine": format!("\"{}\" 2000", sleep_exe.display()),
        "mode": "app-container",
        "cdylibPath": dll.to_string_lossy(),
        // sleep_target needs read+execute on its own dir for the
        // AC to load it (loader needs the binary itself, then
        // implicit imports — kernelbase/ucrtbase/ntdll which all
        // already grant ALL APPLICATION PACKAGES).
        "allowRead": vec![sleep_exe.parent().unwrap().to_string_lossy().to_string()],
        "allowWrite": Vec::<String>::new(),
    });
    log!("policy = {}", policy_json);

    // Write the policy to a temp file rather than piping it via
    // stdin: the broker spawns the AC target with default stdio
    // inheritance, and `timeout.exe` (one of the more reliable
    // sleeps-for-N-seconds tools) refuses to run when its stdin
    // is a pipe rather than a tty. Bypass the issue by using a
    // file-backed --policy.
    let pol_path = std::env::temp_dir().join(format!(
        "smoke-cdylib-{}.json", std::process::id()
    ));
    if let Err(e) = std::fs::write(&pol_path, policy_json.to_string()) {
        eprintln!("[smoke-cdylib] FAIL: write {}: {e:#}", pol_path.display());
        std::process::exit(1);
    }
    log!("policy file = {}", pol_path.display());

    let t0 = Instant::now();
    let child = match std::process::Command::new(&sbox)
        .arg("--policy").arg(&pol_path)
        // Explicit `null` stdin so the AC target inherits a closed
        // (not piped) stdin handle. With `inherit` the smoke binary's
        // own stdin (a pipe when run from `cargo run`/PowerShell)
        // propagates into the AC and `timeout.exe` refuses to start
        // ("Input redirection is not supported").
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[smoke-cdylib] FAIL: spawn sbox-exec: {e:#}");
            std::process::exit(1);
        }
    };
    let mut child = child;
    // Capture stderr for grep (and re-emit for the operator).
    let stderr = child.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let mut buf = String::new();
        let r = BufReader::new(stderr);
        for line in r.lines() {
            match line {
                Ok(l) => {
                    eprintln!("{l}");
                    buf.push_str(&l);
                    buf.push('\n');
                }
                Err(_) => break,
            }
        }
        buf
    });

    let status = child.wait().expect("wait sbox-exec");
    let total_ms = t0.elapsed().as_millis();
    let stderr_dump = stderr_thread.join().unwrap_or_default();
    let _ = std::fs::remove_file(&pol_path);

    log!("sbox-exec exited code={:?} ({} ms)", status.code(), total_ms);

    // Look for the success log line emitted by trigger() on
    // verified report. The format is:
    //   "[sbox-exec] cdylib reported back: pid=<P> version=<V> init=<I> ..."
    let report_line = stderr_dump.lines()
        .find(|l| l.contains("cdylib reported back"));
    match report_line {
        Some(l) => {
            log!("PASS: {l}");
            std::process::exit(0);
        }
        None => {
            log!("FAIL: did not see 'cdylib reported back' in broker stderr");
            // Surface a few interesting lines for the human:
            for l in stderr_dump.lines() {
                if l.contains("cdylib") || l.contains("[sbox-exec]") {
                    log!("  {}", l);
                }
            }
            std::process::exit(2);
        }
    }
}
