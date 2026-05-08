//! Phase K smoke test: run the cdylib smoke target with
//! `WINSBOX_TRACE_SYSCALLS=1` and assert the broker emits
//! `[sbox-trace]` lines for the new opt-in trace hooks.
//!
//! The trace mode patches 12 additional `Nt*` syscalls (file opens,
//! IOCTL, ALPC, registry, sync primitives) that bash's bootstrap
//! plausibly hits. Each is a passthrough+log shape — no semantic
//! change to the syscall, just an IPC frame to the broker so the
//! crash-region diagnostic in Phase L has data.
//!
//! Why `sleep_target` and not `cmd /c echo hi`:
//!   * The plan named `cmd /c echo hi` but we re-use the existing
//!     smoke target for parity with `smoke_cdylib`. Loading
//!     `sleep_target.exe` still touches every interesting trace
//!     syscall (NtOpenFile to load ntdll/kernel32/ucrtbase, NtOpenKey
//!     for image-options registry lookups, NtCreateEvent for std's
//!     thread sync). `cmd.exe` inside an AC additionally needs ACL
//!     grants we don't set up here.
//!   * Trace mode itself is target-agnostic; once it works on
//!     `sleep_target`, Phase L runs the same broker against
//!     `bash.exe` with no further wiring.
//!
//! Pass criteria:
//!   * Broker stderr contains "trace hooks patched pre-resume" (i.e.,
//!     install_trace ran and didn't bail).
//!   * Target exits cleanly (exit code 0).
//!   * Broker stderr contains at least `TRACE_FLOOR` (5)
//!     `[sbox-trace]` lines — the loader's bootstrap exercises every
//!     trace syscall family on the standard sleep_target path.
//!
//! No "degraded pass" mode. The Phase K fix-up forced the dev-profile
//! `ac-cdylib` to opt-level 2 (matching release) so the manual-mapped
//! hook bodies behave identically across `cargo build` and
//! `cargo build --release`. If the target AVs at 0xC0000005 again, the
//! diagnostic regression caught one of: a hook bytecode bug (debug-
//! profile codegen, `extern "system"` ABI break), a manual-map fixup
//! gap (relocation/section-protection drift), or an IPC env layout
//! mismatch (cdylib `IpcEnv` vs broker `prefill_ipc` slot offsets).
//!
//! Default-OFF check is covered by `smoke_cdylib` itself: if this
//! example introduces overhead in the no-env-var path, that test
//! would regress.

#[cfg(not(windows))]
fn main() {
    eprintln!("smoke_trace: windows only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    use std::time::Instant;

    macro_rules! log { ($($a:tt)*) => { eprintln!("[smoke_trace] {}", format!($($a)*)) } }

    fn locate_sleep_target() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent()?;
        let cand = exe_dir.join("sleep_target.exe");
        if cand.exists() { Some(cand.canonicalize().unwrap_or(cand)) } else { None }
    }

    fn locate_cdylib() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("WINSBOX_CDYLIB") {
            let pb = PathBuf::from(p);
            if pb.exists() { return Some(pb); }
        }
        let exe = std::env::current_exe().ok()?;
        let exe_dir = exe.parent()?;
        // Check the example's own debug/release sibling first, then
        // fall back to peer profile dirs. With the Phase K fix-up
        // forcing opt-level=2 on the ac-cdylib package even in dev,
        // both profiles produce a usable cdylib; we still prefer the
        // sibling profile so a `cargo run --example smoke_trace`
        // (debug) doesn't accidentally pick a stale release artifact.
        for c in [
            exe_dir.join("ac_cdylib.dll"),
            exe_dir.parent().map(|p| p.join("debug").join("ac_cdylib.dll"))
                .unwrap_or_default(),
            exe_dir.parent().map(|p| p.join("release").join("ac_cdylib.dll"))
                .unwrap_or_default(),
        ] {
            if c.exists() {
                return Some(c.canonicalize().unwrap_or(c));
            }
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            for sub in ["debug", "release"] {
                let p = std::path::Path::new(&td).join(sub).join("ac_cdylib.dll");
                if p.exists() { return Some(p); }
            }
        }
        None
    }

    fn locate_broker() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let parent = exe.parent()?.parent()?.to_path_buf();
        let cand = parent.join("sbox-exec.exe");
        if cand.exists() { return Some(cand); }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            for sub in ["debug", "release"] {
                let p = PathBuf::from(&td).join(sub).join("sbox-exec.exe");
                if p.exists() { return Some(p); }
            }
        }
        None
    }

    let dll = match locate_cdylib() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_trace] FAIL: ac_cdylib.dll not found.\n\
                 Build with: cargo build -p ac-cdylib"
            );
            std::process::exit(1);
        }
    };
    let sleep_exe = match locate_sleep_target() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_trace] FAIL: sleep_target.exe not found.\n\
                 Build with: cargo build --example sleep_target"
            );
            std::process::exit(1);
        }
    };
    let sbox = match locate_broker() {
        Some(p) => p,
        None => {
            eprintln!(
                "[smoke_trace] FAIL: sbox-exec.exe not found.\n\
                 Build with: cargo build --bin sbox-exec"
            );
            std::process::exit(1);
        }
    };
    log!("dll          = {}", dll.display());
    log!("sleep_target = {}", sleep_exe.display());
    log!("sbox-exec    = {}", sbox.display());

    let policy_json = serde_json::json!({
        // 500 ms is enough for the loader's syscall storm to fire and
        // the broker to log the trace; we don't need 2 s.
        "commandLine": format!("\"{}\" 500", sleep_exe.display()),
        "mode": "app-container",
        "cdylibPath": dll.to_string_lossy(),
        "allowRead": vec![sleep_exe.parent().unwrap().to_string_lossy().to_string()],
        "allowWrite": Vec::<String>::new(),
    });

    let pol_path = std::env::temp_dir().join(format!(
        "smoke-trace-{}.json", std::process::id()
    ));
    if let Err(e) = std::fs::write(&pol_path, policy_json.to_string()) {
        eprintln!("[smoke_trace] FAIL: write policy: {e:#}");
        std::process::exit(1);
    }

    let t0 = Instant::now();
    let child = match std::process::Command::new(&sbox)
        .arg("--policy").arg(&pol_path)
        // The opt-in trace switch — drives launch.rs's `install_trace`
        // path. Set on the broker itself; the cdylib reads it via the
        // IPC env that the broker fills in pre-resume.
        .env("WINSBOX_TRACE_SYSCALLS", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&pol_path);
            eprintln!("[smoke_trace] FAIL: spawn sbox-exec: {e:#}");
            std::process::exit(1);
        }
    };
    let mut child = child;
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

    // Verify install ran. install_trace logs how many of the 12
    // hooks landed; we just check that the line is present.
    let install_line = stderr_dump.lines()
        .find(|l| l.contains("trace hooks patched pre-resume"));
    if install_line.is_none() {
        log!("FAIL: did not see 'trace hooks patched pre-resume' — install_trace skipped?");
        for l in stderr_dump.lines() {
            if l.contains("trace") || l.contains("WINSBOX_TRACE") {
                log!("  {}", l);
            }
        }
        std::process::exit(2);
    }
    log!("OK: {}", install_line.unwrap());

    // Hard gate: target must have exited cleanly. Pre-fix-up the dev
    // cdylib AVed during the loader's first hook entry (debug-profile
    // ARM64 codegen quirk in the hook prologue); the fix-up matches
    // dev's `ac-cdylib` opt-level to release, so any 0xC0000005 from
    // here on is a real regression in either the cdylib's hook bodies,
    // the manual-map fixups, or the IPC env layout. Don't paper over
    // it with a "degraded pass".
    let rendezvous_failed = stderr_dump.lines().any(|l|
        l.contains("entry rendezvous failed") ||
        l.contains("cdylib injection setup failed")
    );
    if rendezvous_failed {
        log!("FAIL: entry rendezvous failed — target AVed before the loader ran");
        for l in stderr_dump.lines() {
            if l.contains("rendezvous") || l.contains("setup failed") ||
                l.contains("target exit") {
                log!("  {}", l);
            }
        }
        std::process::exit(2);
    }
    if status.code() != Some(0) {
        log!(
            "FAIL: target exit was {:?}, expected 0 — loader hit a hook \
             that crashed mid-run", status.code(),
        );
        std::process::exit(2);
    }

    // Hard gate: must see at least TRACE_FLOOR `[sbox-trace]` lines.
    // The loader's bootstrap exercises every trace family
    // (NtCreateEvent, NtOpenKey, NtQueryValueKey, NtOpenFile,
    // NtDeviceIoControlFile) on the standard sleep_target path; floor
    // is comfortably below the typical 40+ count. Zero trace lines
    // means the cdylib never had a chance to call ipc_trace_send,
    // which (given a clean target exit) implies the install path
    // skipped every hook.
    let trace_lines: Vec<&str> = stderr_dump.lines()
        .filter(|l| l.contains("[sbox-trace]"))
        .collect();
    log!("trace lines emitted: {}", trace_lines.len());
    const TRACE_FLOOR: usize = 5;
    if trace_lines.len() < TRACE_FLOOR {
        log!("FAIL: only {} trace lines, expected ≥{} (loader ran but no traces fired)",
             trace_lines.len(), TRACE_FLOOR);
        for l in &trace_lines { log!("  {}", l); }
        std::process::exit(2);
    }
    log!("PASS: {} trace lines (≥{})", trace_lines.len(), TRACE_FLOOR);

    // Echo a few sample lines for the operator — useful when running
    // this manually to eyeball trace coverage.
    log!("sample trace output:");
    for l in trace_lines.iter().take(5) {
        log!("  {}", l);
    }
    std::process::exit(0);
}
