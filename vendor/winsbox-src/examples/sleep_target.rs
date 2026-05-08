//! Tiny sleep target used by the cdylib smoke test. Sleeps for the
//! number of milliseconds in `argv[1]` (default 2000) then exits 0.
//!
//! Why a custom binary instead of `cmd /c timeout` or `cmd /c ping`:
//!   * `timeout.exe` aborts when its stdin is anything other than a
//!     console (refuses pipes / NUL handles) — fragile under
//!     non-interactive cargo + PowerShell harnesses.
//!   * `ping.exe` needs network capabilities the AC doesn't grant.
//!   * `cmd /c <bare>` exits in <50 ms — too fast for the
//!     CreateRemoteThread settle window (B0 finding).
//!
//! Tiny static-ish PE: only links kernel32 (Sleep) via Rust's std,
//! plus the std panic handler. Survives AC just fine — no loader
//! quirks, no stdin reads.

#[cfg(windows)]
fn main() {
    let ms: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sleep_target: windows only");
    std::process::exit(1);
}
