//! `sbox-exec install` subcommand. Elevation required.
//!
//! Phase 2 responsibilities:
//!   - Check elevation via `TokenElevation`; refuse if unelevated.
//!   - Resolve SANDBOX_SID, call `wfp::install_persistent(port)`.
//!   - Reserve the proxy port with
//!     `netsh int ipv4 add excludedportrange protocol=tcp startport=<port> numberofports=1 store=persistent`.
//!   - Write marker file to `%ProgramData%\winsbox\installed.json`.
//!   - Roll back on partial failure.

use anyhow::Result;

/// `sbox-exec install` (default port `60080` if `None`).
pub fn install(_port: Option<u16>) -> Result<()> {
    todo!("phase 2: admin check + wfp::install_persistent + netsh + marker file")
}

/// `sbox-exec install --remove`.
pub fn remove() -> Result<()> {
    todo!("phase 2")
}

/// `sbox-exec install --check`.
pub fn check() -> Result<()> {
    todo!("phase 2: print marker file contents or 'not installed'")
}
