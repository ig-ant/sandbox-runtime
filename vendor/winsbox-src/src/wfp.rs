//! Windows Filtering Platform (WFP) filter install/remove.
//!
//! Phase 2 responsibilities:
//!   - Open an engine handle via `FwpmEngineOpen0`.
//!   - Create a stable-GUID sublayer via `FwpmSubLayerAdd0`.
//!   - Install 6 filters (3 at IPv4 + 3 at IPv6 ALE_AUTH_CONNECT):
//!     1. PERMIT — match SANDBOX_SID + remote=loopback + remote_port=proxy.
//!     2. BLOCK  — match SANDBOX_SID (lower weight than #1).
//!     3. BLOCK — remote=loopback + remote_port=proxy + NOT SANDBOX_SID
//!                (filter shape TBD: separate sublayer + ordering, or
//!                DENY-ACE SD; see open questions in the plan).
//!   - Persistent (non-dynamic) filters; survive reboot.
//!   - Marker file at `%ProgramData%\winsbox\installed.json` records
//!     port + filter/sublayer GUIDs.

use anyhow::Result;

/// Install the persistent WFP filter set keyed on SANDBOX_SID, with
/// `proxy_port` as the only permitted destination on loopback.
pub fn install_persistent(_proxy_port: u16) -> Result<()> {
    todo!("phase 2: FwpmEngineOpen0 + sublayer + 6 filters")
}

/// Remove the filters and sublayer installed by `install_persistent`.
pub fn uninstall_persistent() -> Result<()> {
    todo!("phase 2: remove filters + sublayer")
}

/// Return `Some(port)` if filters are present (from marker file),
/// `None` if not installed.
pub fn is_installed() -> Result<Option<u16>> {
    todo!("phase 2: read marker file at %ProgramData%\\winsbox\\installed.json")
}
