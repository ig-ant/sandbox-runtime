//! Phase E-1: cdylib injection helpers retained after the manual-map
//! cutover.
//!
//! Phase B/C/D wired up `LoadLibraryW` + `CreateRemoteThread` injection
//! with a section/event handshake (the `CdylibBuffer` + DllMain init
//! protocol). Phase E-1 replaced that with `manual_map` (pre-resume
//! manual map of the cdylib at `/BASE:0x70000000`); the production
//! flow no longer involves `LoadLibraryW`. D-4 deletes the dead
//! Phase-B/C/D scaffolding entirely; what remains here is the minimal
//! surface the broker still depends on:
//!
//!   * `placeholder_env_pair` — the broker pushes this into
//!     `extra_env` before spawn so the env block has space for an
//!     `AC_CDYLIB_BUFFER` slot. The slot is unused by the manual-map
//!     loader (it never reads the buffer), but having it present keeps
//!     diagnostic tooling that grep'd for the env var working.
//!   * `CdylibReport` — diagnostic struct retained on `CdylibInjection`
//!     so the broker logs a uniform "cdylib reported back" line for the
//!     smoke test. The manual-map path fills this with a synthetic
//!     value (no DllMain ran) — see `launch.rs::try_inject_cdylib_full`.

#![cfg(windows)]

/// Env-var key the legacy LoadLibraryW path used to pass the in-target
/// VA of `CdylibBuffer` into the cdylib's DllMain. The manual-map path
/// doesn't read this, but the env slot is still pushed so future
/// diagnostic tooling that greps for `AC_CDYLIB_BUFFER` keeps working.
pub const ENV_KEY: &str = "AC_CDYLIB_BUFFER";

/// 16-char hex placeholder. Same shape the legacy `prepare()` would
/// have overwritten in-place; manual-map mode leaves it as zeros.
pub const ENV_PLACEHOLDER: &str = "0000000000000000";

/// Diagnostic copy of the cdylib's report-back struct. Pre-Phase-E
/// the cdylib's DllMain stamped real values here (init_result, version,
/// pid, sentinel); manual-map mode synthesises the line in the broker
/// log directly. The struct is kept because `CdylibInjection` retains
/// it as a field for future re-use.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CdylibReport {
    pub init_result: u32,
    pub version: u32,
    pub sentinel: u32,
    pub pid: u32,
}

/// Build the env-var entry the caller must include in the env block
/// passed to `CreateProcess`.
pub fn placeholder_env_pair() -> (String, String) {
    (ENV_KEY.to_string(), ENV_PLACEHOLDER.to_string())
}
