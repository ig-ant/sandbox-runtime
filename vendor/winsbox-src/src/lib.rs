//! Library facade for the broker crate. Most code lives in the binary
//! (`src/main.rs` + siblings); the `lib.rs` exists so:
//!
//! 1. `cargo test --lib <module>` works for new modules under unit test
//!    (e.g. `acl_stamper`, `stamp_manifest`).
//! 2. `examples/*.rs` can `use sbox_exec::acl_stamper;` to bench against
//!    real paths without rebuilding the whole binary.
//!
//! The binary still owns its own `mod foo;` declarations — we don't share
//! the FS-broker / token / launch modules through the lib because they
//! pull in heavy Win32 surface that's binary-only. New phase-A modules go
//! here.

#[cfg(windows)]
pub mod util;

#[cfg(windows)]
pub mod acl_stamper;

#[cfg(windows)]
pub mod stamp_manifest;
