//! `winsbox` — WFP+SID network sandbox for Windows.
//!
//! Library entry point so `cargo test --lib` can reach internal modules.
//! Most modules are Windows-only; non-Windows builds expose only
//! `policy`.

pub mod policy;

#[cfg(windows)] pub mod util;
#[cfg(windows)] pub mod token;
#[cfg(windows)] pub mod job;
#[cfg(windows)] pub mod sid;
#[cfg(windows)] pub mod wfp;
#[cfg(windows)] pub mod proxy;
#[cfg(windows)] pub mod install;
#[cfg(windows)] pub mod launch;
#[cfg(windows)] pub mod winsta;
#[cfg(windows)] pub mod self_protect;
#[cfg(windows)] pub mod share_mode;
#[cfg(windows)] pub mod acl;
pub mod lock_db;
