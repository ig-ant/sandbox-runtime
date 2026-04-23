//! Placeholder secondary binary. The probes ended up re-exec'ing the
//! main `winsbox-poc` binary via `child <which>` instead of using a
//! separate target, so this is unused but kept so Cargo's [[bin]] entry
//! resolves on both platforms.
fn main() {
    std::process::exit(0);
}
