//! Top-level run-mode entry point: build the restricted token, create
//! the job, build the env (including `HTTP_PROXY`/`HTTPS_PROXY`/
//! `ALL_PROXY`), spawn the target suspended, assign to job, start the
//! proxy, resume, wait for exit.
//!
//! Phase 2 will implement this; signature is fixed so `main.rs` can
//! reference it.

use anyhow::Result;

use crate::policy::Policy;

/// Run a policy and return the child's exit code.
pub fn run(_pol: &Policy) -> Result<u32> {
    todo!("phase 2: build token, job, env, spawn, start proxy, wait")
}
