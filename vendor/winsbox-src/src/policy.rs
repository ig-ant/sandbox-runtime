//! Run-mode policy file shape (JSON, gutted to the bare minimum
//! needed by the WFP+SID design). The `winsbox-msys2-iter` policy
//! grew AC-SID lists, broker mount paths, ACL stamp manifests, etc.
//! — none of that exists here.

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    pub target_exe: std::path::PathBuf,
    #[serde(default)] pub target_args: Vec<String>,
    #[serde(default)] pub cwd: Option<std::path::PathBuf>,
    #[serde(default)] pub env_extra: std::collections::HashMap<String, String>,
    /// Phase 5: paths the sandbox must NOT be able to read. The broker
    /// acquires a share-mode-0 (only FILE_SHARE_DELETE) handle on each
    /// path before spawning the child; the kernel's share-mode check
    /// then refuses any subsequent open from the sandbox child that
    /// requests GENERIC_READ.
    ///
    /// Non-existent paths are silently skipped (a secret may not exist
    /// in the current workspace). Other failures bubble up.
    #[serde(default)] pub fs_deny_read: Vec<std::path::PathBuf>,
}
