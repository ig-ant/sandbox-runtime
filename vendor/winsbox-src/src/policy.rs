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
}
