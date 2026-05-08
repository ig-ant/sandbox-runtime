use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct Policy {
    pub command_line: String,
    pub cwd: Option<String>,
    /// Additional env vars layered on top of the parent's environment.
    pub env: Vec<(String, String)>,
    pub allow_read: Vec<String>,
    pub deny_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_write: Vec<String>,
    pub network: NetworkPolicy,
    pub use_alternate_desktop: bool,
    /// Path to `ac_cdylib.dll` (or compatible) to inject into the AC
    /// target post-spawn. When `None` the broker falls back to the
    /// `WINSBOX_CDYLIB` environment variable; if neither is set the
    /// AC runs without compat hooks (suitable for non-MSYS workloads
    /// — bash/git/npm need the cdylib for namespace shims).
    pub cdylib_path: Option<String>,
    /// Phase G: caller-controlled key for deriving a stable AC profile
    /// name (and thus a stable AC SID across runs). When `Some(k)`,
    /// the broker hashes `k` to produce the profile-name suffix; same
    /// `k` across launches → same SID → manifest cache hit → warm
    /// restart skips the 3.5s ACL stamping walk.
    ///
    /// When `None`, the broker falls back to a hash of its own install
    /// path (`std::env::current_exe()`), which is per-install stable.
    /// Callers that want per-policy stability (e.g., distinct policies
    /// in the same install) should pass a stable string here — the
    /// session id, the workspace dir, etc.
    ///
    /// JSON name: `stableSidKey`.
    pub stable_sid_key: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct NetworkPolicy {
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
}
