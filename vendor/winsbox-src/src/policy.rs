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
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct NetworkPolicy {
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
}

/// Phase-D-3 internal mode selector. The policy schema no longer carries
/// a `mode` field — the production path is `AppContainer + cdylib + ACL
/// stamps`. `WINSBOX_LEGACY_BROKER=1` selects the pre-D legacy broker-FS
/// path for staged rollback during the D-1→D-4 transition; this knob
/// goes away in D-4 once the cdylib path's bash workload is verified.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    #[default]
    AppContainer,
    Broker,
}

impl Mode {
    pub fn from_env() -> Self {
        if std::env::var("WINSBOX_LEGACY_BROKER").as_deref() == Ok("1") {
            Mode::Broker
        } else {
            Mode::AppContainer
        }
    }
}
