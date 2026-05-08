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
    /// Hook `NtCreateFile`/`NtOpenFile` so reads/writes go through
    /// the broker's policy engine. When false (default during
    /// bring-up) the Phase-1 ACL grants are the only FS gate.
    pub broker_fs: bool,
    /// Phase selector understood by the launcher. Phase 0.5 only
    /// implements `Stub`; later phases add `AppContainer` / `Broker`.
    pub mode: Mode,
    /// Phase-B opt-in. Path to `ac_cdylib.dll` (or compatible) to
    /// inject into the AC target post-spawn. When `None` the launch
    /// path is identical to pre-Phase-B. The broker also honours
    /// the `WINSBOX_CDYLIB` environment variable as a fallback so
    /// smoke tests / CI can opt in without editing policy JSON.
    pub cdylib_path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct NetworkPolicy {
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Stub,
    AppContainer,
    Broker,
}
