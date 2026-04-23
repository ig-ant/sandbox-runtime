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
    /// Phase selector understood by the launcher. Phase 0.5 only
    /// implements `Stub`; later phases add `AppContainer` / `Broker`.
    pub mode: Mode,
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
