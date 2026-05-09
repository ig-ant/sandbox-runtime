//! Phase N-2: broker-mediated `NtCreateFile` / `NtOpenFile` policy
//! decisions. The cdylib's proxy hooks send `OP_BROKER_OPEN` frames
//! after the saved-original syscall returns `STATUS_ACCESS_DENIED`;
//! this module provides the policy-check primitive the broker uses
//! to decide whether to grant the open.
//!
//! ## Security model
//!
//! Three policy sources for "broker may broker this open":
//!
//! 1. **Explicit `allowRead` / `allowWrite`** — paths the user listed
//!    in config. `denyRead` / `denyWrite` overrides — a path matching
//!    a deny prefix is rejected even if it's also covered by an
//!    allow prefix.
//! 2. **Auto-toolchain dirs** — when `auto_toolchain_access` is true
//!    (default), the broker walks `process.env.PATH` at startup and
//!    adds entries under recognised toolchain roots (`Program Files`,
//!    `Program Files (x86)`, `%LOCALAPPDATA%\Programs`,
//!    `%USERPROFILE%\scoop`, `%USERPROFILE%\.cargo\bin`) to a
//!    **read-only** allow list.
//! 3. **System dirs** — should never reach broker mediation; the
//!    kernel grants AC tokens AAP-readable access via standard ACEs
//!    on system DLLs / registry keys.
//!
//! ## Path normalisation
//!
//! Inputs come from the AC via `OBJECT_ATTRIBUTES.ObjectName`. Format:
//!
//!   * `\??\C:\path` — the canonical NT-namespace form Win32 file
//!     functions use; `\??\` is the per-session dosdevices link to
//!     `\GLOBAL??\`. Strip the prefix.
//!   * `C:\path` — bare DOS form. Use as-is.
//!   * `\Device\…` — the device-namespace form. Reject; we only
//!     mediate file paths under DOS drive letters.
//!   * `\??\UNC\server\share\…` — UNC. Strip the `\??\UNC\` prefix
//!     and prepend `\\` so it looks like `\\server\share\…`.
//!
//! Comparison is **case-insensitive** (Windows file-system semantics)
//! and **prefix-based with directory boundary**. `C:\foo\bar` is
//! covered by an allow rule of `C:\foo` but NOT by `C:\fo`.
//!
//! ## Symlink / junction defence
//!
//! The policy check runs twice: once on the input path and again on
//! the canonicalized post-open path (resolved via
//! `GetFinalPathNameByHandleW`). A junction inside an allowed dir
//! that points outside any allowed dir gets rejected at the
//! second-pass, after the broker has the handle. Caller closes the
//! broker handle on failure and returns `STATUS_ACCESS_DENIED` to
//! the AC.

use std::path::PathBuf;

/// Decision the broker makes about a candidate broker-mediated open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Path is in an allow list (and not in a deny list); broker may
    /// re-issue the open.
    Allow,
    /// Path is denied — either matched a deny list, or didn't match
    /// any allow list. `reason` distinguishes for the audit log.
    Reject(RejectReason),
}

/// Why a broker-open was rejected. Surfaced in the
/// `[sbox-exec] broker-open: REJECTED reason="…"` log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Path matched a `denyRead` prefix.
    DenyRead,
    /// Path matched a `denyWrite` prefix.
    DenyWrite,
    /// Path didn't match any allow list (including auto-toolchain
    /// dirs).
    NotInAllowList,
    /// Caller asked for write access to a read-only path (e.g.,
    /// `allowRead` or auto-toolchain).
    WriteToReadOnly,
    /// `RootDirectory` was non-NULL (relative open). Not supported
    /// in this iteration; document as M-1+ follow-up.
    RelativeOpen,
    /// Path didn't normalise to a DOS drive (e.g., `\Device\Null`).
    NonDosPath,
    /// Path was empty.
    EmptyPath,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::DenyRead => "denyRead match",
            RejectReason::DenyWrite => "denyWrite match",
            RejectReason::NotInAllowList => "not in allow list",
            RejectReason::WriteToReadOnly =>
                "write to read-only path (allowRead / auto-toolchain)",
            RejectReason::RelativeOpen =>
                "RootDirectory-relative open not supported",
            RejectReason::NonDosPath =>
                "non-DOS path (e.g., \\Device\\…)",
            RejectReason::EmptyPath => "empty path",
        }
    }
}

/// Snapshot of the policy lists the broker uses. Cheap to clone (just
/// `Vec<String>`s); built once per broker run.
#[derive(Debug, Clone, Default)]
pub struct PolicyLists {
    /// Explicit user-configured `allowRead` paths.
    pub allow_read: Vec<String>,
    /// Explicit user-configured `denyRead` paths.
    pub deny_read: Vec<String>,
    /// Explicit user-configured `allowWrite` paths.
    pub allow_write: Vec<String>,
    /// Explicit user-configured `denyWrite` paths.
    pub deny_write: Vec<String>,
    /// Auto-detected toolchain dirs from broker's PATH (read-only).
    /// Empty when `auto_toolchain_access: false`.
    pub auto_toolchain: Vec<String>,
}

/// Win32 file-access bits we treat as "writes" for policy purposes.
/// Any bit in this mask present in `desired_access` means the caller
/// wants to write — only `allowWrite` paths can satisfy.
///
/// Reference: `winnt.h`. `FILE_GENERIC_WRITE` = 0x00120116; we
/// expand to the underlying bits so callers passing
/// `FILE_WRITE_DATA` directly are also caught.
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
/// MAXIMUM_ALLOWED — caller asked the kernel for "whatever you can
/// give me". Treat as a write request to be conservative; an
/// `allowRead` path with this access bit gets bumped down to read by
/// the broker's actual `NtCreateFile` call (the kernel will prune
/// to the granted access on the broker's user token).
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

const WRITE_MASK: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
    FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
    GENERIC_WRITE | GENERIC_ALL;

/// Return true if `desired_access` requests any write capability.
pub fn is_write_access(desired_access: u32) -> bool {
    desired_access & WRITE_MASK != 0
}

/// Return true if `desired_access` is `MAXIMUM_ALLOWED` only — caller
/// will accept whatever the broker token can grant. We treat as read
/// for allow-list purposes and let the kernel prune.
pub fn is_maximum_allowed(desired_access: u32) -> bool {
    desired_access == MAXIMUM_ALLOWED
}

/// Normalise an `OBJECT_ATTRIBUTES.ObjectName` path to a comparable
/// DOS form. Returns `None` for non-DOS paths (e.g., `\Device\…`).
///
/// Examples:
///   * `\??\C:\Program Files\nodejs` → `C:\Program Files\nodejs`
///   * `\??\UNC\server\share\x` → `\\server\share\x`
///   * `C:\Program Files\nodejs` → `C:\Program Files\nodejs`
///   * `\Device\HarddiskVolume3\X` → None
pub fn normalize_nt_path(p: &str) -> Option<String> {
    if p.is_empty() {
        return None;
    }
    // `\??\UNC\server\share\…` → `\\server\share\…` (handle this
    // before the generic `\??\` strip).
    if let Some(rest) = p.strip_prefix(r"\??\UNC\") {
        return Some(format!(r"\\{}", rest));
    }
    if let Some(rest) = p.strip_prefix(r"\??\") {
        return Some(rest.to_string());
    }
    // Bare DOS form — `C:\…` (drive letter, colon, backslash).
    let bytes = p.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
    {
        return Some(p.to_string());
    }
    // UNC bare form `\\server\share\…`.
    if p.starts_with(r"\\") && !p.starts_with(r"\\?\") {
        return Some(p.to_string());
    }
    // `\\?\` extended path: `\\?\C:\…` → `C:\…`.
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{}", rest));
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return Some(rest.to_string());
    }
    // Anything starting with `\Device\…`, `\GLOBAL??\…` is non-DOS.
    None
}

/// Test whether `path` is under (or equal to) `prefix`. Both are
/// normalised forms (drive letter or UNC root). Comparison is
/// case-insensitive (Windows-FS semantics) with directory-boundary
/// awareness so `C:\foo` does NOT cover `C:\foobar`.
pub fn is_under(path: &str, prefix: &str) -> bool {
    let path_lc = path.to_ascii_lowercase();
    let prefix_lc = prefix.to_ascii_lowercase();
    let prefix_lc = prefix_lc.trim_end_matches('\\');
    if !path_lc.starts_with(prefix_lc) {
        return false;
    }
    // Equal length → exact match.
    if path_lc.len() == prefix_lc.len() {
        return true;
    }
    // Next char in `path` must be a path separator.
    let next = path_lc.as_bytes()[prefix_lc.len()];
    next == b'\\' || next == b'/'
}

/// Phase N-2 Part B: Windows reserved device names. Opening these
/// always succeeds in any user context; they're equivalent to
/// /dev/null + std streams on POSIX. Cygwin/MSYS2 binaries (git,
/// bash) translate `/dev/null` → `\??\nul` for `NtCreateFile`, which
/// the kernel maps to `\Device\Null` regardless of token. Allowing
/// these doesn't expose any FS state — the broker just opens the
/// device and dups the handle.
///
/// Reference: Win32 reserved DOS names. Case-insensitive.
const RESERVED_DOS_DEVICES: &[&str] = &[
    "nul", "con", "prn", "aux",
];

/// Run the policy check against a normalised DOS path. The caller is
/// responsible for stripping the NT-namespace prefix first via
/// [`normalize_nt_path`].
pub fn is_path_allowed_for_broker_open(
    path: &str,
    desired_access: u32,
    pol: &PolicyLists,
) -> Decision {
    if path.is_empty() {
        return Decision::Reject(RejectReason::EmptyPath);
    }
    let want_write = is_write_access(desired_access) && !is_maximum_allowed(desired_access);

    // Phase N-2 Part B: reserved DOS device names always allowed.
    // `nul` (with optional `.txt`-style extension or `:streamname`
    // suffix — Windows ignores anything after the device name).
    let path_lc = path.to_ascii_lowercase();
    let leaf = path_lc.rsplit(['\\', '/']).next().unwrap_or(&path_lc);
    let leaf_base = leaf.split(['.', ':']).next().unwrap_or(leaf);
    if RESERVED_DOS_DEVICES.contains(&leaf_base) {
        return Decision::Allow;
    }

    // 1. Deny lists first — they override every allow.
    for d in &pol.deny_read {
        let Some(dn) = normalize_for_compare(d) else { continue; };
        if is_under(path, &dn) {
            return Decision::Reject(RejectReason::DenyRead);
        }
    }
    if want_write {
        for d in &pol.deny_write {
            let Some(dn) = normalize_for_compare(d) else { continue; };
            if is_under(path, &dn) {
                return Decision::Reject(RejectReason::DenyWrite);
            }
        }
    }

    // 2. Allow lists.
    if want_write {
        // Writes require allow_write. allowRead / auto-toolchain do
        // NOT satisfy a write request.
        for a in &pol.allow_write {
            let Some(an) = normalize_for_compare(a) else { continue; };
            if is_under(path, &an) {
                return Decision::Allow;
            }
        }
        // Read-only allow path matches but caller wanted write —
        // surface a clearer reason than NotInAllowList.
        for a in pol.allow_read.iter().chain(pol.auto_toolchain.iter()) {
            let Some(an) = normalize_for_compare(a) else { continue; };
            if is_under(path, &an) {
                return Decision::Reject(RejectReason::WriteToReadOnly);
            }
        }
        return Decision::Reject(RejectReason::NotInAllowList);
    }

    // Read access: any allow list (allowRead, allowWrite — write
    // implies read, auto_toolchain) satisfies.
    for a in pol.allow_read.iter()
        .chain(pol.allow_write.iter())
        .chain(pol.auto_toolchain.iter())
    {
        let Some(an) = normalize_for_compare(a) else { continue; };
        if is_under(path, &an) {
            return Decision::Allow;
        }
    }
    // Phase N-2: also allow read-only opens of *ancestor* dirs of
    // any allow-listed path. cmd.exe (and many tools) walks up from
    // the drive root to canonicalise relative paths — without this
    // the broker rejects every traversal step. Restricted to
    // `desired_access` covering only directory-traversal-ish bits
    // (no write / EA / DAC bits — those were already rejected
    // above by `want_write`). This is an implicit ALL APPLICATION
    // PACKAGES read-traverse on dirs that lead to allow-listed
    // paths; the broker still re-validates the canonical path
    // post-open, so a junction at e.g. `C:\` redirecting to a
    // sensitive root would re-reject.
    for a in pol.allow_read.iter()
        .chain(pol.allow_write.iter())
        .chain(pol.auto_toolchain.iter())
    {
        let Some(an) = normalize_for_compare(a) else { continue; };
        if is_under(&an, path) {
            // `path` is an ancestor of `an`. Grant read-traverse.
            return Decision::Allow;
        }
    }
    Decision::Reject(RejectReason::NotInAllowList)
}

/// Normalise a raw policy entry for comparison. Strips trailing
/// slashes and uses [`normalize_nt_path`] when present, otherwise
/// falls back to the input.
fn normalize_for_compare(s: &str) -> Option<String> {
    if let Some(n) = normalize_nt_path(s) {
        return Some(n);
    }
    Some(s.trim_end_matches('\\').to_string())
}

/// Phase D: walk `process.env.PATH` and return the entries under
/// recognised toolchain roots. Used at broker startup to populate
/// `PolicyLists.auto_toolchain` when `auto_toolchain_access: true`.
///
/// Roots considered:
///   * `%ProgramFiles%`         (typically `C:\Program Files`)
///   * `%ProgramFiles(x86)%`    (typically `C:\Program Files (x86)`)
///   * `%LOCALAPPDATA%\Programs`
///   * `%USERPROFILE%\scoop`
///   * `%USERPROFILE%\.cargo\bin`
///
/// Excluded:
///   * `%LOCALAPPDATA%\Microsoft\WindowsApps` — Windows Store alias
///     redirector dir; entries are reparse points to UWP packages
///     that need package activation the AC can't reach. Including
///     it just opens an unreachable surface.
pub fn detect_toolchain_dirs() -> Vec<String> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("ProgramFiles") {
        if !p.is_empty() { roots.push(PathBuf::from(p)); }
    }
    if let Ok(p) = std::env::var("ProgramFiles(x86)") {
        if !p.is_empty() { roots.push(PathBuf::from(p)); }
    }
    if let Ok(p) = std::env::var("LOCALAPPDATA") {
        if !p.is_empty() { roots.push(PathBuf::from(p).join("Programs")); }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            roots.push(PathBuf::from(&p).join("scoop"));
            roots.push(PathBuf::from(&p).join(".cargo").join("bin"));
        }
    }
    let store_alias = std::env::var("LOCALAPPDATA").ok()
        .map(|p| PathBuf::from(p).join("Microsoft").join("WindowsApps"));

    let path = std::env::var("PATH").unwrap_or_default();
    let mut out = Vec::new();
    for entry in path.split(';') {
        let e = entry.trim();
        if e.is_empty() { continue; }
        let entry_path = PathBuf::from(e);
        // Skip the Store alias dir explicitly.
        if let Some(s) = &store_alias {
            if path_equals_ci(&entry_path, s) { continue; }
        }
        // Match any of the toolchain roots.
        let matched = roots.iter().any(|r| path_under_ci(&entry_path, r));
        if matched {
            out.push(e.to_string());
        }
    }
    // De-dup while preserving order. PATH commonly lists the same
    // dir multiple times (`Git\cmd` + `Git\bin`).
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.to_ascii_lowercase()));
    out
}

fn path_under_ci(p: &std::path::Path, base: &std::path::Path) -> bool {
    let p_lc = p.to_string_lossy().to_ascii_lowercase();
    let b_lc = base.to_string_lossy().to_ascii_lowercase();
    let b_lc = b_lc.trim_end_matches(['\\', '/']);
    if !p_lc.starts_with(b_lc) { return false; }
    if p_lc.len() == b_lc.len() { return true; }
    let next = p_lc.as_bytes()[b_lc.len()];
    next == b'\\' || next == b'/'
}

fn path_equals_ci(a: &std::path::Path, b: &std::path::Path) -> bool {
    let a_lc = a.to_string_lossy().to_ascii_lowercase();
    let b_lc = b.to_string_lossy().to_ascii_lowercase();
    let a_lc = a_lc.trim_end_matches(['\\', '/']);
    let b_lc = b_lc.trim_end_matches(['\\', '/']);
    a_lc == b_lc
}

// ─── tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> PolicyLists {
        PolicyLists {
            allow_read: vec![r"C:\fixture\base".into()],
            deny_read: vec![r"C:\fixture\base\denyRead".into()],
            allow_write: vec![r"C:\fixture\base\allowWrite".into()],
            deny_write: vec![],
            auto_toolchain: vec![r"C:\Program Files\nodejs".into()],
        }
    }

    #[test]
    fn normalize_strips_nt_prefix() {
        assert_eq!(
            normalize_nt_path(r"\??\C:\foo\bar").unwrap(),
            r"C:\foo\bar",
        );
        assert_eq!(
            normalize_nt_path(r"\??\UNC\server\share\x").unwrap(),
            r"\\server\share\x",
        );
        assert_eq!(
            normalize_nt_path(r"C:\foo\bar").unwrap(),
            r"C:\foo\bar",
        );
        assert!(normalize_nt_path(r"\Device\HarddiskVolume3\X").is_none());
        assert!(normalize_nt_path("").is_none());
    }

    #[test]
    fn is_under_directory_boundary() {
        assert!(is_under(r"C:\foo", r"C:\foo"));
        assert!(is_under(r"C:\foo\bar", r"C:\foo"));
        assert!(is_under(r"C:\foo\bar\baz", r"C:\foo"));
        assert!(!is_under(r"C:\foobar", r"C:\foo"));
        assert!(!is_under(r"C:\foo", r"C:\foo\bar"));
        // Case-insensitive.
        assert!(is_under(r"C:\Foo\Bar", r"c:\foo"));
        // Trailing separator on prefix tolerated.
        assert!(is_under(r"C:\foo\bar", r"C:\foo\"));
    }

    #[test]
    fn allow_read_grants_read_open() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open(
            r"C:\fixture\base\public.txt", 0x0001 /* FILE_READ_DATA */, &pl,
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn deny_read_overrides_allow_read() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open(
            r"C:\fixture\base\denyRead\secret.txt", 0x0001, &pl,
        );
        assert_eq!(d, Decision::Reject(RejectReason::DenyRead));
    }

    #[test]
    fn write_to_allow_read_is_rejected() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open(
            r"C:\fixture\base\public.txt", FILE_WRITE_DATA, &pl,
        );
        assert_eq!(d, Decision::Reject(RejectReason::WriteToReadOnly));
    }

    #[test]
    fn write_to_allow_write_is_granted() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open(
            r"C:\fixture\base\allowWrite\out.txt", FILE_WRITE_DATA, &pl,
        );
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn auto_toolchain_grants_read_only() {
        let pl = lists();
        let d_read = is_path_allowed_for_broker_open(
            r"C:\Program Files\nodejs\node.exe", 0x0001, &pl,
        );
        assert_eq!(d_read, Decision::Allow);
        let d_write = is_path_allowed_for_broker_open(
            r"C:\Program Files\nodejs\node.exe", FILE_WRITE_DATA, &pl,
        );
        assert_eq!(d_write, Decision::Reject(RejectReason::WriteToReadOnly));
    }

    #[test]
    fn ancestor_of_allow_listed_path_is_readable() {
        let pl = lists();
        // `C:\Program Files` is an ancestor of `C:\Program Files\nodejs`
        // (auto_toolchain). Read-traverse should succeed.
        let d = is_path_allowed_for_broker_open(
            r"C:\Program Files", 0x0001, &pl,
        );
        assert_eq!(d, Decision::Allow);
        // `C:\` likewise.
        let d = is_path_allowed_for_broker_open(r"C:\", 0x0001, &pl);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn ancestor_open_for_write_is_rejected() {
        let pl = lists();
        // Ancestor traversal is read-only — writes to `C:\Program Files`
        // must NOT slip through.
        let d = is_path_allowed_for_broker_open(
            r"C:\Program Files", FILE_WRITE_DATA, &pl,
        );
        assert_eq!(d, Decision::Reject(RejectReason::NotInAllowList));
    }

    #[test]
    fn unrelated_path_rejected() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open(
            r"C:\Windows\System32\config\SAM", 0x0001, &pl,
        );
        assert_eq!(d, Decision::Reject(RejectReason::NotInAllowList));
    }

    #[test]
    fn empty_path_rejected() {
        let pl = lists();
        let d = is_path_allowed_for_broker_open("", 0x0001, &pl);
        assert_eq!(d, Decision::Reject(RejectReason::EmptyPath));
    }

    #[test]
    fn nt_prefix_strip_works_in_full_pipeline() {
        let pl = lists();
        // Caller normally normalises before calling, but verify the
        // normaliser produces a string the matcher accepts.
        let p = normalize_nt_path(r"\??\C:\fixture\base\public.txt").unwrap();
        let d = is_path_allowed_for_broker_open(&p, 0x0001, &pl);
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn write_mask_covers_common_bits() {
        assert!(is_write_access(FILE_WRITE_DATA));
        assert!(is_write_access(FILE_APPEND_DATA));
        assert!(is_write_access(GENERIC_WRITE));
        assert!(is_write_access(DELETE));
        assert!(!is_write_access(0x0001 /* FILE_READ_DATA */));
        assert!(!is_write_access(0x80000000 /* GENERIC_READ */));
    }

    /// Phase N-2 Part B: Cygwin/MSYS2 binaries (git, bash) translate
    /// `/dev/null` → `\??\nul` for `NtCreateFile`. The reserved DOS
    /// device names allow-list short-circuits the policy check so
    /// these always succeed regardless of the user's allow lists.
    #[test]
    fn reserved_dos_devices_allowed() {
        let pl = lists();
        // `\??\nul` normalises to `nul`.
        let d = is_path_allowed_for_broker_open("nul", FILE_WRITE_DATA, &pl);
        assert_eq!(d, Decision::Allow);
        // Case-insensitive.
        let d = is_path_allowed_for_broker_open("NUL", FILE_WRITE_DATA, &pl);
        assert_eq!(d, Decision::Allow);
        // Other reserved names also covered.
        let d = is_path_allowed_for_broker_open("con", 0x0001, &pl);
        assert_eq!(d, Decision::Allow);
        // `nul.txt` and similar — Win32 ignores everything after the
        // device name in the leaf, treating the file as the device.
        let d = is_path_allowed_for_broker_open("nul.txt", 0x0001, &pl);
        assert_eq!(d, Decision::Allow);
        // Path containing `nul` as a non-leaf component is NOT a
        // device open (it's a real-FS path); should fall through to
        // the normal policy check.
        let d = is_path_allowed_for_broker_open(
            r"C:\nul\actually-a-file", 0x0001, &pl,
        );
        assert_eq!(d, Decision::Reject(RejectReason::NotInAllowList));
    }
}
