//! Broker-side filesystem policy. v1: lexical prefix match on a
//! lower-cased DOS path. Default-allow read, default-deny write.
//! The confused-deputy hardening (open-then-`GetFinalPathNameByHandle`,
//! hardlink fan-in, access-mask invariant) lands as a follow-up
//! once the brokered open mechanism is proven; until then the
//! Phase-1 ACL grants remain in place as belt-and-braces and the
//! token is the security boundary against raw-syscall bypass.

use crate::policy::Policy;

// FILE_WRITE_ATTRIBUTES (0x100) and FILE_WRITE_EA (0x10) are
// deliberately excluded — many tools request them speculatively
// (CRT stat, PDB lookup) and they don't grant data write.
const WRITE_BITS: u32 =
    0x00000002 /* FILE_WRITE_DATA */ |
    0x00000004 /* FILE_APPEND_DATA */ |
    0x00010000 /* DELETE */ |
    0x00040000 /* WRITE_DAC */ |
    0x00080000 /* WRITE_OWNER */ |
    0x40000000 /* GENERIC_WRITE */ |
    0x10000000 /* GENERIC_ALL */;

pub struct FsPolicy {
    deny_read: Vec<String>,
    allow_write: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Open with the broker's full token (filesystem paths the
    /// lockdown token can't reach).
    Allow,
    /// Open while impersonating the target's lowbox token.
    /// Device endpoints (AFD, ConDrv, …) tag themselves with the
    /// *creator*'s AppContainer at NtCreateFile time; opening
    /// them with the broker's non-AC token yields a non-AC
    /// socket that the target then can't connect on.
    AllowAsTarget,
    Deny(&'static str),
}

impl FsPolicy {
    pub fn from_policy(p: &Policy) -> Self {
        let norm = |v: &[String]| -> Vec<String> {
            v.iter().map(|s| canon_dos(s)).collect()
        };
        Self {
            deny_read: norm(&p.deny_read),
            allow_write: norm(&p.allow_write),
        }
    }

    /// `nt_path` is the broker-side path string as read from the
    /// caller's `OBJECT_ATTRIBUTES.ObjectName` (already UTF-16→UTF-8).
    pub fn evaluate(&self, nt_path: &str, desired_access: u32) -> Decision {
        let lower = canon_dos(nt_path);
        // Non-filesystem device endpoints whose driver enforces
        // its own per-IOCTL access check against the *caller*'s
        // token (so brokering the open doesn't widen the
        // boundary): AFD's connect/bind checks the lowbox
        // network capability; ConDrv attaches to the caller's
        // conhost. Everything else under \Device\ is denied —
        // brokering a named-pipe or PhysicalDrive open with the
        // broker's full token would be a straight escape. The
        // follow-up is a "try original syscall first" stub so
        // device opens the lockdown token can already do never
        // reach the broker.
        if let Some(dev) = lower.strip_prefix(r"\device\") {
            return if dev.starts_with("harddiskvolume")
                || dev.starts_with("mup")
                || dev.starts_with("lanmanredirector")
                || dev.starts_with("namedpipe\\")
                || dev.starts_with("physicaldrive")
            {
                Decision::Deny("device→fs/pipe namespace")
            } else {
                // AFD/ConDrv/CNG/KsecDD/Nsi/NetBT etc. — open
                // under the target's lowbox token so the
                // endpoint is AC-tagged and the target can use
                // it; the device driver enforces the boundary.
                Decision::AllowAsTarget
            };
        }
        if let Some(rest) = lower.strip_prefix(r"\??\") {
            if matches!(rest,
                "nul" | "con" | "conin$" | "conout$" | "aux" | "prn"
            ) {
                return Decision::Allow;
            }
            if rest.starts_with("pipe\\") || rest.starts_with("unc\\") {
                return Decision::Deny("pipe/UNC");
            }
            if rest.starts_with("mountpointmanager")
                || rest.starts_with("nsi")
            {
                return Decision::Allow;
            }
        }
        let dos = match nt_to_dos(nt_path) {
            Some(d) => d,
            None => return Decision::Deny("non-DOS namespace"),
        };
        if self.deny_read.iter().any(|d| under(&dos, d)) {
            return Decision::Deny("denyRead");
        }
        if desired_access & WRITE_BITS != 0
            && !self.allow_write.iter().any(|a| under(&dos, a))
        {
            return Decision::Deny("write outside allowWrite");
        }
        Decision::Allow
    }
}

fn under(path: &str, root: &str) -> bool {
    path == root
        || (path.starts_with(root)
            && path.as_bytes().get(root.len()).map(|&b| b == b'\\').unwrap_or(false))
}

/// Lower-case, forward→back-slash, strip trailing separators.
fn canon_dos(s: &str) -> String {
    let mut out: String = s.chars()
        .map(|c| if c == '/' { '\\' } else { c.to_ascii_lowercase() })
        .collect();
    while out.ends_with('\\') && out.len() > 3 { out.pop(); }
    out
}

/// Best-effort NT→DOS: `\??\C:\x` → `c:\x`. Returns `None` for
/// device/UNC/pipe namespaces (denied in v1).
fn nt_to_dos(nt: &str) -> Option<String> {
    let lower = canon_dos(nt);
    if let Some(rest) = lower.strip_prefix(r"\??\") {
        if rest.starts_with("unc\\") || rest.starts_with("pipe\\") {
            return None;
        }
        // `\??\C:\…` → `c:\…`
        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
            return Some(rest.to_string());
        }
        return None;
    }
    if lower.starts_with(r"\device\") || lower.starts_with(r"\\") {
        return None;
    }
    // Already DOS-shaped (rare for ntdll callers, but accept).
    if lower.len() >= 2 && lower.as_bytes()[1] == b':' {
        return Some(lower);
    }
    None
}
