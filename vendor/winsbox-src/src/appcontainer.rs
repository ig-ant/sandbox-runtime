use crate::util::{from_pwstr, pcwstr, wstr};
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::path::PathBuf;
use windows::core::PWSTR;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
    DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
};
use windows::Win32::Security::{FreeSid, PSID};

pub struct AppContainer {
    pub name: String,
    pub sid: PSID,
    pub sid_string: String,
    /// `%LOCALAPPDATA%\Packages\<name>\AC` — readable by both broker and
    /// the AC process; used for the AF_UNIX bridge sockets.
    pub folder: PathBuf,
}

/// 64-bit FNV-1a — small, fast, non-crypto. We hash a "stable key" string
/// (caller's `stableSidKey` policy field, or a fallback derived from the
/// broker install path) and embed the low-16-hex-chars in the AC profile
/// name so the resulting AC SID is reproducible across runs of the same
/// install. With a stable name, `DeriveAppContainerSidFromAppContainerName`
/// returns the same SID every run, the manifest cache file (`<sid>.json`)
/// is found, and the policy stamper short-circuits.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 16 lowercase hex chars from a 64-bit FNV-1a of `key`.
fn short_hash(key: &str) -> String {
    format!("{:016x}", fnv1a64(key.as_bytes()))
}

/// Fallback "stable key" when the caller doesn't pass one: the broker's
/// own install path. Same install → same SID; different installs (e.g.,
/// dev tree vs `npm i`'d copy) → different SIDs, which is the right
/// granularity (manifest stamps are install-scoped via path-keyed ACEs).
fn fallback_install_key() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "sbox-exec-default".to_string())
}

impl AppContainer {
    /// Back-compat shim for callers that don't care about manifest-cache
    /// stability across runs (e.g., the spike-cdylib probe). Forwards to
    /// `create_with_key(tag, None)` — i.e., uses the install-path
    /// fallback. Names from this path are stable per-install but not
    /// per-caller-policy.
    pub fn create(tag: &str) -> Result<Self> {
        Self::create_with_key(tag, None)
    }

    /// Phase G: build a deterministic AC profile name from a caller-
    /// provided key (the `stableSidKey` policy field) or the install-path
    /// fallback. Profile name shape: `srt.<tag>.<16-hex>`. Profile names
    /// are bounded at 64 chars; 4 ("srt.") + tag + 1 (".") + 16 (hash) =
    /// 21 + tag, leaving 43 chars for tag — comfortably under for the
    /// typical "ac" / "spike" / "p1x" tags we use.
    ///
    /// Concurrency note: two sboxes with the same `stableSidKey` share the
    /// AC profile (and the folder under `%LOCALAPPDATA%\Packages`). For
    /// this phase we assume single-instance per key — the create call is
    /// idempotent (handles `ERROR_ALREADY_EXISTS` by deriving the same
    /// SID), so concurrent callers won't error on profile creation, but
    /// they will trample each other's per-AC writeable state. Callers
    /// that need true isolation should pass distinct `stableSidKey`s.
    pub fn create_with_key(tag: &str, key: Option<&str>) -> Result<Self> {
        let owned_key;
        let effective_key: &str = match key {
            Some(k) => k,
            None => {
                owned_key = fallback_install_key();
                &owned_key
            }
        };
        let hash = short_hash(effective_key);
        // Profile names must be ≤64 chars, no path separators.
        let name = format!("srt.{}.{}", tag, hash);
        debug_assert!(name.len() <= 64, "AC profile name too long: {name}");
        let wname = wstr(&name);
        unsafe {
            // No pre-delete: with stable names, an extant profile is
            // exactly what we want (same SID → manifest cache hit). The
            // create call below is idempotent via the ALREADY_EXISTS arm.
            let sid = match CreateAppContainerProfile(
                pcwstr(&wname), pcwstr(&wname), pcwstr(&wname), None,
            ) {
                Ok(s) => s,
                Err(e) if e.code().0 as u32 == 0x800700B7 => {
                    DeriveAppContainerSidFromAppContainerName(pcwstr(&wname))
                        .context("derive existing AC sid")?
                }
                Err(e) => bail!("CreateAppContainerProfile({name}): {e}"),
            };
            let mut sp = PWSTR::null();
            ConvertSidToStringSidW(sid, &mut sp).context("ConvertSidToStringSidW")?;
            let sid_string = from_pwstr(sp);
            crate::util::local_free(sp.0 as *mut c_void);

            let fp = GetAppContainerFolderPath(pcwstr(&wstr(&sid_string)))
                .context("GetAppContainerFolderPath")?;
            let folder = PathBuf::from(from_pwstr(fp));
            windows::Win32::System::Com::CoTaskMemFree(Some(fp.0 as *const c_void));
            std::fs::create_dir_all(&folder).ok();

            Ok(Self { name, sid, sid_string, folder })
        }
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        unsafe {
            if !self.sid.0.is_null() { FreeSid(self.sid); }
            // Phase G cleanup: with stable SIDs, the AC writeable folder
            // accumulates state across runs (cygwin/MSYS2 deposit AF_UNIX
            // sockets, fork-sync sections, etc. before we tear them down
            // ourselves). Wipe the folder explicitly so a fresh launch
            // doesn't see stale leftovers. `DeleteAppContainerProfile`
            // below also clears the folder, but we belt-and-braces it
            // because docs are vague about partial-cleanup behavior on
            // open handles. Both calls are best-effort: failures here
            // are not fatal — the next run's AF_UNIX bind will overwrite,
            // and the SID stays the same regardless.
            let _ = std::fs::remove_dir_all(&self.folder);
            let _ = DeleteAppContainerProfile(pcwstr(&wstr(&self.name)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same key → same hash → same profile name. This is the load-bearing
    /// property for Phase G's manifest-cache-hit goal: across runs of the
    /// same install (same broker exe path), the AC profile name is byte-
    /// identical, so `DeriveAppContainerSidFromAppContainerName` yields
    /// the same SID, so the `<sid>.json` manifest file matches.
    #[test]
    fn deterministic_short_hash() {
        let a = short_hash("hello");
        let b = short_hash("hello");
        assert_eq!(a, b, "FNV-1a should be deterministic");
        assert_eq!(a.len(), 16, "short hash must be 16 hex chars");
        assert!(
            a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "short hash must be lowercase hex: got {a}"
        );
    }

    #[test]
    fn distinct_keys_distinct_hashes() {
        // Not a hard cryptographic guarantee, but FNV-1a is good enough
        // that two semantically-different keys won't collide on a 64-bit
        // hash in practice. Catches accidental "always returns 0".
        assert_ne!(short_hash("install-a"), short_hash("install-b"));
        assert_ne!(short_hash(""), short_hash("x"));
    }

    /// The full profile name fits Windows' 64-char AC-name limit even
    /// when the tag is at the upper end of what we use.
    #[test]
    fn profile_name_under_64_chars() {
        let hash = short_hash("any-key");
        // Longest tag we use today is ~6 chars ("spike"). Sanity-test
        // a generous 30-char tag — anything longer would be a caller
        // bug (debug_assert in create_with_key catches it).
        let tag = "a".repeat(30);
        let name = format!("srt.{}.{}", tag, hash);
        assert!(
            name.len() <= 64,
            "profile name {} chars: {}", name.len(), name,
        );
    }
}
