//! Custom Win32 ACL stamper. Replaces the icacls-shelling `acl.rs` with
//! direct `GetNamedSecurityInfoW` / `SetNamedSecurityInfoW` /
//! `TreeSetNamedSecurityInfoW` calls plus an idempotency probe so re-applying
//! an unchanged policy is a near no-op.
//!
//! See `cheeky-jingling-stream.md` §"Components > 1. acl_stamper.rs" for the
//! full design contract; the load-bearing rules are:
//!
//! - For each `allow_*` path: emit an `(OI)(CI) ALLOW` ACE for the AC SID.
//! - For each `deny_*` path P: only emit a DENY ACE if some ancestor is in
//!   `allow_*`. Otherwise the path is already closed (no AC ACE → no access)
//!   and a DENY would just bloat the ACL.
//! - Skip the per-root walk if `GetNamedSecurityInfoW` already shows our exact
//!   ACE on the root *and* a probe leaf inherits it.

use anyhow::{anyhow, bail, Result};
use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    BuildExplicitAccessWithNameW, BuildTrusteeWithSidW, ConvertSidToStringSidW,
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    TreeSetNamedSecurityInfoW, ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, PROG_INVOKE_SETTING, SE_FILE_OBJECT, TREE_SEC_INFO_SET,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    EqualSid, GetAce, ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;

use crate::util::{from_pwstr, pcwstr, wstr};

// AceType byte values (per ntifs.h). The `windows` crate doesn't expose them
// as constants — they're documented as part of the ACE wire format.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;

/// Phase N-0: `WINSBOX_STAMP_VERBOSE=1` opt-in to per-path stamp
/// outcome logging. Cached after first read so the env-var lookup
/// doesn't repeat for every path/SID pair.
fn stamp_verbose() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("WINSBOX_STAMP_VERBOSE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

/// Phase N-0: emit one `[acl_stamper] verbose:` line per (path, SID,
/// outcome) tuple when `WINSBOX_STAMP_VERBOSE=1`. No-op otherwise.
/// Outcome strings are stable so log scrapers can grep them.
fn log_stamp_verbose(path: &Path, sid_label: &str, outcome: &str) {
    if !stamp_verbose() { return; }
    eprintln!(
        "[acl_stamper] verbose: path={:?} sid={sid_label} outcome={outcome}",
        path,
    );
}

/// `(OI)(CI)` — children inherit the ACE; both files (OI) and subdirs (CI).
fn oici() -> ACE_FLAGS {
    ACE_FLAGS(OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0)
}

/// Mask we use for read access. `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` is
/// what icacls calls `RX`. We keep both: read-only without execute makes
/// loading DLLs / executing scripts fail and AC-side tools choke.
fn read_mask() -> u32 {
    FILE_GENERIC_READ.0 | windows::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE.0
}

/// Mask for write access. Plain `FILE_GENERIC_WRITE` — granting "modify" in
/// icacls terms requires also handing out delete; for now we match the
/// previous `acl.rs` semantics where allow_write was `M` → we'll use
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE`
/// to mirror the M shape that worked under Phase 2b.
fn write_mask() -> u32 {
    use windows::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    const DELETE: u32 = 0x0001_0000;
    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE
}

/// Policy stamp request. All fields are caller-controlled. `exclude` is the
/// path-prefix exclude list documented in the plan: empty by default, used
/// only for special cases (e.g. excluding a path that the recursive walk
/// would otherwise stamp transitively).
#[derive(Debug, Clone, Default)]
pub struct PolicyStamp {
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_write: Vec<PathBuf>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StampStats {
    pub roots_stamped: usize,
    pub roots_skipped_idempotent: usize,
    /// Phase E-5a: an `allow_*` path was skipped because the directory's
    /// existing DACL already grants `ALL APPLICATION PACKAGES` (S-1-15-2-1)
    /// at least the access we'd add. This is the common case for system
    /// tool installs (`C:\Program Files\Git`, `C:\Windows`, ...) which
    /// already inherit a `(OI)(CI)` ALLOW for AC packages and which the
    /// broker (a non-admin user) typically *cannot* re-stamp anyway.
    pub roots_skipped_already_accessible: usize,
    /// Phase E-5a: a `TreeSetNamedSecurityInfoW` call returned
    /// `ERROR_ACCESS_DENIED` (e.g., admin-protected dir) but we
    /// continued instead of aborting the whole `apply()`.
    pub roots_soft_failed_access_denied: usize,
    /// A path was skipped because it doesn't exist on disk (or the
    /// underlying `GetNamedSecurityInfoW` failed for any non-AccessDenied
    /// reason — e.g. `Y:\NUL`/`Y:\CON` which `getDefaultWritePaths`
    /// emits as DOS-device aliases). Treated as non-fatal so a single
    /// malformed allow_*/deny_* entry doesn't abort the whole stamp pass
    /// and silently leave the AC token with NO ACL enforcement at all.
    pub roots_soft_failed_other: usize,
    pub denies_emitted: usize,
    pub denies_omitted_unnecessary: usize,
    pub elapsed_ms: u128,
}

/// RAII wrapper that `LocalFree`s a SID returned from
/// `psid_from_string` on drop. Used during the well-known-SID DENY
/// pass to avoid leaking each `S-1-*` SID we allocate per deny path.
struct SidGuard(PSID);
impl Drop for SidGuard {
    fn drop(&mut self) {
        free_psid(self.0);
    }
}

/// One leaf record we emit. `_kind` is retained for human-readable error
/// messages even though the apply path doesn't otherwise inspect it.
#[derive(Debug, Clone)]
struct StampOp {
    path: PathBuf,
    #[allow(dead_code)]
    kind: &'static str,
    mask: u32,
    mode: ACCESS_MODE,
}

/// Outcome of a single `apply_one` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOutcome {
    /// `TreeSetNamedSecurityInfoW` succeeded.
    Stamped,
    /// Idempotency probe matched — root already has our ACE and a
    /// probe leaf inherits it.
    SkippedIdempotent,
    /// Phase E-5a: `TreeSetNamedSecurityInfoW` returned
    /// `ERROR_ACCESS_DENIED`. Caller should log + continue.
    SoftFailedAccessDenied,
}

/// Well-known SID for `ALL APPLICATION PACKAGES`. Standard tool installs
/// like `C:\Program Files\Git`, `C:\Windows`, etc. already carry an
/// `(OI)(CI)` ALLOW ACE for this SID inherited from above, which is
/// enough for the AC's lockdown token to read+execute. When that's
/// already true on an `allow_*` path, our extra stamp would be redundant
/// — and admin-protected dirs we can't write to anyway.
const ALL_APP_PACKAGES_SID: &str = "S-1-15-2-1";

/// Well-known "restricted code" SID. The broker's USER_LIMITED lockdown
/// token is a **restricted** token whose restricting-SID list is
/// `[Everyone, AuthUsers, Users, Logon, RESTRICTED]` (see
/// `token.rs::make_lockdown_with`). On a restricted token every access
/// check has *two* passes: the normal one against the token's groups
/// (where the AC SID lives — our explicit ALLOW grants pass this), AND
/// a second one against the restricting-SID set. Both must succeed.
///
/// User-tree paths under `%TEMP%` only inherit `Everyone:RX` / `Users:RX`
/// (read+execute, no write); the user's own SID is not in the restricting
/// list. So a write to an `allow_write` path under `%TEMP%` passes the
/// AC-SID check but fails the restricting-SID check — manifesting as
/// `Access is denied` even though icacls shows the AC's `(M)` ACE.
///
/// Granting `RESTRICTED` (`S-1-5-12`) at the same mask as the AC SID
/// lets the restricting-SID pass succeed for any path we explicitly
/// stamp. RESTRICTED isn't on any normal user/group token, so this ALLOW
/// is invisible to anything other than restricted tokens — i.e., it
/// doesn't widen access for the broker, regular processes, or the
/// non-AC user.
const RESTRICTED_CODE_SID: &str = "S-1-5-12";

impl PolicyStamp {
    /// Apply against an AC SID. Idempotent: any root whose existing DACL
    /// already contains our exact ACE *and* whose probe leaf inherits it
    /// is skipped.
    pub fn apply(&self, ac_sid: PSID) -> Result<StampStats> {
        let t0 = Instant::now();
        let mut stats = StampStats::default();

        // Skip excluded prefixes. Caller may use this to opt out of stamping
        // particular subtrees (the plan default is empty).
        let excluded = |p: &Path| -> bool {
            let s = p.to_string_lossy();
            self.exclude.iter().any(|e| s.starts_with(e.as_str()))
        };

        // 1. ALLOW stamps.
        //
        // Phase E-5a: probe-skip rule applies *only* to ALLOW stamps.
        // If the root's existing DACL already grants ALL APPLICATION
        // PACKAGES at least the mask we'd add, our stamp is redundant
        // and we skip it. DENY paths below skip this probe — even
        // an existing ALL-APP-PACKAGES ALLOW means we DO need an
        // explicit DENY to override.
        //
        // Phase L follow-up: the broker's USER_LIMITED lockdown token is
        // a *restricted* token (`token.rs::make_lockdown_with`) whose
        // restricting-SID list = `[Everyone, AuthUsers, Users, Logon,
        // RESTRICTED]`. Restricted-token access checks require BOTH the
        // normal-SID pass *and* the restricting-SID pass to succeed.
        // The AC SID's ALLOW grant satisfies the normal-SID pass — but
        // fixture paths under `%TEMP%` only inherit `Everyone:RX` /
        // `Users:RX`, so the restricting-SID pass *fails* on any write
        // (and on reads to dirs that don't already have inherited RX
        // for those well-known groups). Stamping `RESTRICTED` (S-1-5-12)
        // alongside the AC SID's stamp gives the restricting-SID pass a
        // matching grant, unblocking writes/reads on user-tree paths.
        // RESTRICTED isn't on any normal token, so granting it doesn't
        // widen access for non-restricted callers (broker, etc.).
        let restricted_sid_owned = psid_from_string(RESTRICTED_CODE_SID).ok();
        let _restricted_guard = restricted_sid_owned.map(SidGuard);
        let restricted_sid = restricted_sid_owned.unwrap_or(PSID::default());

        let apply_allow = |p: &Path, kind: &'static str, mask: u32, stats: &mut StampStats| {
            // Helper closure: stamp `(p, sid, mask, GRANT)` and bump
            // stats. Used twice per allow path — once for the AC SID and
            // once for the RESTRICTED SID — so both passes of the
            // restricted-token access check succeed.
            let mut do_stamp = |sid: PSID, sid_label: &str| {
                let op = StampOp { path: p.to_path_buf(), kind, mask, mode: GRANT_ACCESS };
                match apply_one(&op, sid) {
                    Ok(ApplyOutcome::Stamped) => {
                        stats.roots_stamped += 1;
                        log_stamp_verbose(p, sid_label, "stamped");
                    }
                    Ok(ApplyOutcome::SkippedIdempotent) => {
                        stats.roots_skipped_idempotent += 1;
                        log_stamp_verbose(p, sid_label, "idempotent");
                    }
                    Ok(ApplyOutcome::SoftFailedAccessDenied) => {
                        stats.roots_soft_failed_access_denied += 1;
                        log_stamp_verbose(p, sid_label, "soft-failed-access-denied");
                    }
                    Err(e) => {
                        eprintln!(
                            "[acl_stamper] WARN apply_one({kind}, sid={sid_label}, {:?}) \
                             failed: {e:#}; continuing",
                            p,
                        );
                        stats.roots_soft_failed_other += 1;
                        log_stamp_verbose(
                            p, sid_label,
                            &format!("soft-failed-other err={:?}", format!("{e:#}")),
                        );
                    }
                }
            };
            do_stamp(ac_sid, "ac");
            if !restricted_sid.0.is_null() {
                do_stamp(restricted_sid, "restricted");
            }
        };

        for p in &self.allow_read {
            if excluded(p) {
                continue;
            }
            if existing_ace_grants_all_app_packages(p, read_mask()).unwrap_or(false) {
                eprintln!(
                    "[acl_stamper] skip {:?}: already accessible to ALL APP PACKAGES (allow_read)",
                    p,
                );
                stats.roots_skipped_already_accessible += 1;
                log_stamp_verbose(p, "ac", "ac-accessible");
                continue;
            }
            apply_allow(p, "allow_read", read_mask(), &mut stats);
        }
        for p in &self.allow_write {
            if excluded(p) {
                continue;
            }
            if existing_ace_grants_all_app_packages(p, write_mask()).unwrap_or(false) {
                eprintln!(
                    "[acl_stamper] skip {:?}: already accessible to ALL APP PACKAGES (allow_write)",
                    p,
                );
                stats.roots_skipped_already_accessible += 1;
                log_stamp_verbose(p, "ac", "ac-accessible");
                continue;
            }
            apply_allow(p, "allow_write", write_mask(), &mut stats);
        }

        // 2. DENY stamps — only when nested under an ALLOW.
        let allow_set: HashSet<PathBuf> = self
            .allow_read
            .iter()
            .chain(self.allow_write.iter())
            .map(|p| canonical_or_self(p))
            .collect();

        // Phase E-3: well-known SIDs whose inherited ALLOW ACEs would
        // otherwise let the AC's USER_LOCKDOWN-token access-check pass on
        // a deny path. Bisection commits 7847a77/b0524ac document why
        // USER_LOCKDOWN keeps `Everyone` enabled (WFP intra-AC loopback
        // exemption); without explicit DENY ACEs for these SIDs the
        // raw-syscall path wins on `Everyone:R`/`Users:R` ancestors.
        //
        // We emit DENY ACEs *in addition to* the AC SID's DENY, scoped
        // strictly to user-specified deny paths. System paths are never
        // auto-denied here — the policy author chose this path explicitly.
        const DENY_INHERITED_SIDS: &[&str] = &[
            "S-1-1-0",      // Everyone
            "S-1-5-11",     // Authenticated Users
            "S-1-5-32-545", // BUILTIN\Users
        ];

        for (paths, kind, mask) in [
            (&self.deny_read, "deny_read", read_mask()),
            (&self.deny_write, "deny_write", write_mask()),
        ] {
            for p in paths {
                if excluded(p) {
                    continue;
                }
                if !nested_under_any(p, &allow_set) {
                    stats.denies_omitted_unnecessary += 1;
                    continue;
                }
                let op = StampOp {
                    path: p.clone(),
                    kind,
                    mask,
                    mode: DENY_ACCESS,
                };
                // Phase E-5a: denies do NOT probe-skip on ALL APP
                // PACKAGES — an existing ALLOW for that SID is exactly
                // why we need the DENY. Only soft-fail on access denied
                // is shared with allow paths; here it's a real concern
                // (we'd be silently failing to enforce a deny) so we
                // log at error severity but still continue so a single
                // admin-protected deny path doesn't tank the whole
                // policy apply.
                match apply_one(&op, ac_sid) {
                    Ok(ApplyOutcome::Stamped) => {
                        stats.roots_stamped += 1;
                        stats.denies_emitted += 1;
                        log_stamp_verbose(p, "ac", "stamped");
                    }
                    Ok(ApplyOutcome::SkippedIdempotent) => {
                        stats.roots_skipped_idempotent += 1;
                        log_stamp_verbose(p, "ac", "idempotent");
                    }
                    Ok(ApplyOutcome::SoftFailedAccessDenied) => {
                        stats.roots_soft_failed_access_denied += 1;
                        eprintln!(
                            "[acl_stamper] ERROR: deny stamp on {:?} \
                             returned ERROR_ACCESS_DENIED — deny may not \
                             be enforced for AC SID. Run broker as admin \
                             or reorganize policy to avoid stamping under \
                             admin-protected roots.",
                            p,
                        );
                        log_stamp_verbose(p, "ac", "soft-failed-access-denied");
                    }
                    Err(e) => {
                        eprintln!(
                            "[acl_stamper] ERROR: deny stamp on {:?} failed: \
                             {e:#}; deny will NOT be enforced for AC SID on \
                             this path",
                            p,
                        );
                        stats.roots_soft_failed_other += 1;
                        log_stamp_verbose(
                            p, "ac",
                            &format!("soft-failed-other err={:?}", format!("{e:#}")),
                        );
                    }
                }
                // Phase E-3: also DENY for the well-known inherited
                // ALLOW SIDs the lockdown token keeps enabled. Each
                // SID is an independent stamp op against the same
                // path, with the same mask. Idempotency probe handles
                // the re-apply case per-SID.
                // Apply all 3 well-known DENYs in one batched
                // SetEntriesInAclW + TreeSetNamedSecurityInfoW pass.
                // Per-SID `apply_one` would deny our own access after
                // the first iteration (Everyone DENY locks even the
                // broker out of further SetSecurity calls on the
                // subtree, since the broker-as-user is in `Everyone`).
                // Batched also halves the kernel walk work.
                let extra_sids: Vec<(String, PSID)> = DENY_INHERITED_SIDS.iter()
                    .filter_map(|s| psid_from_string(s).ok().map(|sid| (s.to_string(), sid)))
                    .collect();
                let guards: Vec<SidGuard> =
                    extra_sids.iter().map(|(_, s)| SidGuard(*s)).collect();
                let pending: Vec<&PSID> =
                    extra_sids.iter().map(|(_, s)| s)
                        .filter(|s| {
                            !root_already_stamped(
                                p, **s, mask, ACCESS_DENIED_ACE_TYPE,
                            ).unwrap_or(false)
                        })
                        .collect();
                let already = extra_sids.len() - pending.len();
                stats.roots_skipped_idempotent += already;
                if !pending.is_empty() {
                    match apply_batched_denies(p, mask, &pending) {
                        Ok(_) => {
                            stats.roots_stamped += pending.len();
                            stats.denies_emitted += pending.len();
                        }
                        Err(e) => {
                            eprintln!(
                                "[acl_stamper] batched well-known DENY on {:?}: {e:#}",
                                p,
                            );
                        }
                    }
                }
                drop(guards);
            }
        }

        stats.elapsed_ms = t0.elapsed().as_millis();
        Ok(stats)
    }

    /// Remove every ACE for `ac_sid` from each root we touched. We don't
    /// distinguish "ACEs we added" vs "pre-existing ACEs for this SID":
    /// since the SID is the per-instance AC package SID and we created it,
    /// any ACE for it is ours. This matches the previous `acl.rs` behavior.
    ///
    /// Phase E-3: also removes the explicit DENY ACEs we added against
    /// the well-known SIDs (Everyone, AuthUsers, Users) on deny paths.
    /// Scoped to DENY-type ACEs only — pre-existing ALLOW ACEs for those
    /// SIDs (which we never touched) are preserved.
    pub fn revert(&self, ac_sid: PSID) -> Result<()> {
        let mut roots: Vec<PathBuf> = self
            .allow_read
            .iter()
            .chain(self.allow_write.iter())
            .chain(self.deny_read.iter())
            .chain(self.deny_write.iter())
            .cloned()
            .collect();
        roots.sort();
        roots.dedup();

        for p in &roots {
            let _ = remove_aces_for_sid(p, ac_sid);
        }

        // Phase L follow-up cleanup: strip the explicit ALLOW ACEs we
        // added against `RESTRICTED` (S-1-5-12) on allow paths so the
        // grant doesn't outlive the AC. Scoped to ALLOW-type ACEs only
        // so any pre-existing DENY for the same SID (unlikely but
        // possible) stays put. Best-effort like the AC-SID strip above.
        let allow_paths: Vec<&PathBuf> =
            self.allow_read.iter().chain(self.allow_write.iter()).collect();
        if !allow_paths.is_empty() {
            if let Ok(restricted_sid) = psid_from_string(RESTRICTED_CODE_SID) {
                let _g = SidGuard(restricted_sid);
                for p in allow_paths {
                    let _ = remove_aces_for_sid_typed(
                        p, restricted_sid, Some(ACCESS_ALLOWED_ACE_TYPE),
                    );
                }
            }
        }

        // Phase E-3 cleanup: strip the well-known-SID DENY ACEs we added
        // on deny paths. Use the deny-only variant so inherited ALLOW
        // ACEs for the same SID stay put.
        const DENY_INHERITED_SIDS: &[&str] = &[
            "S-1-1-0", "S-1-5-11", "S-1-5-32-545",
        ];
        let deny_paths: Vec<&PathBuf> =
            self.deny_read.iter().chain(self.deny_write.iter()).collect();
        for p in deny_paths {
            for s in DENY_INHERITED_SIDS {
                let sid = match psid_from_string(s) {
                    Ok(sid) => sid,
                    Err(_) => continue,
                };
                let _g = SidGuard(sid);
                let _ = remove_aces_for_sid_typed(p, sid, Some(ACCESS_DENIED_ACE_TYPE));
            }
        }
        Ok(())
    }
}

/// Batch-apply DENY ACEs for multiple SIDs in one
/// SetEntriesInAclW + TreeSetNamedSecurityInfoW pass. Used by the
/// Phase E-3 well-known-SID DENY pass: applying Everyone-DENY first
/// then trying to add Users-DENY would lock the broker (running as
/// the user, who is in `Everyone`) out of the subsequent
/// TreeSetNamedSecurityInfoW. Doing them all in one ACL write avoids
/// the chicken-and-egg.
fn apply_batched_denies(path: &Path, mask: u32, sids: &[&PSID]) -> Result<()> {
    if sids.is_empty() {
        return Ok(());
    }
    let path_w = wstr(&path.to_string_lossy());

    // Build one EXPLICIT_ACCESS_W per SID. All DENY, all (OI)(CI), same mask.
    let mut eas: Vec<EXPLICIT_ACCESS_W> = Vec::with_capacity(sids.len());
    for s in sids {
        let mut ea = EXPLICIT_ACCESS_W::default();
        unsafe {
            BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, **s);
            BuildExplicitAccessWithNameW(
                &mut ea as *mut EXPLICIT_ACCESS_W,
                PCWSTR::null(),
                mask,
                DENY_ACCESS,
                oici(),
            );
            // Re-bind the trustee — BuildExplicitAccessWithNameW
            // overwrites it with a name-based trustee referencing the
            // null name we just passed.
            BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, **s);
        }
        eas.push(ea);
    }

    let (mut existing_acl_ptr, sd_ptr) = unsafe { fetch_dacl(&path_w)? };
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            Some(eas.as_slice()),
            Some(existing_acl_ptr as *const ACL),
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        if !sd_ptr.is_null() {
            unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
        }
        bail!("SetEntriesInAclW (batch DENY) failed: {:?}", rc);
    }

    let rc = unsafe {
        TreeSetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
            TREE_SEC_INFO_SET,
            None,
            PROG_INVOKE_SETTING(0),
            None,
        )
    };
    if !new_acl.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(new_acl as *mut c_void)); }
    }
    if !sd_ptr.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
    }
    let _ = &mut existing_acl_ptr;
    if rc != ERROR_SUCCESS {
        bail!(
            "TreeSetNamedSecurityInfoW({:?}) (batch DENY) failed: {:?}",
            path, rc,
        );
    }
    Ok(())
}

/// Apply a single stamp operation.
///
/// Returns:
/// - `ApplyOutcome::Stamped` — `TreeSetNamedSecurityInfoW` succeeded.
/// - `ApplyOutcome::SkippedIdempotent` — root + leaf already have the ACE.
/// - `ApplyOutcome::SoftFailedAccessDenied` — Phase E-5a: the
///   `TreeSetNamedSecurityInfoW` call returned `ERROR_ACCESS_DENIED`
///   (e.g. broker is non-admin and the path is under
///   `C:\Program Files`). Caller decides whether that's tolerable
///   (allow_*: yes, the path may already be AC-readable via
///   ALL APPLICATION PACKAGES; deny_*: log loudly but keep going).
fn apply_one(op: &StampOp, ac_sid: PSID) -> Result<ApplyOutcome> {
    let want_ace_type = match op.mode {
        m if m == GRANT_ACCESS => ACCESS_ALLOWED_ACE_TYPE,
        m if m == DENY_ACCESS => ACCESS_DENIED_ACE_TYPE,
        _ => bail!("unsupported access mode {:?}", op.mode),
    };

    if root_already_stamped(&op.path, ac_sid, op.mask, want_ace_type)?
        && probe_leaf_inherits(&op.path, ac_sid, op.mask, want_ace_type)?
    {
        return Ok(ApplyOutcome::SkippedIdempotent);
    }

    let path_w = wstr(&op.path.to_string_lossy());

    // Build EXPLICIT_ACCESS_W with the AC SID as trustee.
    let mut ea = EXPLICIT_ACCESS_W::default();
    unsafe {
        BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, ac_sid);
        // BuildExplicitAccessWithNameW expects a name pointer; we pre-built
        // the trustee with a SID, but the helper still wants to populate the
        // EA struct (mode + permissions + inheritance). Calling it with a
        // null name is safe — the trustee's SID is preserved.
        BuildExplicitAccessWithNameW(
            &mut ea as *mut EXPLICIT_ACCESS_W,
            PCWSTR::null(),
            op.mask,
            op.mode,
            oici(),
        );
        // BuildExplicitAccessWithNameW overwrites the trustee with one that
        // uses TRUSTEE_IS_NAME pointing at the (null) name. Re-bind to the
        // SID we actually want.
        BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, ac_sid);
    }

    // Read existing DACL, merge our ACE in, write back.
    let (mut existing_acl_ptr, sd_ptr) = unsafe { fetch_dacl(&path_w)? };
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            Some(std::slice::from_ref(&ea)),
            Some(existing_acl_ptr as *const ACL),
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        if !sd_ptr.is_null() {
            unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
        }
        bail!("SetEntriesInAclW failed: {:?}", rc);
    }

    // TreeSetNamedSecurityInfoW propagates inheritance kernel-side. This is
    // the meat of the stamper — same call icacls makes underneath.
    let rc = unsafe {
        TreeSetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
            TREE_SEC_INFO_SET,
            None,
            PROG_INVOKE_SETTING(0),
            None,
        )
    };

    // Free buffers regardless of success.
    if !new_acl.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(new_acl as *mut c_void)); }
    }
    if !sd_ptr.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sd_ptr)); }
    }
    let _ = &mut existing_acl_ptr;

    if rc == ERROR_ACCESS_DENIED {
        // Phase E-5a: admin-protected directory — broker isn't elevated
        // and the kernel won't let us rewrite the DACL. The path may
        // still be AC-accessible via inherited ALL APPLICATION PACKAGES
        // ACEs (verified empirically on `C:\Program Files\Git`), so the
        // caller treats this as a warning rather than a fatal error.
        eprintln!(
            "[acl_stamper] WARN TreeSetNamedSecurityInfoW({:?}) \
             returned ERROR_ACCESS_DENIED — admin-protected dir, \
             skipping (path may already be AC-readable via inherited \
             ALL APPLICATION PACKAGES; verify with `icacls`)",
            op.path,
        );
        return Ok(ApplyOutcome::SoftFailedAccessDenied);
    }
    if rc != ERROR_SUCCESS {
        bail!(
            "TreeSetNamedSecurityInfoW({:?}) failed: {:?}",
            op.path,
            rc
        );
    }

    Ok(ApplyOutcome::Stamped)
}

unsafe fn fetch_dacl(path_w: &[u16]) -> Result<(*mut ACL, *mut c_void)> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let rc = GetNamedSecurityInfoW(
        pcwstr(path_w),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(&mut dacl as *mut *mut ACL),
        None,
        &mut sd,
    );
    if rc != ERROR_SUCCESS {
        bail!("GetNamedSecurityInfoW failed: {:?}", rc);
    }
    Ok((dacl, sd.0))
}

/// Phase E-5a: check whether the root's DACL already has an `(OI)(CI)`
/// (or inherited) ALLOW ACE for `ALL APPLICATION PACKAGES` whose mask
/// covers `requested_mask`. When this is true for an `allow_*` path,
/// the AC token can already access the subtree via inheritance and our
/// stamp would be redundant — and importantly we're often unable to
/// write the stamp anyway (admin-protected dirs like `C:\Program Files`).
///
/// Lookup is best-effort: any failure (path doesn't exist,
/// `GetNamedSecurityInfoW` fails, no DACL) returns `Ok(false)` so the
/// caller falls through to the normal stamp path.
fn existing_ace_grants_all_app_packages(path: &Path, requested_mask: u32) -> Result<bool> {
    let path_w = wstr(&path.to_string_lossy());
    let app_pkgs_sid = match psid_from_string(ALL_APP_PACKAGES_SID) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let _g = SidGuard(app_pkgs_sid);

    unsafe {
        let (dacl_ptr, sd_ptr) = match fetch_dacl(&path_w) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        let result =
            ace_for_sid_grants(dacl_ptr, app_pkgs_sid, requested_mask, ACCESS_ALLOWED_ACE_TYPE);
        if !sd_ptr.is_null() {
            let _ = LocalFree(HLOCAL(sd_ptr));
        }
        Ok(result)
    }
}

/// Returns true if the DACL contains any ALLOW ACE for `target_sid`
/// whose access mask covers the requested rights, considering both
/// specific (`FILE_*`) and generic (`GENERIC_*`) bits.
///
/// For the Phase E-5a probe-skip we only care about the *effective*
/// access for AC packages — we don't need the ACE to be `(OI)(CI)`
/// vs. inherited vs. on the dir itself: the tool-install pattern
/// (e.g. `C:\Program Files\Git`) typically has *both* a non-inherit
/// `(RX)` ACE on the dir for the dir itself and a `(OI)(CI)(IO)(GR,GE)`
/// for children. Either presence is enough to indicate the AC token
/// has read+execute access on this subtree.
///
/// We accept generic rights (`GENERIC_READ | GENERIC_EXECUTE`) as a
/// proxy for the equivalent `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`
/// — Windows expands them at access-check time. Same for write/all.
unsafe fn ace_for_sid_grants(
    dacl: *const ACL, target_sid: PSID, requested_mask: u32, ace_type: u8,
) -> bool {
    if dacl.is_null() || target_sid.0.is_null() {
        return false;
    }
    let count = (*dacl).AceCount as u32;
    // Generic rights bits — `GenericMapping` for files maps:
    //   GENERIC_READ    (0x80000000) → FILE_GENERIC_READ
    //   GENERIC_WRITE   (0x40000000) → FILE_GENERIC_WRITE
    //   GENERIC_EXECUTE (0x20000000) → FILE_GENERIC_EXECUTE
    //   GENERIC_ALL     (0x10000000) → FILE_ALL_ACCESS
    use windows::Win32::Storage::FileSystem::{
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    let expand = |m: u32| -> u32 {
        let mut out = m & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        if m & GENERIC_READ != 0 { out |= FILE_GENERIC_READ.0; }
        if m & GENERIC_WRITE != 0 { out |= FILE_GENERIC_WRITE.0; }
        if m & GENERIC_EXECUTE != 0 { out |= FILE_GENERIC_EXECUTE.0; }
        if m & GENERIC_ALL != 0 {
            out |= FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0;
        }
        out
    };

    for i in 0..count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
            continue;
        }
        let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
        if header.AceType != ace_type {
            continue;
        }
        // Skip Inherit-Only ACEs when checking the DIRECTORY ITSELF —
        // those only apply to children. But for Phase E-5a we want to
        // know if either the dir or its inheritable children grants
        // access; we accept any ACE flag combination as long as the
        // mask covers what we need. The caller (probe-skip) uses this
        // as a heuristic, not a guarantee.
        let mask_ptr = (ace as *const u8)
            .add(std::mem::size_of::<windows::Win32::Security::ACE_HEADER>())
            as *const u32;
        let ace_mask = expand(*mask_ptr);
        if ace_mask & requested_mask != requested_mask {
            continue;
        }
        let sid_ptr = mask_ptr.add(1) as *const c_void;
        let candidate = PSID(sid_ptr as *mut c_void);
        if EqualSid(candidate, target_sid).is_ok() {
            return true;
        }
    }
    false
}

/// Returns true if the root's DACL already has an ACE matching (SID, mask,
/// AceType, OI|CI). Doesn't check sub-flags beyond the inheritance bits.
fn root_already_stamped(path: &Path, ac_sid: PSID, mask: u32, ace_type: u8) -> Result<bool> {
    let path_w = wstr(&path.to_string_lossy());
    unsafe {
        let (dacl_ptr, sd_ptr) = match fetch_dacl(&path_w) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };
        let result = ace_matches(dacl_ptr, ac_sid, mask, ace_type, AceCheck::Root);
        if !sd_ptr.is_null() {
            let _ = LocalFree(HLOCAL(sd_ptr));
        }
        Ok(result)
    }
}

/// Variant of the ACE check.
#[derive(Copy, Clone)]
enum AceCheck {
    /// Looking for our explicit `(OI)(CI)` ACE on a root: must have both
    /// inherit bits set. Used to detect "is the root already stamped?".
    Root,
    /// Looking for an ACE inherited onto a leaf — the kernel strips OI/CI
    /// when the ACE applies to the file itself and replaces it with the
    /// `INHERITED_ACE` flag. Used by the probe-leaf path.
    Leaf,
}

unsafe fn ace_matches(
    dacl: *const ACL,
    ac_sid: PSID,
    mask: u32,
    ace_type: u8,
    mode: AceCheck,
) -> bool {
    if dacl.is_null() || ac_sid.0.is_null() {
        return false;
    }
    let count = (*dacl).AceCount as u32;
    const INHERITED_ACE: u8 = 0x10;
    for i in 0..count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
            continue;
        }
        let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
        if header.AceType != ace_type {
            continue;
        }
        match mode {
            AceCheck::Root => {
                let want = OBJECT_INHERIT_ACE.0 as u8 | CONTAINER_INHERIT_ACE.0 as u8;
                if header.AceFlags & want != want {
                    continue;
                }
            }
            AceCheck::Leaf => {
                // On a leaf the inherited ACE typically has just
                // INHERITED_ACE; on a sub-directory it may also carry the
                // OI/CI bits forward. Either is acceptable as long as the
                // ACE was inherited from us.
                if header.AceFlags & INHERITED_ACE == 0 {
                    continue;
                }
            }
        }
        let mask_ptr = (ace as *const u8).add(std::mem::size_of::<windows::Win32::Security::ACE_HEADER>())
            as *const u32;
        if *mask_ptr != mask {
            continue;
        }
        let sid_ptr = mask_ptr.add(1) as *const c_void;
        let candidate = PSID(sid_ptr as *mut c_void);
        if EqualSid(candidate, ac_sid).is_ok() {
            return true;
        }
    }
    false
}

/// Touch a tempfile under `root` and check whether its ACL has an ACE for
/// `ac_sid` with the right mask and type. Used to confirm inheritance is in
/// fact propagating. Returns false on any I/O error — we'd rather force a
/// stamp than skip when uncertain.
fn probe_leaf_inherits(root: &Path, ac_sid: PSID, mask: u32, ace_type: u8) -> Result<bool> {
    if !root.is_dir() {
        // For file roots, the root itself IS the leaf. Already verified above.
        return Ok(true);
    }
    let unique = format!(
        ".sbox-stamp-probe-{}-{}",
        std::process::id(),
        next_probe_counter()
    );
    let probe = root.join(&unique);
    if std::fs::write(&probe, b"").is_err() {
        // Can't write a probe — assume the inheritance is fine. Re-stamping
        // would also fail.
        return Ok(true);
    }
    let path_w = wstr(&probe.to_string_lossy());
    let result = unsafe {
        match fetch_dacl(&path_w) {
            Ok((dacl, sd)) => {
                let m = ace_matches(dacl, ac_sid, mask, ace_type, AceCheck::Leaf);
                if !sd.is_null() {
                    let _ = LocalFree(HLOCAL(sd));
                }
                m
            }
            Err(_) => false,
        }
    };
    let _ = std::fs::remove_file(&probe);
    Ok(result)
}

/// Counter for probe filename uniqueness. Avoids adding `tempfile` as a dep.
fn next_probe_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// True iff some strict ancestor of `path` is in `allow_set`.
fn nested_under_any(path: &Path, allow_set: &HashSet<PathBuf>) -> bool {
    let canon = canonical_or_self(path);
    let mut cur = canon.parent();
    while let Some(p) = cur {
        if allow_set.contains(&p.to_path_buf()) {
            return true;
        }
        // Try the canonicalized form — allow_set entries are canonicalized.
        if let Ok(c) = std::fs::canonicalize(p) {
            if allow_set.contains(&c) {
                return true;
            }
        }
        cur = p.parent();
    }
    false
}

/// Strip every ACE for `ac_sid` from `path`. Used by `revert`.
fn remove_aces_for_sid(path: &Path, ac_sid: PSID) -> Result<()> {
    remove_aces_for_sid_typed(path, ac_sid, None)
}

/// Strip ACEs for `target_sid` from `path`, optionally restricted to ACEs of
/// a specific type (`ACCESS_DENIED_ACE_TYPE` etc.). When `ace_type_filter`
/// is `None`, every ACE for the SID is removed. When `Some(t)`, only ACEs
/// whose `AceType == t` are removed — used by Phase E-3 revert to peel our
/// explicit DENY ACEs off well-known SIDs without touching pre-existing
/// ALLOW ACEs that the user actually relies on.
fn remove_aces_for_sid_typed(
    path: &Path, target_sid: PSID, ace_type_filter: Option<u8>,
) -> Result<()> {
    let path_w = wstr(&path.to_string_lossy());
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: windows::Win32::Security::PSECURITY_DESCRIPTOR =
        windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl as *mut *mut ACL),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(anyhow!("GetNamedSecurityInfoW({:?}): {:?}", path, rc));
    }

    // Build the list of ACEs to keep — every existing ACE whose SID
    // isn't `target_sid`, plus (when filtering by ACE type) any ACE for
    // `target_sid` whose type doesn't match the filter.
    let mut keep: Vec<EXPLICIT_ACCESS_W> = Vec::new();
    if !dacl.is_null() {
        unsafe {
            let count = (*dacl).AceCount as u32;
            for i in 0..count {
                let mut ace: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
                    continue;
                }
                let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
                let mask_ptr = (ace as *const u8)
                    .add(std::mem::size_of::<windows::Win32::Security::ACE_HEADER>())
                    as *const u32;
                let ace_mask = *mask_ptr;
                let sid_ptr = mask_ptr.add(1) as *mut c_void;
                let candidate = PSID(sid_ptr);
                let sid_matches = EqualSid(candidate, target_sid).is_ok();
                let type_matches = match ace_type_filter {
                    Some(t) => header.AceType == t,
                    None => true,
                };
                if sid_matches && type_matches {
                    continue; // drop
                }

                let mode = match header.AceType {
                    ACCESS_ALLOWED_ACE_TYPE => GRANT_ACCESS,
                    ACCESS_DENIED_ACE_TYPE => DENY_ACCESS,
                    _ => continue, // we only know how to round-trip these
                };
                let mut ea = EXPLICIT_ACCESS_W::default();
                BuildTrusteeWithSidW(&mut ea.Trustee as *mut TRUSTEE_W, candidate);
                ea.grfAccessPermissions = ace_mask;
                ea.grfAccessMode = mode;
                ea.grfInheritance = ACE_FLAGS(header.AceFlags as u32);
                keep.push(ea);
            }
        }
    }

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    // SetEntriesInAclW with no oldAcl → builds a fresh ACL from `keep`.
    let rc = unsafe {
        SetEntriesInAclW(
            Some(keep.as_slice()),
            None,
            &mut new_acl,
        )
    };
    if rc != ERROR_SUCCESS {
        if !sd.0.is_null() {
            unsafe { let _ = LocalFree(HLOCAL(sd.0)); }
        }
        return Err(anyhow!("SetEntriesInAclW (revert) failed: {:?}", rc));
    }

    let rc = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&path_w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
        )
    };
    if !new_acl.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(new_acl as *mut c_void)); }
    }
    if !sd.0.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sd.0)); }
    }
    if rc != ERROR_SUCCESS {
        return Err(anyhow!("SetNamedSecurityInfoW (revert): {:?}", rc));
    }
    Ok(())
}

/// Convert a string SID like `"S-1-15-2-1"` to a heap-owned PSID. Caller
/// frees with `LocalFree`. Only used by tests / examples that don't have a
/// real AC handy.
pub fn psid_from_string(sid_str: &str) -> Result<PSID> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let mut sid = PSID::default();
    let w = wstr(sid_str);
    unsafe {
        ConvertStringSidToSidW(pcwstr(&w), &mut sid)
            .map_err(|e| anyhow!("ConvertStringSidToSidW({sid_str}): {e}"))?;
    }
    Ok(sid)
}

/// Free a SID returned by `psid_from_string`.
pub fn free_psid(sid: PSID) {
    if !sid.0.is_null() {
        unsafe { let _ = LocalFree(HLOCAL(sid.0)); }
    }
}

/// Return the string form of a PSID. Convenience for manifest serialization.
pub fn psid_to_string(sid: PSID) -> Result<String> {
    use windows::core::PWSTR;
    let mut p = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut p)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
    }
    let s = from_pwstr(p);
    crate::util::local_free(p.0 as *mut c_void);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-known capability SID that the AC subsystem accepts but
    /// which is *not* covered by `ALL APPLICATION PACKAGES` inheritance.
    /// We use an arbitrary app-capability-style SID here so the
    /// Phase E-5a probe-skip doesn't trigger and short-circuit the
    /// existing per-SID idempotency / allow / deny checks (the inherited
    /// `S-1-15-2-1 ALLOW` on `%TEMP%` would otherwise make `apply()`
    /// skip every test root before our SID-specific assertions ran).
    const TEST_SID: &str = "S-1-15-3-1024-2049345768";

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sbox-stamper-{}-{}-{}",
            tag,
            std::process::id(),
            next_probe_counter()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    #[test]
    fn test_idempotent_apply() {
        let root = unique_dir("idem");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };

        // Each allow path now stamps twice: once for the AC SID and
        // once for `RESTRICTED` (S-1-5-12) so that restricted-token
        // access checks pass on both the normal- and restricting-SID
        // passes (see the comment block in `apply`).
        let s1 = policy.apply(sid).unwrap();
        assert_eq!(s1.roots_stamped, 2, "first apply should stamp AC + RESTRICTED");
        assert_eq!(s1.roots_skipped_idempotent, 0);

        let s2 = policy.apply(sid).unwrap();
        assert_eq!(s2.roots_stamped, 0, "second apply should be a no-op");
        assert_eq!(s2.roots_skipped_idempotent, 2, "both ACEs should be idempotent");

        policy.revert(sid).unwrap();
        free_psid(sid);
        cleanup(&root);
    }

    #[test]
    fn test_deny_omitted_when_no_parent_allow() {
        // A DENY path with no allow ancestor — the path is already closed
        // by default, so we shouldn't bother stamping a DENY there.
        let root = unique_dir("deny-orphan");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            deny_read: vec![root.clone()],
            ..Default::default()
        };

        let s = policy.apply(sid).unwrap();
        assert_eq!(s.denies_emitted, 0);
        assert_eq!(s.denies_omitted_unnecessary, 1);
        assert_eq!(s.roots_stamped, 0);

        free_psid(sid);
        cleanup(&root);
    }

    #[test]
    fn test_deny_emitted_when_nested_under_allow() {
        let root = unique_dir("allow-root");
        let nested = root.join("private");
        std::fs::create_dir_all(&nested).unwrap();
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            deny_read: vec![nested.clone()],
            ..Default::default()
        };

        let s = policy.apply(sid).unwrap();
        // Phase E-3: 1 DENY for the AC SID + 3 DENYs for well-known
        // SIDs (Everyone, AuthUsers, Users) per deny path.
        assert_eq!(s.denies_emitted, 4, "AC SID + 3 well-known SID DENYs");
        assert_eq!(s.denies_omitted_unnecessary, 0);
        assert!(s.roots_stamped >= 5);

        policy.revert(sid).unwrap();
        free_psid(sid);
        cleanup(&root);
    }

    /// Phase E-3: with USER_LOCKDOWN keeping `Everyone` enabled, the
    /// stamper must emit explicit DENY ACEs for the well-known SIDs on
    /// deny paths so a raw-syscall bypass doesn't leak through inherited
    /// `Everyone:R` from system paths. Verify that:
    ///  1. The DENY ACEs land on the deny path (one per well-known SID).
    ///  2. Revert removes only those DENY ACEs, leaving any pre-existing
    ///     ALLOW ACEs for the same SIDs (e.g. inherited Users:RX) intact.
    #[test]
    fn test_well_known_deny_aces_added_and_reverted() {
        let root = unique_dir("e3-allow");
        let nested = root.join("private");
        std::fs::create_dir_all(&nested).unwrap();
        let ac_sid = psid_from_string(TEST_SID).unwrap();
        let everyone = psid_from_string("S-1-1-0").unwrap();
        let users = psid_from_string("S-1-5-32-545").unwrap();
        let auth_users = psid_from_string("S-1-5-11").unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            deny_read: vec![nested.clone()],
            ..Default::default()
        };

        policy.apply(ac_sid).unwrap();

        for (label, s) in [
            ("Everyone", everyone),
            ("AuthUsers", auth_users),
            ("Users", users),
        ] {
            let present =
                root_already_stamped(&nested, s, read_mask(), ACCESS_DENIED_ACE_TYPE)
                    .unwrap();
            assert!(present, "DENY ACE for {label} should be present after apply");
        }

        policy.revert(ac_sid).unwrap();

        for (label, s) in [
            ("Everyone", everyone),
            ("AuthUsers", auth_users),
            ("Users", users),
        ] {
            let present =
                root_already_stamped(&nested, s, read_mask(), ACCESS_DENIED_ACE_TYPE)
                    .unwrap();
            assert!(!present, "DENY ACE for {label} should be removed after revert");
        }

        free_psid(ac_sid);
        free_psid(everyone);
        free_psid(users);
        free_psid(auth_users);
        cleanup(&root);
    }

    /// Phase E-5a: when a directory already has an `(OI)(CI)` ALLOW
    /// ACE for `ALL APPLICATION PACKAGES` granting at least the rights
    /// we'd add, `apply()` must skip stamping that path and bump
    /// `roots_skipped_already_accessible` instead. Critically, it
    /// must NOT add a redundant ACE for the test SID, since the
    /// real-world case (e.g. `C:\Program Files\Git`) is a path we
    /// can't write to anyway.
    #[test]
    fn test_skip_when_all_app_packages_already_grants() {
        let root = unique_dir("e5a-skip");
        // Plant an (OI)(CI) ALLOW ACE for ALL APPLICATION PACKAGES
        // with FILE_GENERIC_READ | FILE_GENERIC_EXECUTE — same mask
        // we'd add for an allow_read stamp.
        let app_pkgs = psid_from_string(ALL_APP_PACKAGES_SID).unwrap();
        let _g = SidGuard(app_pkgs);
        let plant_op = StampOp {
            path: root.clone(),
            kind: "test_plant",
            mask: read_mask(),
            mode: GRANT_ACCESS,
        };
        // Use apply_one directly to plant the ACE under the App
        // Pkgs SID. (apply_one is internal — that's fine; this is
        // a unit test in the same module.)
        let outcome = apply_one(&plant_op, app_pkgs).unwrap();
        assert_eq!(outcome, ApplyOutcome::Stamped, "planting ACE must succeed");

        // Confirm the helper sees it.
        assert!(
            existing_ace_grants_all_app_packages(&root, read_mask()).unwrap(),
            "helper must detect the planted ALL APP PACKAGES ACE",
        );

        // Now apply a policy with the test SID against the same
        // root: stamping should be skipped.
        let test_sid = psid_from_string("S-1-15-3-1024-1").unwrap(); // app capability SID, distinct from S-1-15-2-1
        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };

        let stats = policy.apply(test_sid).unwrap();
        assert_eq!(
            stats.roots_skipped_already_accessible, 1,
            "apply must skip-AC-accessible the planted root",
        );
        assert_eq!(stats.roots_stamped, 0, "no stamp should be issued");

        // And our test SID's ACE must NOT have been added.
        assert!(
            !root_already_stamped(&root, test_sid, read_mask(), ACCESS_ALLOWED_ACE_TYPE)
                .unwrap(),
            "test SID's ACE should not have been added (probe-skip)",
        );

        // Cleanup: remove the planted ACE before deleting the dir.
        let cleanup_policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };
        let _ = cleanup_policy.revert(app_pkgs);

        free_psid(test_sid);
        cleanup(&root);
    }

    #[test]
    fn test_revert_removes_aces() {
        let root = unique_dir("revert");
        let sid = psid_from_string(TEST_SID).unwrap();

        let policy = PolicyStamp {
            allow_read: vec![root.clone()],
            ..Default::default()
        };
        policy.apply(sid).unwrap();

        // Confirm an ACE exists.
        assert!(
            root_already_stamped(&root, sid, read_mask(), ACCESS_ALLOWED_ACE_TYPE).unwrap(),
            "ACE should be present after apply"
        );

        policy.revert(sid).unwrap();
        assert!(
            !root_already_stamped(&root, sid, read_mask(), ACCESS_ALLOWED_ACE_TYPE).unwrap(),
            "ACE should be gone after revert"
        );

        free_psid(sid);
        cleanup(&root);
    }
}
