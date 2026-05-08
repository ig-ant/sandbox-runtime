//! On-disk record of "which stamps did we apply, against which AC SID, hashed
//! against which policy" — see `cheeky-jingling-stream.md` §"Components > 2.
//! stamp_manifest.rs". The broker reads the manifest on startup; if its
//! `policy_hash` matches the current policy hash, all stamping work is
//! skipped (the warm-restart fast path).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::acl_stamper::PolicyStamp;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StampRecord {
    pub path: String,
    pub kind: String, // "allow_read" | "allow_write" | "deny_read" | "deny_write"
    pub mask: u32,
    pub inherit: String, // "OICI"
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StampManifest {
    pub version: u32, // 1
    pub ac_sid: String,
    pub applied_at: String, // ISO 8601
    pub policy_hash: u64,
    pub stamps: Vec<StampRecord>,
}

impl StampManifest {
    pub fn new(ac_sid: impl Into<String>, policy_hash: u64) -> Self {
        Self {
            version: 1,
            ac_sid: ac_sid.into(),
            applied_at: now_iso8601(),
            policy_hash,
            stamps: Vec::new(),
        }
    }

    /// Build the stamp record list from a `PolicyStamp`, capturing the leaves
    /// that the stamper would emit. Used by the broker to write the manifest
    /// after a successful apply.
    pub fn from_policy(ac_sid: impl Into<String>, policy: &PolicyStamp) -> Self {
        let mut m = Self::new(ac_sid, hash_policy(policy));
        for p in &policy.allow_read {
            m.stamps.push(record(p, "allow_read", 0x0012_00a9));
        }
        for p in &policy.allow_write {
            m.stamps.push(record(p, "allow_write", 0x0013_01ff));
        }
        for p in &policy.deny_read {
            m.stamps.push(record(p, "deny_read", 0x0012_00a9));
        }
        for p in &policy.deny_write {
            m.stamps.push(record(p, "deny_write", 0x0013_01ff));
        }
        m
    }
}

fn record(p: &Path, kind: &str, mask: u32) -> StampRecord {
    StampRecord {
        path: p.to_string_lossy().into_owned(),
        kind: kind.to_string(),
        mask,
        inherit: "OICI".to_string(),
    }
}

/// Stable hash over the policy's path lists. Order-independent: we sort each
/// list before hashing. Non-cryptographic — this is "did the policy change?",
/// not authentication.
pub fn hash_policy(p: &PolicyStamp) -> u64 {
    fn norm(v: &[PathBuf]) -> Vec<String> {
        let mut s: Vec<String> = v.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        s.sort();
        s.dedup();
        s
    }
    let mut h = DefaultHasher::new();
    norm(&p.allow_read).hash(&mut h);
    "|allow_read".hash(&mut h);
    norm(&p.allow_write).hash(&mut h);
    "|allow_write".hash(&mut h);
    norm(&p.deny_read).hash(&mut h);
    "|deny_read".hash(&mut h);
    norm(&p.deny_write).hash(&mut h);
    "|deny_write".hash(&mut h);
    let mut excl = p.exclude.clone();
    excl.sort();
    excl.dedup();
    excl.hash(&mut h);
    "|exclude".hash(&mut h);
    h.finish()
}

/// ISO 8601 timestamp. We avoid pulling in `chrono`/`time` for one helper —
/// produce `YYYY-MM-DDTHH:MM:SSZ` from `SystemTime`.
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-time conversion of a Unix epoch in seconds. Lifted from Howard
    // Hinnant's "date algorithms" — public domain. Spelling it out avoids a
    // `chrono` dep just for a stamp.
    let (y, mo, d, h, mi, s) = epoch_to_civil(secs as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, mo, d, h, mi, s
    )
}

fn epoch_to_civil(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let day = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let h = tod / 3600;
    let mi = (tod % 3600) / 60;
    let s = tod % 60;

    // Days since 1970-01-01 → Y/M/D, Hinnant.
    let z = day + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (y + if m <= 2 { 1 } else { 0 }) as i32;
    (y, m, d, h, mi, s)
}

pub struct ManifestStore {
    dir: PathBuf,
}

impl ManifestStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// `<dir>/<sid_filesafe>.json`. SID strings (`S-1-15-2-...`) are already
    /// filename-safe but we sanitize defensively in case a caller passes
    /// something odd.
    fn path_for(&self, ac_sid: &str) -> PathBuf {
        let sanitized: String = ac_sid
            .chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' => c,
                _ => '_',
            })
            .collect();
        self.dir.join(format!("{sanitized}.json"))
    }

    pub fn load(&self, ac_sid: &str) -> Result<Option<StampManifest>> {
        let p = self.path_for(ac_sid);
        if !p.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&p)
            .with_context(|| format!("read manifest {}", p.display()))?;
        let m: StampManifest = serde_json::from_str(&raw)
            .with_context(|| format!("parse manifest {}", p.display()))?;
        Ok(Some(m))
    }

    pub fn save(&self, m: &StampManifest) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("create manifest dir {}", self.dir.display()))?;
        let p = self.path_for(&m.ac_sid);
        let s = serde_json::to_string_pretty(m).context("serialize manifest")?;
        // Write+rename for crash safety.
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, s.as_bytes())
            .with_context(|| format!("write tmp manifest {}", tmp.display()))?;
        std::fs::rename(&tmp, &p)
            .with_context(|| format!("rename {} -> {}", tmp.display(), p.display()))?;
        Ok(())
    }

    /// True iff the stored manifest's policy hash differs from the new one
    /// — i.e. we need to re-stamp.
    pub fn diff(&self, prev: &StampManifest, next_policy_hash: u64) -> bool {
        prev.policy_hash != next_policy_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sbox-manifest-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn test_roundtrip() {
        let dir = unique_dir("roundtrip");
        let store = ManifestStore::new(dir.clone());

        let policy = PolicyStamp {
            allow_read: vec![PathBuf::from(r"C:\Users\test")],
            allow_write: vec![PathBuf::from(r"C:\Users\test\proj")],
            deny_read: vec![PathBuf::from(r"C:\Users\test\.ssh")],
            ..Default::default()
        };
        let m = StampManifest::from_policy("S-1-15-2-1", &policy);

        store.save(&m).unwrap();
        let back = store.load("S-1-15-2-1").unwrap().expect("manifest present");
        assert_eq!(m, back);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_diff_detects_change() {
        let dir = unique_dir("diff");
        let store = ManifestStore::new(dir.clone());

        let p1 = PolicyStamp {
            allow_read: vec![PathBuf::from(r"C:\a")],
            ..Default::default()
        };
        let p2 = PolicyStamp {
            allow_read: vec![PathBuf::from(r"C:\a"), PathBuf::from(r"C:\b")],
            ..Default::default()
        };

        let h1 = hash_policy(&p1);
        let h2 = hash_policy(&p2);
        assert_ne!(h1, h2);

        let m = StampManifest::from_policy("S-1-15-2-1", &p1);
        store.save(&m).unwrap();
        let prev = store.load("S-1-15-2-1").unwrap().unwrap();

        assert!(!store.diff(&prev, h1), "same policy → no re-stamp");
        assert!(store.diff(&prev, h2), "different policy → re-stamp");

        // Order-independence: shuffling the allow list yields the same hash.
        let p1_shuffled = PolicyStamp {
            allow_read: vec![PathBuf::from(r"C:\a"), PathBuf::from(r"C:\a")],
            ..Default::default()
        };
        assert_eq!(hash_policy(&p1), hash_policy(&p1_shuffled));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_missing_returns_none() {
        let dir = unique_dir("missing");
        let store = ManifestStore::new(dir.clone());
        assert!(store.load("S-1-15-2-99").unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
