//! Bench against a real big tree (`%USERPROFILE%\.rustup` is the canonical
//! target — ~50k items, the same shape we actually care about). Prints three
//! timings:
//!
//! 1. Cold apply: should be on the order of the icacls baseline (~20–40s).
//! 2. Warm re-apply (same policy via the stamper): idempotency probe should
//!    skip the walk → < 10s.
//! 3. Manifest-gated apply (same policy hash): we don't even call
//!    `apply()` — the broker reads the manifest, sees the hashes match,
//!    and moves on. Should be < 100ms.
//!
//! Cleans up after itself (revert + remove the manifest).
//!
//! Invoke with:
//!
//! ```
//! $env:CARGO_TARGET_DIR = "C:\Users\ig\winsbox-target"
//! & "$env:USERPROFILE\.cargo\bin\cargo.exe" run --example bench_stamper
//! ```

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use sbox_exec::acl_stamper::{free_psid, psid_from_string, PolicyStamp};
    use sbox_exec::stamp_manifest::{hash_policy, ManifestStore, StampManifest};
    use std::path::PathBuf;
    use std::time::Instant;

    // S-1-15-2-1 = ALL APPLICATION PACKAGES. Real well-known SID, every
    // AppContainer process has it in its membership; perfect for benching
    // without spinning up an AC profile.
    const SID: &str = "S-1-15-2-1";

    let target = std::env::var("BENCH_TARGET").map(PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("USERPROFILE").expect("USERPROFILE");
        PathBuf::from(home).join(".rustup")
    });
    if !target.exists() {
        eprintln!("bench target {} doesn't exist; pass BENCH_TARGET=<path> to override", target.display());
        std::process::exit(2);
    }

    let manifest_dir = std::env::temp_dir().join(format!(
        "sbox-bench-manifest-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&manifest_dir).ok();
    let store = ManifestStore::new(manifest_dir.clone());

    let policy = PolicyStamp {
        allow_read: vec![target.clone()],
        ..Default::default()
    };
    let policy_hash = hash_policy(&policy);

    let sid = psid_from_string(SID)?;

    println!("== bench_stamper ==");
    println!("target: {}", target.display());
    println!("manifest dir: {}", manifest_dir.display());
    println!("policy hash: {:#x}", policy_hash);

    // 1. Cold apply.
    let t = Instant::now();
    let s1 = policy.apply(sid)?;
    let cold_ms = t.elapsed().as_millis();
    println!(
        "[1/3] cold apply: {} ms  ({:?})  ",
        cold_ms, s1
    );
    let manifest = StampManifest::from_policy(SID, &policy);
    store.save(&manifest)?;

    // 2. Warm re-apply via the stamper directly. Idempotency probe takes
    // over.
    let t = Instant::now();
    let s2 = policy.apply(sid)?;
    let warm_ms = t.elapsed().as_millis();
    println!(
        "[2/3] warm apply (stamper idempotency): {} ms  ({:?})",
        warm_ms, s2
    );

    // 3. Manifest-gated. This is the *fastest* path — we don't even call
    // `apply()`. Broker logic shape: load manifest, hash policy, compare.
    let t = Instant::now();
    let prev = store.load(SID)?.expect("manifest written above");
    let needs_restamp = store.diff(&prev, policy_hash);
    let manifest_ms = t.elapsed().as_millis();
    println!(
        "[3/3] manifest-gated check: {} ms  (needs_restamp={})",
        manifest_ms, needs_restamp
    );

    // Cleanup. Revert the ACEs and remove the temp manifest dir.
    println!("cleaning up …");
    policy.revert(sid)?;
    std::fs::remove_dir_all(&manifest_dir).ok();
    free_psid(sid);

    println!("done.");
    println!(
        "summary: cold={} ms, warm={} ms, manifest-gated={} ms",
        cold_ms, warm_ms, manifest_ms
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("bench_stamper only runs on windows");
}
