# Pre-created Cygwin shared-section probe — findings

**Branch**: `winsbox-msys2-iter` (HEAD `4d26ef0`)
**Date**: 2026-05-10
**New file**: `vendor/winsbox-src/examples/probe_preshared.rs`
**Outcome**: **Hypothesis rejected** — pre-creating the section is
necessary-but-not-sufficient (probably *not* even necessary) for bare-AC
bash to bootstrap on Win11 25H2 ARM64.

## TL;DR

The probe successfully pre-creates Cygwin's `shared.5` named section at
the exact AC-namespace path Cygwin would look it up under, with a
NULL DACL (= everyone full-access, matching Cygwin's `sec_all_nih`).

- Section path constructed correctly: matches the captured procmon
  trace (`docs/n6_bash_il_low_trace.log` line 254-255).
- `installation_key` computed correctly: `1888ae32e00d56aa` (matches
  captured trace byte-for-byte).
- Broker-side `NtCreateDirectoryObject` + `NtCreateSection` both
  return `STATUS_SUCCESS`.
- Broker-side `NtOpenSection` reopen-by-name also succeeds — the
  section is structurally findable.

**Bash still AVs with `0xC0000005`, 0 bytes stdout, 0 bytes stderr** —
indistinguishable from the bare-AC baseline (`probe_vanilla_ac`).

## What was tried

1. **Approach B** (per task description) — the most direct: pre-create
   the entire chain inside the per-AC namespace:

   ```
   \Sessions\<sess>\AppContainerNamedObjects\<ac-sid>\          ← (a)
                                              msys-2.0S5-<key>\  ← (b)
                                                 shared.5         ← (c)
   ```

   - (a) created via `sbox_exec::token::create_ac_bno()` (existing helper).
   - (b) `NtCreateDirectoryObject` with `OBJ_OPENIF | OBJ_CASE_INSENSITIVE`,
     `DIRECTORY_ALL_ACCESS`, and an explicit security descriptor with a
     NULL DACL (allow-all).
   - (c) `NtCreateSection` with `SECTION_ALL_ACCESS`, `PAGE_READWRITE`,
     `SEC_COMMIT`, `MaximumSize = 0xE7B8` (verified `sizeof(shared_info)`
     from `bash_av_root_cause.md`), pagefile-backed (`SectionFileHandle=0`),
     same NULL-DACL security descriptor.

2. **Verification**: the probe reopens the section by name via
   `NtOpenSection` and reports `STATUS_SUCCESS`. So the section
   exists at the expected path with broker-side access.

3. **`installation_key` derivation**: replicated Cygwin's
   `init_cygheap::init_installation_root` (`winsup/cygwin/mm/cygheap.cc:162`)
   to compute the 16-hex install-key from the NT-form DLL path.
   Algorithm:

   ```
   h = 0
   for each WCHAR c in nt_path:
       h = upcased(c) + (h<<6) + (h<<16) - h
   key = hex(h, 16 chars, lowercase)
   ```

   Computed `1888ae32e00d56aa` for
   `\??\C:\Program Files\Git\usr\bin\msys-2.0.dll` — matches the
   captured procmon trace exactly. Confidence-high the section is
   sitting where Cygwin would look it up.

## Outcome

```
[probe-preshared] dir create:    NTSTATUS=0x0  (NULL DACL = allow-all)
[probe-preshared] section create: NTSTATUS=0x0
[probe-preshared] section reopen-by-name status: 0x0
[probe-preshared] target pid=10072
[probe-preshared] exit code = 0xc0000005 (-1073741819)
[probe-preshared] --- stdout (0 bytes) ---
[probe-preshared] --- stderr (0 bytes) ---
[probe-preshared] OUTCOME: bare-AC bash AVs even with pre-created section.
```

Compare to `probe_vanilla_ac` (no pre-create) baseline:

```
[probe-vanilla-ac] exit code = 0xc0000005 (-1073741819)
[probe-vanilla-ac] --- stdout (0 bytes) ---
[probe-vanilla-ac] --- stderr (0 bytes) ---
```

**Byte-identical observable behaviour.** Pre-create does not change
the failure mode.

## Why the hypothesis was wrong (or at least incomplete)

`docs/bash_arm64_root_cause_synthesis.md` puts the bare-AC AV at
`msys_dll_init+0x1652`, `test byte ptr [rdx+1], 8`, with `rdx` pointing
into 535-GB MEM_FREE. That's an **earlier** site than the
`shared_info::create()` chain. The newer `docs/bash_av_root_cause.md`
analysis (with hooks + IL_LOW) traces a *different* AV at
`dll_list::cleanup_forkables` reading NULL `cygwin_shared`, downstream
of a failed `CreateFileMappingW("shared.5")`. The two AVs are at
different sites in `msys_dll_init`'s execution and the bare-AC one is
upstream of the section create.

Concretely, `dll_crt0_0()` in `winsup/cygwin/dcrt0.cc:725` calls
`setup_cygheap()` (which initialises `cygheap`, `user`,
`installation_root`, `pg`) **before** `memory_init()` (which calls
`shared_info::create()`). The bare-AC `+0x1652` AV is plausibly inside
the `cygheap` chain — `cygheap->user.init()` (LSA-touching) or
`init_installation_root()` (registry-touching). Both are pre-section.

The procmon-based "shared section is denied" finding
(`docs/procmon_bash_findings.md` and the corresponding capture in
`n6_bash_il_low_trace.log:256`) was on a **non-bare** run with hooks +
IL_LOW + cdylib injection. In that configuration, bash got far enough
to hit the section create — but in the bare AC the AV is upstream.

The 0-byte stderr in the bare-AC case is the giveaway: Cygwin's
`api_fatal` (the path that *would* emit
"`*** fatal error - CreateFileMapping shared.5, Win32 error 5`") is
never reached. The process AVs cleanly before any fatal-error string
is composed.

## Recommended next steps

### Don't pursue this fix path further

The hypothesis was reasonable given the procmon trace, but the bare-AC
AV is at a different site. Pre-creating `shared.5` is **at most** a
partial fix: it would help if/when the section-create path is reached,
but it doesn't address the upstream AV.

The synthesis doc (`bash_arm64_root_cause_synthesis.md`) already
recommended **deferral** — keep the test gated on
`process.arch !== 'arm64'`. This experiment validates that
recommendation: there is no narrow targeted fix.

### If the operator wants to confirm the upstream AV site

Run `probe_preshared` with `WINSBOX_PAUSE_FOR_DEBUGGER=1` (plumbing
added in this branch) and attach the **arm64** `cdb.exe` from
`C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe`
(the x64 build of cdb isn't installed on this host; the arm64 build
can debug x64-emulated processes via WOW64-style cross-arch debug).

Look for the precise RIP at first-chance AV — if it's again at
`msys-2.0!_feinitialise+...` near `setup_cygheap` or
`init_installation_root`, the cause is registry / LSA reach failing
under bare AC, not the shared section. Concretely useful breakpoints:

```
bp msys-2.0!dll_crt0_0          (DllMain entry — sanity)
bp msys-2.0!setup_cygheap       (before bare-AC suspect site)
bp msys-2.0!shared_info::create (the section-create path)
g
```

If `setup_cygheap` is entered but `shared_info::create` is not
reached, the AV is upstream of the section and the pre-create probe
results are explained.

### If pre-create *is* eventually shown to be a partial fix

The probe's structural pieces are reusable for broker integration:

- `cygwin_installation_key()` (in `probe_preshared.rs`) — pure
  algorithmic port of Cygwin's `hash_path_name`. Self-contained;
  candidate for moving into `src/cygwin_compat.rs` or similar if
  upstreamed.
- `create_ac_bno()` already exists in `src/token.rs:300`.
- The `NtCreateDirectoryObject` + `NtCreateSection` ceremony is
  three calls and 60 lines — easy to extract.

Broker integration shape (if/when needed):

```rust
// In launch.rs, after AppContainer::create_with_key,
// before CreateProcessAsUserW. Gated on a config flag or
// auto-detected from target binary (e.g., target imports
// msys-2.0.dll / cygwin1.dll).
if policy.pre_create_cygwin_shared {
    let key = cygwin_installation_key(&target_msys_dll_path);
    let (bno_base, _ac_root_h) = create_ac_bno(&ac.sid_string)?;
    let parent_path = format!(
        r"{}\{}S5-{}", bno_base,
        cygwin_dll_id(&target_msys_dll_path), key,
    );
    let _dir_h = create_dir_with_null_dacl(&parent_path)?;
    let section_h = create_pagefile_section_with_null_dacl(
        &format!(r"{}\shared.5", parent_path), 0xE7B8,
    )?;
    // Keep both handles alive in the LaunchedTarget struct so the
    // section persists for the target's lifetime; drop on cleanup.
    target.preshared_handles = vec![dir_h, section_h];
}
```

But this is **deferred** until either (a) the upstream AV is fixed in
Cygwin, or (b) someone identifies what `setup_cygheap()` is choking on
in bare AC and provides a separate fix for that.

## Verification

- `cargo test --lib`: 30/30 pass (no regressions).
- `cargo build --release --example probe_preshared`: clean.
- `cargo run --release --example probe_preshared`: exits 2 as designed
  (AV outcome). All broker-side calls succeed cleanly.
- `cargo run --release --example probe_vanilla_ac`: unchanged baseline
  (also AVs).

## Files

- New: `vendor/winsbox-src/examples/probe_preshared.rs`
- This doc: `docs/preshared_probe_findings.md`
- Unchanged: everything else (no shared modules, no test gates, no
  policy plumbing touched).
