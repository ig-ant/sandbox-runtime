# Cygwin recovery findings — beyond IL_LOW

**Investigation scope**: deltas between `95e81ab` (last-known-working bash echo on x64 CI: 19p/2s/0f) and `791d2fc` (current HEAD; IL_LOW restored; bash exits 66 EX_NOINPUT). 47 commits, ~2000 LOC deleted.

**Context recap**:
- N-6 step 1 (`a3a9649`) confirmed Phase L Wall 1 was misdiagnosis: cygwin1.dll DllMain *does* run cleanly under USER_LIMITED+AC when broker arch matches target arch (x64 broker → x64 bash), reaching ~160 trace lines through ucrtbase / msvcp_win / sechost / RPCRT4 / advapi32 / KsecDD / bcryptPrimitives / Lsa registry probe / NtCreateEvent ×9 / NtCreateSection+NtMapViewOfSection ×2 before exit.
- 791d2fc restored IL_LOW. On x64 CI bash now starts cleanly and exits **66 (EX_NOINPUT)** — bash itself is exiting with sysexits 66 ("cannot open input"), meaning Cygwin's DllMain succeeded but bash subsequently failed to open something.
- Phase D-4 commit (`3686f0a`, "Path C") deleted **1977 LOC** including the entire legacy broker FS / Reg / Attr / FS-pipe-client paths. Phase N-2 (`7f3e20a`) reintroduced **only** `OP_BROKER_OPEN` for `NtCreateFile` / `NtOpenFile`. Several other deletions are not replaced.

**Bash exit 66**: bash uses sysexits codes from `<sysexits.h>`. `EX_NOINPUT = 66` = "cannot open input". `bash -c "echo hello"` doesn't read a script file, but Cygwin-bash startup opens config files via Cygwin's path layer (`/etc/profile`, `/etc/bash.bashrc`, mount table at `/etc/fstab`, `/etc/passwd` for `getpwuid`). Failing those at the "open input" abstraction (Cygwin-side `path_conv` returning ENOENT) drives bash to print to stderr and exit 66.

---

## 1. HIGHEST-CONFIDENCE missing pieces

### 1A. NtQueryAttributesFile / NtQueryFullAttributesFile broker (DELETED in 3686f0a, NOT REPLACED)

**Removed by**: `3686f0a` Path C / D-4.
**95e81ab status**: hooked + brokered via `OP_NTQUERYATTR` (6) / `OP_NTQUERYFULLATTR` (7) → `handle_attr` in `launch.rs:785-844`.
**HEAD status**: not hooked anywhere. `grep -r NtQueryAttributesFile vendor/winsbox-src/` returns zero.

**Why Cygwin needs this**: `winsup/cygwin/path.cc` calls `NtQueryAttributesFile` extensively (path.cc:592 for `pc.fileattr`, path.cc:5155 for symlink resolution, plus calls in `uinfo.cc`, `syscalls.cc`, `fhandler/dev.cc`, `fhandler/procsys.cc`). This is on the `path_conv` hot path — every `/etc/passwd` / `/etc/profile` / `/dev/null` lookup the bash startup makes goes through `NtQueryAttributesFile` first to determine if the path exists / is a symlink / is a device.

**Failure mode**: bare AC token can't query attributes on most filesystem paths even when ACL stamping has granted `FILE_GENERIC_READ`, because `NtQueryAttributesFile` requires `FILE_READ_ATTRIBUTES` on the **parent directory**, which AC stamping doesn't always grant. Result: `path_conv` returns `STATUS_ACCESS_DENIED` → Cygwin maps to `ENOENT` → bash sees "cannot open" → exit 66.

**95e81ab implementation** (`launch.rs:785-844`):
```rust
fn handle_attr(ch, target, req, ctx) {
    // Read OBJECT_ATTRIBUTES.ObjectName from target
    let path = read_target_obj_path(...);
    match ctx.fs.evaluate(&path, FILE_READ_ATTRIBUTES) {
        Decision::Deny(why) => reply ACCESS_DENIED;
        Decision::AllowAsTarget => reply FS_PASSTHROUGH;
        Decision::Allow => {} // continue
    }
    // broker re-issues with broker token
    let st = NtQueryAttributesFile(&oa, &mut out)
          | NtQueryFullAttributesFile(&oa, &mut out);
    ch.reply_attr(st, &out);
}
```

**Restoration LOC estimate**: ~120 LOC.
- 60 LOC for `handle_attr` body (cdylib hook + IPC + broker handler)
- 30 LOC `interception_x64.rs` / `_arm64.rs` patch table additions
- 30 LOC `OP_NT_QUERY_ATTRIBUTES_FILE` opcode + Wire field

**Verdict**: most likely root cause of exit 66. Cygwin's path resolution is NOT routed through `NtCreateFile` (which would hit the existing `OP_BROKER_OPEN` proxy); it's routed through the lighter `NtQueryAttributesFile` first to avoid opening a handle for stat-style checks. Without brokering this call, every `path_conv` in Cygwin sees ACCESS_DENIED.

---

### 1B. Pipe client-end open via broker_pipes set (DEAD CODE in HEAD)

**Removed by**: `3686f0a` Path C / D-4 (deleted `handle_fs`, which was the consumer).
**95e81ab status**: live — `handle_named_pipe` records the leaf in `ctx.broker_pipes`; `handle_fs` reads `ctx.broker_pipes` to decide whether to broker the client-end `NtCreateFile` for that pipe (`launch.rs:660-672`).
**HEAD status**: **`broker_pipes` is INSERTED but NEVER READ**. Confirmed via:
```
git show HEAD:vendor/winsbox-src/src/launch.rs | grep -n broker_pipes
83:    broker_pipes: Mutex<...>,           # field decl
1059:        broker_pipes: Mutex::new(...),  # init in main path
2164:        broker_pipes: Mutex::new(...),  # init in alternate path
2622:        ctx.broker_pipes.lock().unwrap().insert(leaf_l.to_string()); # insert only
```
No reader anywhere.

**Why Cygwin needs this**: Cygwin's `sigproc_init` creates a per-PID signal pipe at `\??\pipe\msys-<hash>-<pid>-sigwait`. The broker creates the **server end** via the surviving `handle_named_pipe`. Then Cygwin's same DllMain code path calls `NtCreateFile` (often via `fhandler_pipe::nt_create`) to open the **client end** of its own pipe. The pipe's DACL is the broker's default (AC denied); the AC token can't open it.

**Failure mode in HEAD**:
1. `NtCreateFile` saved-original returns `STATUS_ACCESS_DENIED` (or `STATUS_OBJECT_NAME_NOT_FOUND` if the namespace path differs).
2. cdylib's denylog hook routes to `OP_BROKER_OPEN`.
3. `broker_open.rs::normalize_nt_path` strips `\??\` → `pipe\msys-...`.
4. `is_path_allowed_for_broker_open` rejects: not a drive letter, not in `allowRead`/`allowWrite`/auto-toolchain.
5. Result: `STATUS_ACCESS_DENIED` returned to Cygwin → sigwait setup fails → bash bails.

**95e81ab implementation** (`launch.rs:660-672` inside `handle_fs`):
```rust
let is_own_pipe = lower
    .strip_prefix(r"\??\pipe\")
    .or_else(|| lower.strip_prefix(r"\device\namedpipe\"))
    .is_some_and(|leaf| ctx.broker_pipes.lock().unwrap().contains(leaf));
let decision = if is_own_pipe { Decision::Allow }
               else { ctx.fs.evaluate(&path, access) };
```

**Restoration LOC estimate**: ~25 LOC.
- Add a `handle_broker_open` early-out in `broker_open.rs` that consults `broker_pipes` and bypasses the DOS-path policy check. Or add the pipe-client check in the cdylib's denylog hook (skip the broker-open IPC, go directly to a new `OP_BROKER_OPEN_PIPE`).

**Verdict**: very likely required. If 1A doesn't fully fix exit 66, this is the next-most-load-bearing missing piece. Cygwin's sigwait setup happens in DllMain (`sigproc_init`) — without it, every Cygwin process AVs or exits with a fatal error after DllMain returns.

---

### 1C. NtOpenKey / NtOpenKeyEx registry broker (DELETED in 3686f0a, NOT REPLACED)

**Removed by**: `3686f0a` Path C / D-4.
**95e81ab status**: hooked + brokered via `OP_NTOPENKEY` (3) / `OP_NTOPENKEYEX` (4) → `handle_reg` in `launch.rs:1131-1230`. Brokered KEY_READ access to registry keys whose AC ALL_APP_PACKAGES inherited grant didn't extend.
**HEAD status**: not hooked. Comment in `interception_x64.rs:65` admits "D-4: NtOpenKey / NtOpenKeyEx hooks dropped (registry policy ... ACL stamping owns FS/Reg policy)". But ACL stamping requires the policy to enumerate every reg key; Cygwin's reg accesses are not in any policy.

**Why Cygwin needs this**: `winsup/cygwin/uinfo.cc::cygheap_pwdgrp::init` reads `HKEY_LOCAL_MACHINE\SOFTWARE\Cygwin\setup` (rootdir for `/etc/passwd` lookup), `HKEY_CURRENT_USER\Environment`, and per-Win32 user SID-mapping keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`. Bash startup needs `getpwuid(getuid())` which transitively reads these. AC token reaches `HKLM\SOFTWARE\Cygwin\setup` (system grant) but **NOT** `HKLM\...\ProfileList\<sid>` (per-SID ACE granted to specific users).

**Failure mode**: `getpwuid` returns NULL → Cygwin synthesizes a fake user → `bash` then can't find `$HOME` → tries to read `/etc/passwd` → that's also an `NtQueryAttributesFile`/`NtCreateFile` chain that fails per 1A. Compound contributor to exit 66.

**Restoration LOC estimate**: ~150 LOC (similar shape to 1A — opcode + cdylib hook + handler).

**Confidence**: medium-high. Even if 1A and 1B fix the immediate exit-66, registry-brokering for `getpwuid`/`getpwnam` is needed for bash to find `$HOME` and `/etc/profile`, which `bash -c` reads on login shell flag. `bash -c "echo hello"` is **not** a login shell — bash skips `/etc/profile` and `~/.bashrc` for non-login non-interactive shells. So this may be lower priority than 1A and 1B for the immediate exit-66 fix, but is required for `bash -l` and any path that goes through user info.

---

## 2. PLAUSIBLE-BUT-NEEDS-VERIFICATION

### 2A. STATUS_OBJECT_NAME_NOT_FOUND not routed to broker

The cdylib's `hook_nt_create_file_denylog` only routes to `OP_BROKER_OPEN` on `STATUS_ACCESS_DENIED`. Cygwin opens paths like `\??\C:\cygwin64\etc\passwd` that don't exist on Git-for-Windows installs (it's `C:\Program Files\Git\etc\passwd`). The saved-original returns `STATUS_OBJECT_NAME_NOT_FOUND`, NOT `ACCESS_DENIED`. This is the *correct* status (the file genuinely doesn't exist) but it suggests Cygwin's mount table init ought to be mounting `/etc → C:\Program Files\Git\etc`. If the mount-table read fails earlier (registry → 1C), Cygwin doesn't know where to look.

**Verification cost**: low — re-run smoke_bash with `WINSBOX_TRACE_SYSCALLS=1` after 1A is restored, look for the pre-exit-66 syscall sequence.

### 2B. lpReserved2 forwarding — VERIFIED PRESENT

`read_target_startupinfo` in HEAD (`launch.rs:2844-2890`) is byte-identical to 95e81ab's version at `launch.rs:1509-1556`. The `lpReserved2` / `cbReserved2` forwarding for Cygwin `child_info_fork` is intact. Not a regression. The Path C commit message *mentioned* "lpReserved2 forwarding" as one of four untested hypotheses, but `lpReserved2 forwarding` was already implemented at 95e81ab and survived the deletion (it's needed by `handle_cpw` which survived).

`bash -c "echo hello"` does **not** fork (echo is a builtin), so this isn't on the failure path anyway.

### 2C. Cygwin-DLL hostfxr/MountPointManager surviving paths

CI fix `3092e82` added `MountPointManager` to `READ_ONLY_KERNEL_DEVICES`. Confirms that broker mediation reaches some Cygwin code paths post-DllMain. But the broker only allowlists `MountPointManager` and the four DOS reserved devices (`nul`, `con`, `prn`, `aux`). Cygwin also opens `\Device\Null` directly (not via `\??\nul`), `\Device\Tty`, `\Device\KsecDD` (already brokered via `is_read_only_kernel_device`?), and `\Device\Afd` (passthrough at 95e81ab's `Decision::AllowAsTarget`). Need to verify whether HEAD's `is_path_allowed_for_broker_open` returns reject for `\Device\Null` accesses.

The 95e81ab `policy_engine.rs:62-78` had explicit handling of `\Device\<name>` paths:
```rust
if let Some(dev) = lower.strip_prefix(r"\device\") {
    return match head {
        "cng" | "ksecdd" | "nsi" | "deviceapi" | "mountpointmanager" => Decision::Allow,
        _ => Decision::AllowAsTarget,
    };
}
```

HEAD's `broker_open.rs:202` rejects every `\Device\` path (returns `None` from `normalize_nt_path`). The 95e81ab logic for `\Device\Null` (Cygwin uses `\??\Null` aka `\Device\Null`) would have returned `Decision::AllowAsTarget` (passthrough), which means the original AC syscall succeeds (kernel allows AAP-tagged AC tokens to open `\Device\Null`). Whether HEAD's plain passthrough also succeeds depends on the kernel ACL on `\Device\Null` — likely fine, but Cygwin opens `\Device\NamedPipe\` (the pipe namespace root) for some operations and the AC's right there is unknown.

**Verification cost**: medium — strace via existing `WINSBOX_TRACE_SYSCALLS=1`, find post-DllMain accesses to `\Device\*`.

### 2D. Trace coverage gap pre-exit-66

The N-5 trace coverage stops at 30 syscalls (`docs/n5_findings.md`). Critical missing hooks for diagnosing exit-66: `NtSetInformationFile`, `NtWriteFile` (bash writes "hello\n" before exiting!), `NtTerminateProcess`. Without `NtWriteFile` trace we can't tell whether bash got to its `printf` call or died before. Suggested as a one-commit diagnostic before any restoration: extend `TRACE_SYSCALL_NAMES` by 3-4 entries.

---

## 3. ALREADY-RESTORED (verified vs 95e81ab)

### 3A. IL_LOW restoration ✓

Commit `791d2fc` restored `token::IL_LOW` constant and `run_confined`'s use of `(USER_LIMITED, IL_LOW)` instead of `(USER_LIMITED, IL_UNTRUSTED)`. Matches 95e81ab's `spec_from_env` default exactly.

### 3B. lpReserved2 forwarding ✓

`read_target_startupinfo` survived intact (verified above). Cygwin fork uses this; bash echo doesn't trigger fork.

### 3C. handle_cpw / CreateProcessInternalW interception ✓

`handle_cpw` survived. The cmd → bash → bash spawn chain is hooked end-to-end. Phase N-2 Part B added grandchild cdylib injection.

### 3D. handle_dirobj (BNO redirect) ✓

`\BaseNamedObjects\msys-*` → per-AC namespace redirect intact.

### 3E. handle_named_pipe ✓

NtCreateNamedPipeFile broker (server end) intact for `msys-*` / `cygwin-*` / bare-installation-key shapes.

---

## 4. NOT CYGWIN-RELEVANT (deltas ruled out)

- **Phase E-5c no_std cdylib** (`c0209d1`, 127KB → 11KB): purely a build-time concern. Manual-map loader handles both shapes; bash sees the same hook surface.
- **ACL stamping introduction** (`6f1e7ce` Phase A → `b324c1a` Phase D): replaces the legacy `acl.rs::AclJournal` per-spawn grant with a stamp manifest. The stamp ACL is *additive* — covers the same paths the old code did (allowRead, exe-dir, AC SID grants). Equivalent for bash's needs; only the warm-restart caching is new.
- **Phase G stable AC SID** (`da67ed0`): same SID across runs → manifest cache hit → 3.5s startup → 0ms warm. Behaviorally identical.
- **Phase H ARM64 entry trampoline** (`b671f35`): per-arch infra; x64 path unchanged.
- **Phase I global_asm! enc_abs_jmp** (`73929db`): build-time codegen. Same instruction bytes.
- **Phase J token.rs cleanup** (`47fc913`): deleted unused `USER_LOCKDOWN` constant. The 791d2fc recovery re-added IL_LOW. USER_LIMITED was already the production token shape per Phase E-5c.
- **Phase K trace mode** (`b6bedee`): diagnostic-only, opt-in via `WINSBOX_TRACE_SYSCALLS=1`.
- **Phase N-1 USERPROFILE forwarding** (`c37e186`): ENV var forwarding. Helps Cygwin find $HOME but only matters once getpwuid succeeds (per 1C).
- **Phase N-4 Schannel investigation** (`fff0a1e` + `46098c5`): structural LSA wall; only matters for HTTPS, not bash-echo.
- **N-6 step 1 x64 cross-build** (`a3a9649`): the actual fix for Phase L Wall 1; orthogonal to the deletions investigated here.

---

## 5. Top-3 ranked + restoration plan

| # | Missing piece | Confidence | LOC | Likely-fixes-exit-66 |
|---|---|---|---|---|
| 1 | `NtQueryAttributesFile` / `NtQueryFullAttributesFile` broker | **High** | ~120 | **Yes** — Cygwin path_conv depends on this for every `/etc/*` lookup |
| 2 | `broker_pipes` consumer (pipe client-end open) | **High** | ~25 | Likely — Cygwin sigwait setup depends on this |
| 3 | `NtOpenKey` / `NtOpenKeyEx` broker | Medium | ~150 | Partial — only matters if bash-echo path reads HKLM (likely doesn't) |

**Recommended sequence**:
1. **First**: extend trace coverage by 4 syscalls (`NtSetInformationFile`, `NtWriteFile`, `NtReadFile`, `NtTerminateProcess`) and re-run smoke_bash on x64 to capture the **specific** syscall sequence preceding exit 66. ~30 LOC, 1 commit, definitive evidence.
2. **Then**: restore #1 (`NtQueryAttributesFile` broker). Highest expected impact.
3. **Then**: restore #2 (pipe client-end). Small change.
4. **Then**: only if 1+2 doesn't fix: restore #3 or extend allowed-device list in `broker_open.rs` for the post-1+2 trace.

**Will exit-66 likely resolve with restoration?** Yes for #1+#2 — the existing CI fixes (`3092e82` MountPointManager, `374ec3d` wrapper-aware isCygwinGit, `f300d7d` depth-2 grandchild dup) collectively show the architecture is stable enough that reintroducing a single missing hook plus fixing the dead-code pipe consumer is in scope.

**Caveat**: even after these restorations, `bash (msys2) ls | head` (currently `test.skip` at HEAD line 132) would still hit Cygwin fork()'s section-remap + child_info handle table, which depends on a chain of behaviors that were *all* working at 95e81ab + Phase 2b but haven't been re-verified post-cdylib. That test stays skipped.
