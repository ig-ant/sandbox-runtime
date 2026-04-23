# winsbox-poc

## What this is

`sandbox-runtime` confines arbitrary commands by shelling out to a
platform-native sandbox CLI: `sandbox-exec` (seatbelt) on macOS and
`bwrap` + a seccomp helper on Linux. Windows has no equivalent CLI, so
the proposed design ships a Rust broker (`sbox-exec.exe`) that fills
the same slot using the Chromium sandbox primitives — AppContainer,
restricted tokens, Job objects, integrity levels, ntdll interception —
in two phases:

- **Phase 1**: AppContainer + Job + Low IL + alternate desktop +
  mitigation policies. Filesystem allow/deny via temporary ACL grants
  to the AppContainer SID; network blocked by AppContainer (no
  `internetClient` capability) with an AF_UNIX bridge to the existing
  HTTP/SOCKS proxy. Roughly macOS-equivalent guarantees.
- **Phase 2**: Chromium-style lockdown — `CreateRestrictedToken`
  (deny-only groups, NULL restricting SID, Untrusted IL) wrapped in a
  LowBox token, with the broker inline-hooking `ntdll!Nt{Create,Open}File`
  / `NtCreateUserProcess` in the suspended target so file access and
  child-process creation are policy-checked over IPC and handles are
  duplicated back. The token is the security boundary; the hooks are
  for compatibility.

This crate is the de-risking spike for that design: nine standalone
probes that empirically test the OS-behaviour assumptions each phase
depends on, *before* any of it is built. Each probe answers one binary
question; `cargo run -- all` runs the lot and writes `RESULTS.md`.

## How the proposed Windows design maps to the existing platforms

| Guarantee | macOS (`sandbox-exec`) | Linux (`bwrap` + seccomp) | Windows Phase 1 | Windows Phase 2 | Validated by |
|---|---|---|---|---|---|
| Filesystem write allow-list | Seatbelt `(allow file-write* (subpath …))` | `--ro-bind /` + `--bind <allow>` | ACL grant `(OI)(CI)M` to AppContainer SID on each `allowWrite` path | Broker policy engine: open-then-`GetFinalPathNameByHandleW`-then-verify, `DuplicateHandle` on allow | P3, P9 |
| Filesystem read deny-list | Seatbelt `(deny file-read* …)` | `--ro-bind /dev/null <deny>` over the path | Explicit deny ACE for AC SID | Broker policy engine (same path check, deny → `STATUS_ACCESS_DENIED`) | P3, P9 |
| Confused-deputy (symlink/junction/hardlink) defence | Seatbelt resolves paths kernel-side; `isSymlinkOutsideBoundary` pre-check | bind-mounts pin inodes; `isSymlinkOutsideBoundary` pre-check | Kernel ACL check is on the resolved object | `GetFinalPathNameByHandleW` re-check + `nNumberOfLinks`/`FindFirstFileNameW` fan-in check + dir handles never get `FILE_ADD_FILE` | P9 |
| Network default-deny | Seatbelt `(deny network*)` | `bwrap --unshare-net` | AppContainer with empty capability list | LowBox token with empty capability list | P1 |
| Allowed-domain egress via SRT proxy | Seatbelt allows `localhost:<proxy>`; `HTTP_PROXY` env | `socat` Unix-socket bridge into the netns; `HTTP_PROXY` env | AF_UNIX bridge between AC child and broker, TCP relay inside the AC; `HTTP_PROXY` env | Same bridge (AppContainer layer is kept for network) | P1, P2 |
| Loopback to other host services blocked | Seatbelt `network-outbound` rules | netns isolates loopback entirely | AppContainer blocks cross-IL loopback; bridge exposes only the proxy socket (no `LoopbackExempt`) | Same | P1, P2 |
| Child processes inherit the boundary | Seatbelt is per-process-tree | Mount/PID/net namespaces are inherited | AppContainer + Job inherited by `CreateProcess` | Restricted token + Job inherited; broker hooks `NtCreateUserProcess` to re-apply ntdll patches to grandchildren | P4, P8 |
| Kill whole tree on broker exit | Caller's process group | `bwrap --die-with-parent` | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Same | — |
| Privilege floor of confined code | Seatbelt profile | unprivileged userns + seccomp `EPERM` | Low IL + Job UI restrictions + mitigation policies | Untrusted IL + deny-only SIDs + NULL restricting SID + no privileges | P5 |
| Bootstrap (let the target's runtime initialise before lockdown bites) | n/a — seatbelt rules apply from `exec` | n/a — bind mounts apply from `exec` | n/a — AC + ACLs apply from `CreateProcess` | Two-token: lockdown primary + restricted-same-access impersonation on the main thread for loader init, reverted by a thread-context trampoline before `main()` | P5, P7 |
| Runtime DLL / `LoadLibrary` after lockdown | n/a | n/a | AC can read anything ACL'd `ALL APPLICATION PACKAGES` | `NtCreateFile` hook → broker opens + `DuplicateHandle` back; `\KnownDlls` section objects load regardless | P6 |
| Admin / setuid required | No | No (unprivileged userns) | No | No | — |
| External runtime deps | none (`sandbox-exec` is in base OS) | `bwrap`, `socat` | none (Rust static binary; `AF_UNIX` is in-box ≥ Win10 1803) | none | — |

## Probes

| Probe | Question |
|---|---|
| P1 | Can a no-capability AppContainer process bind+connect 127.0.0.1 to itself? |
| P2 | Can an AppContainer process reach a broker over AF_UNIX? |
| P3 | Does an explicit ACL grant to the AC SID let the AC write there (and only there)? |
| P4 | Do grandchildren of an AC process inherit the AC? |
| P5 | Does the loader survive a `CreateRestrictedToken→NtCreateLowBoxToken` primary token with thread-impersonation bootstrap? |
| P6 | Can we inline-hook `ntdll!NtCreateFile` in a `CREATE_SUSPENDED` child? |
| P7 | Can a thread-context-redirect stub revert impersonation after the loader APC but before `main()`? |
| P8 | Does the P6 hook on `NtCreateUserProcess` fire when the target spawns a child? |
| P9 | Does `GetFinalPathNameByHandleW` *not* canonicalize hardlinks, and can `nNumberOfLinks`+`FindFirstFileNameW` detect the fan-in? |

P1–P4 gate Phase 1; P5–P8 gate Phase 2; P9 gates the broker's
confused-deputy defence in Phase 2.

A `FAIL` verdict is data, not a CI failure — it triggers the documented
pivot for that probe. Only an `ERROR` (probe crashed) returns non-zero.

This crate is deleted once the real `winsbox-src` lands.

---

## Findings

**9/9 PASS** on GitHub-hosted `windows-latest` (x64, 10.0.26100) and
`windows-11-arm` (10.0.26200) as of `7545d66`. P7 reports SKIP on arm64
and defers to the x64 verdict (the loader-APC-then-thread-PC ordering it
tests is arch-independent; only the hand-encoded stub differs).

### Phase 1 (AppContainer launcher) — fully validated

| Probe | Finding |
|---|---|
| P1 | A no-capability AppContainer process can bind `127.0.0.1:0` and connect to itself. The `--relay-inside` design holds. |
| P2 | AF_UNIX crosses the AppContainer boundary in **both** directions when the socket file lives in the AC's package folder. The bridge needs no `LoopbackExempt` and no admin. |
| P3 | `SetNamedSecurityInfoW` granting `(OI)(CI)` Modify to the AC SID on a directory lets the AC write there and *only* there; a sibling directory without the grant stays `EPERM`. `allowWrite` via dynamic ACLs works. |
| P4 | A plain `CreateProcess` from inside the AC produces a grandchild that is still in the AC and still subject to the same ACL enforcement. Multi-process tools (`npm → node → git`) inherit the boundary without help. |

### Phase 2 (restricted-token broker) — validated, one recipe constraint surfaced

| Probe | Finding |
|---|---|
| P5 | Restricted-token launch works (P5a = `0x0`) **only** once the initial impersonation token is built correctly — see below. The lowbox-wrapped variant (P5b) additionally requires the initial token to be lowbox-wrapped too. |
| P6 | `ntdll!NtCreateFile` can be inline-hooked in a `CREATE_SUSPENDED` child by overwriting the export prologue with an absolute jmp to a `VirtualAllocEx`'d stub; the hook fires before the target reaches `main()`. The robust stub shape is *count++ then a verbatim copy of the entire ~32-byte syscall stub* (which is self-contained, ends in `ret`, and only has PC-relative branches that stay inside the copy) — partial-prologue stealing splits the `test [SharedUserData],1` instruction and crashes. |
| P7 | A thread-context redirect (`GetThreadContext` → set PC to stub → `SetThreadContext`) runs **after** the loader APC and **before** `RtlUserThreadStart`, so a stub that calls `NtSetInformationThread(ThreadImpersonationToken, NULL)` then jumps back gives an automatic `LowerToken()` for uncooperative targets. The stub must preserve `rcx`/`rdx` (RtlUserThreadStart's entry/arg) around the call. |
| P8 | The P6 hook on `NtCreateUserProcess` fires once per grandchild spawn, so the broker can observe child creation and (combined with P6) recursively patch grandchildren. |
| P9 | `GetFinalPathNameByHandleW` returns whichever name was used to open a hardlinked file (it does *not* canonicalize to a single name); `BY_HANDLE_FILE_INFORMATION.nNumberOfLinks` reports the link count and `FindFirstFileNameW`/`FindNextFileNameW` enumerate every name. The fan-in defence in the broker's policy engine is implementable as designed. |

### The `SeTokenCanImpersonate` rule (P5 root cause)

The first three P5 attempts exited `0xC00000A5`
(`STATUS_BAD_IMPERSONATION_LEVEL`) during loader init. Root cause,
confirmed against Chromium's `sandbox_policy_base.cc::MakeTokens()` and
the post-`SetThreadToken` `CheckImpersonationToken` guard in
`broker_services.cc`:

> The kernel silently downgrades a thread's impersonation token to
> `SecurityIdentification` if it does not "match" the process token on
> three axes — **restricted vs unrestricted**, **integrity level**
> (impersonation IL must be ≤ process IL), and **AppContainer vs
> non-AppContainer**. The loader's first file open then fails with
> `STATUS_BAD_IMPERSONATION_LEVEL`.

A plain `DuplicateTokenEx` of the broker's full Medium-IL token violates
all three when the process token is a Low-IL restricted lowbox token.
The working recipe (Chromium's `USER_RESTRICTED_SAME_ACCESS`):

1. `CreateRestrictedToken(base, flags=0, deny=∅, privs=∅, restrict =
   {user SID} ∪ {every enabled group SID})` — the token is now *flagged*
   restricted while granting identical effective access.
2. `SetTokenInformation(TokenIntegrityLevel)` to the **same** IL as the
   lockdown token.
3. If the lockdown token is lowbox-wrapped, lowbox-wrap this token too
   (`NtCreateLowBoxToken` with the same package SID).
4. `DuplicateTokenEx(..., SecurityImpersonation, TokenImpersonation)`.
5. After `SetThreadToken` on the suspended child's main thread, re-open
   the thread token and assert its impersonation level is not
   `SecurityIdentification` — fail fast on a downgrade.

### Probe-implementation pitfalls (not design findings, but cost CI rounds)

- A counter `VirtualAllocEx`'d in the child's address space is
  unreadable after `WaitForSingleObject` returns — the VAS is torn down
  even though the process handle is still open. Sample it while the
  child is alive.
- `cargo run` with two `[[bin]]` entries needs `default-run`.

### Caveats

- GitHub-hosted Windows runners run as Administrator with Defender
  exclusions. Re-run on a stock non-admin Windows 11 box before relying
  on these results — `CreateProcessAsUserW` and the AppContainer ACL
  grants in particular may behave differently without
  `SeAssignPrimaryTokenPrivilege`.
- arm64 P6/P8 stubs use a literal-pool `ldr x16,#imm; str` sequence with
  hand-computed offsets; they pass on the runner but were not exercised
  beyond that.
