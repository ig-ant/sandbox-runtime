# CI fix: broker-open `MountPointManager` for MinGW/Cygwin git

## Symptom

CI runs (both `windows-latest` x64 and `windows-11-arm` arm64) fail
`git --version` in `test/sandbox/windows.test.ts` with:

```
[sbox-exec] broker-open: REJECTED (NtCreateFile) path="MountPointManager"
                         access=0x100080 reason="not in allow list"
```

`374ec3d` (wrapper-aware `isCygwinGit`) didn't make the test skip on CI
because the resolved git binary on the CI runners isn't statically
Cygwin-linked according to our PE import probe — it's a thin
`mingw64\bin\git.exe` (x64) or `clangarm64\bin\git.exe` (arm64) that
LoadLibrary's its msys runtime instead of importing it.

## Root cause

`git --version` opens `\??\MountPointManager` during locale /
path-canonicalization with `desired_access = 0x100080`
(`FILE_READ_ATTRIBUTES | SYNCHRONIZE`). The kernel device responds
with `STATUS_ACCESS_DENIED` under our AC token (the device's DACL
grants `FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY` to standard users
but the AC's lockbox token isn't a standard user). The cdylib falls
back to broker-open, but the broker policy didn't have an entry for
`MountPointManager` so it was rejected as `not in allow list`.

Locally on the dev box this rejection is non-fatal — the host's git
treats the canonicalisation failure as "no mount info available" and
exits 0. On CI runners the same rejection bubbles up to a non-zero
exit, failing the `expect(r.exitCode).toBe(0)` assertion.

## Why locally we couldn't repro the failure

Local `WINSBOX_TRACE_SYSCALLS=1 bun test -t "git --version"` shows
the broker rejection but `target exit=0x0`. Different MinGW git build
flavor / different runtime startup ordering of `MountPointManager`
relative to other locale syscalls. The fix below resolves both — CI
fails because of the rejection, the local box was always one bug-flag
flip away from the same outcome.

## Fix (Approach C — broker allow + don't widen test gate)

`vendor/winsbox-src/src/broker_open.rs`:

1. Added `READ_ONLY_KERNEL_DEVICES` const list (initial entry:
   `mountpointmanager`) — system-wide kernel devices we permit
   read-only opens against. Differs from the existing
   `RESERVED_DOS_DEVICES` list (which covers per-process pseudo-files
   like `nul` / `con`) because these devices have system-wide state
   and a different security shape.
2. `is_path_allowed_for_broker_open` now short-circuits to `Allow`
   when the normalised path matches a kernel device AND the access
   mask doesn't request writes. Match is against the **whole
   normalised path** (no drive letter — kernel devices come through
   `normalize_nt_path(\??\MountPointManager)` as just
   `"MountPointManager"`), so a real-FS file under an allow tree
   like `C:\fixture\base\MountPointManager` doesn't accidentally
   short-circuit.
3. Exposed `is_read_only_kernel_device(path)` for the broker's open
   reissue path.

`vendor/winsbox-src/src/launch.rs::handle_broker_open` (≈ line 1545):

The broker normally widens caller-requested read access to
`desired_access | GENERIC_READ` so loader-style `EXECUTE+READ` opens
succeed. `MountPointManager`'s DACL doesn't grant `GENERIC_READ` (only
the narrower `FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY`), so adding
that bit makes the broker's own `NtCreateFile` reissue fail with
`STATUS_ACCESS_DENIED`. Skip the widening when the path is a
read-only kernel device.

## Test changes

`vendor/winsbox-src/src/broker_open.rs::tests`: 4 new unit tests:

- `read_only_kernel_devices_allow_reads` — `MountPointManager` (mixed
  case, plus the actual `0x100080` mask `git --version` uses) is
  granted.
- `read_only_kernel_devices_reject_writes` — `FILE_WRITE_DATA` and
  `GENERIC_WRITE` against `MountPointManager` reject as
  `NotInAllowList` (no separate reason code; treated like any
  unrecognised path).
- `read_only_kernel_devices_do_not_match_real_fs_paths` — a path
  with a drive prefix whose leaf is `MountPointManager` is NOT
  device-classified; falls through to standard policy.
- `deny_read_with_kernel_device_leaf_still_denied` — a denyRead path
  whose leaf is `MountPointManager` is still denied.

`cargo test --lib`: 23 → 27 (4 new, all pass).

## Threat model

`\Device\MountPointManager` is a kernel device that responds to
IOCTLs to query (or modify, with privilege) mount-point metadata.
Risk surface added by allowing a broker-mediated read-only open:

- **Read IOCTLs** (`IOCTL_MOUNTMGR_QUERY_POINTS`,
  `IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH`, ...): enumerate
  drive-letter ↔ volume-GUID mappings. Same data any authenticated
  user can already retrieve via `mountvol` / `Get-Volume`. No file
  contents, no ACLs, no secrets.
- **Write IOCTLs** (`IOCTL_MOUNTMGR_CREATE_POINT`,
  `IOCTL_MOUNTMGR_DELETE_POINTS`): require admin privilege. Even
  with a brokered handle the kernel filters at IOCTL dispatch time
  based on `GrantedAccess`. We open with the caller's exact mask
  (`FILE_READ_ATTRIBUTES | SYNCHRONIZE`), so the resulting handle
  can't dispatch any of these — the AC would get
  `STATUS_INVALID_DEVICE_REQUEST` or `STATUS_ACCESS_DENIED`.

Net: this widens the broker surface by exactly one read-only kernel
device whose data is already visible to standard users. denyRead /
denyWrite security boundaries remain intact (verified by the
`deny_read_with_kernel_device_leaf_still_denied` test and the
`bun test -t "read from denyRead is denied"` integration test).

## Local verification

```
$ cargo test --lib
27 passed; 0 failed

$ cargo build --release          # clean
$ cargo run --example smoke_cdylib       # target exit=0x0
$ cargo run --example smoke_broker_open  # SOFT-PASS as before

$ bun test test/sandbox/windows.test.ts
17 pass / 5 skip / 0 fail   (matches prior baseline)

$ WINSBOX_TRACE_SYSCALLS=1 bun test -t "git --version" \
    test/sandbox/windows.test.ts
[sbox-exec] broker-open: GRANTED (NtCreateFile)
                         path="MountPointManager"
                         canonical="MountPointManager"
                         access=0x100080 handle=0x134
[sbox-exec] target exit=0x0
1 pass
```

## Other devices likely to surface

If the next CI run reveals a different rejected device, the fix is
mechanical: add it to `READ_ONLY_KERNEL_DEVICES` and verify the same
threat-model checks (read-only IOCTLs, no admin-only data
exposure). Candidates known to be touched by MinGW/Cygwin
canonicalization:

- `KsecDD` — registry / crypto stack. Read IOCTLs only; write
  IOCTLs require kernel-mode caller (driver). Safe.
- `NamedPipe` — RPC / pipe enumeration. Listing pipes is benign
  (any user can do it via NtQueryDirectoryFile on the device).
- `DeviceApi` — kernel-mode plug-and-play API. Read IOCTLs only.

For the immediate failure mode only `MountPointManager` is needed;
adding the others proactively widens our surface without a confirmed
caller. Defer until/unless CI surfaces them.
