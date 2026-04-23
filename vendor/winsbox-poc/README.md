# winsbox-poc

Throwaway probes that empirically validate the OS-behaviour assumptions
behind the Windows sandbox design before any of it is built. Each probe
answers one binary question; `cargo run -- all` runs the lot and writes
`RESULTS.md`.

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

A `FAIL` verdict is data, not a CI failure — it triggers the documented
pivot for that probe. Only an `ERROR` (probe crashed) returns non-zero.

This crate is deleted once the real `winsbox-src` lands.
