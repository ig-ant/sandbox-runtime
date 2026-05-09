import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { isWindows } from '../helpers/platform.js'
import {
  makeFixture,
  cleanupFixture,
  isCygwinGit,
  isToolchainUsable,
  runSandboxed,
  withHostListener,
  type Fixture,
} from '../helpers/windows.js'

const d = isWindows ? describe : describe.skip

d('windows sandbox', () => {
  let fx: Fixture

  beforeAll(async () => {
    fx = await makeFixture()
  })
  afterAll(() => {
    cleanupFixture(fx)
  })

  // ───────────────────────── compat (native-PE) ─────────────────────────

  test(
    'cmd /c echo hello',
    async () => {
      const r = await runSandboxed('echo hello', fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout.trim()).toBe('hello')
    },
    20_000,
  )

  // Phase N-2 Part B (D-4 lift): nested cmd spawn — the immediate
  // target is `cmd /c <command>`, the immediate target's CPW hook
  // brokers the inner `cmd /c echo hello` spawn, the broker injects
  // cdylib into the inner cmd, the inner cmd's CPW hook brokers
  // `echo hello` (a builtin so no further fork — but the recursion
  // through one level is exercised). Verify no hang / deadlock under
  // recursive injection.
  test(
    'recursive cmd spawn (cmd /c cmd /c echo hi)',
    async () => {
      const r = await runSandboxed('cmd /c echo hi', fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout.trim()).toBe('hi')
    },
    20_000,
  )

  // Toolchain compat tests.
  //
  // Phase N-2 Part B (D-4 lift) made cdylib injection extend to
  // grandchildren: when `cmd /c node ...` runs, cmd's PATH walk reaches
  // node via broker-mediated NtCreateFile (auto-toolchain-allowed
  // `C:\Program Files\nodejs`), then cmd brokers the node spawn via
  // its CPW hook → broker manual-maps the cdylib into node, hooks
  // node's syscalls, and node's own DLL loads (out of `Program Files\
  // nodejs`) flow through the broker too. So the host no longer
  // strictly needs `ALL APPLICATION PACKAGES` on the toolchain dir
  // for these tests to work — the broker mediates.
  //
  // Python's Windows-Store alias (under `\Microsoft\WindowsApps\`) is
  // a UWP redirector that needs package activation our token can't
  // reach; gate that one on a real toolchain install via PATH.
  const pythonUsable = isToolchainUsable('python')
  // Git for Windows ships cygwin1.dll. Native ARM64 git binaries are
  // not statically Cygwin-linked (verified via `isCygwinBinary`).
  // Run the test iff git is on PATH AND not a Cygwin runtime binary.
  // Native git on this host runs grandchild-cdylib-injected with
  // broker-mediated `\??\nul` (= /dev/null) per Phase N-2 Part B.
  const gitUsable = isToolchainUsable('git') && !isCygwinGit()

  test(
    'node prints hello',
    async () => {
      const r = await runSandboxed(`node -e "console.log('hello')"`, fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('hello')
    },
    25_000,
  )

  ;(pythonUsable ? test : test.skip)(
    'python prints hello',
    async () => {
      const r = await runSandboxed(`python -c "print('hello')"`, fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('hello')
    },
    20_000,
  )

  ;(gitUsable ? test : test.skip)(
    'git --version',
    async () => {
      const r = await runSandboxed('git --version', fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout.toLowerCase()).toContain('git version')
    },
    20_000,
  )

  // MSYS2/Cygwin compat. The bash chain goes
  //   `cmd /c bash.exe` (Git\bin) → `bash.exe` (Git\usr\bin) → echo,
  // crossing arch on ARM64 hosts (Git\bin\bash.exe is ARM64,
  // Git\usr\bin\bash.exe is x64) — the cdylib's grandchild
  // injection bails on cross-arch and Cygwin AVs in DllMain. On
  // x64 hosts every link is x64 so the cdylib injects through the
  // chain. Gate on host arch until per-arch broker shipping
  // (N-7) lands.
  const bashCompat = process.arch === 'arm64' ? test.skip : test
  bashCompat('bash (msys2) prints hello', async () => {
    const bash = `${process.env.ProgramFiles}\\Git\\bin\\bash.exe`
    if (!fs.existsSync(bash)) {
      console.warn(`  [skip] ${bash} not found`)
      return
    }
    const r = await runSandboxed(`"${bash}" -c "echo hello"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('hello')
  })

  // MSYS2/Cygwin compat is a known-failing case in this PR; tracked as
  // separate follow-up. See examples/smoke_bash.rs for the diagnostic
  // trail.
  test.skip('bash (msys2) ls | head', async () => {
    const bash = `${process.env.ProgramFiles}\\Git\\bin\\bash.exe`
    if (!fs.existsSync(bash)) {
      console.warn(`  [skip] ${bash} not found`)
      return
    }
    const r = await runSandboxed(
      `"${bash}" -c "ls /usr/bin | head -3"`,
      fx.config,
    )
    expect(r.exitCode).toBe(0)
    expect(r.stdout.trim().split(/\r?\n/).length).toBeGreaterThanOrEqual(1)
  })

  test(
    'curl.exe --version',
    async () => {
      const r = await runSandboxed('curl.exe --version', fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout.toLowerCase()).toContain('curl')
    },
    20_000,
  )

  test(
    'write to allowWrite succeeds',
    async () => {
      const target = path.join(fx.allowWrite, 'ok.txt')
      const r = await runSandboxed(`echo ok > "${target}"`, fx.config)
      expect(r.exitCode).toBe(0)
      expect(fs.existsSync(target)).toBe(true)
    },
    20_000,
  )

  test(
    'read from explicit allowRead path succeeds',
    async () => {
      // fx.base is in allowRead; ambientFile lives under it.
      const r = await runSandboxed(`type "${fx.ambientFile}"`, fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('PUBLIC')
    },
    20_000,
  )

  // HTTPS via Schannel needs LSA (Schannel is implemented as an
  // LSA SSP), and the lowbox can't reach the LSA ALPC port — see
  // `examples/smoke_bash.rs` Phase L header for the full diagnostic.
  // The HTTP variant below passes, which proves the AF_UNIX bridge
  // and the SRT proxy work; HTTPS specifically needs Schannel.
  //
  // Phase N-4 retest (2026-05-09): N-2's broker-mediated NtCreateFile
  // / NtOpenFile does NOT close this case. The trace span inside the
  // curl grandchild between cdylib injection and the schannel error
  // contains zero denied filesystem / registry / pipe / ALPC syscalls
  // before `AcquireCredentialsHandle → SEC_E_NO_CREDENTIALS
  // (0x8009030e)`. The default outbound `AcquireCredentialsHandle(
  // UNISP/SCHANNEL, SECPKG_CRED_OUTBOUND, NULL pAuthData)` should
  // always succeed on a sane Windows install (no client cert is
  // needed for outbound TLS); the synthetic `NO_CREDENTIALS` reply
  // means schannel's LSA-side package state is broken inside the
  // per-AC LSA endpoint — there is no brokerable user-mode syscall
  // to mediate. Plan finding E (fundamentally unbrokerable).
  //
  // Path forward: broker-side TLS termination (MITM proxy). Broker
  // generates a session CA via rcgen, installs with `certutil -user
  // -addstore Root`, and the existing `netbridge.rs` HTTP CONNECT
  // path becomes a TLS terminator signing per-domain certs. Curl in
  // the AC then sees plaintext upstream and never engages Schannel.
  // Deferred to a separate phase (~300 LOC + rcgen dep) — see trace
  // at `docs/curl_https_trace_n4.log` and the deferral note in
  // `plans/winsbox-phase-n.md` Phase N-4 / fallback section.
  test.skip(
    'curl allowed domain via proxy succeeds (https — deferred, see Phase O MITM)',
    async () => {
      const r = await runSandboxed(
        'curl.exe -sSI https://example.com/',
        fx.config,
      )
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toMatch(/HTTP\/[\d.]+ [23]\d\d/)
    },
    20_000,
  )

  // Same request without TLS, so it exercises the AF_UNIX bridge
  // and the SRT proxy under the lockdown token without touching
  // Schannel/LSA.
  test(
    'curl allowed domain (http) via proxy succeeds',
    async () => {
      const r = await runSandboxed(
        'curl.exe -sSI http://example.com/',
        fx.config,
      )
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toMatch(/HTTP\/[\d.]+ [23]\d\d/)
    },
    20_000,
  )

  // MSYS2/Cygwin compat is a known-failing case in this PR; tracked as
  // separate follow-up. See examples/smoke_bash.rs for the diagnostic
  // trail. (npm.cmd shells out via cmd.exe to node.exe, but its
  // post-install scripts call sh.exe from MSYS2 and hit the same
  // section/dirobj path as bash.)
  test.skip('npm view (multi-process + network) succeeds', async () => {
    // npm caches the registry response; point its cache at
    // allowWrite so the broker doesn't (correctly) deny it.
    const npmCache = path.join(fx.allowWrite, 'npm-cache')
    const r = await runSandboxed(
      `cmd /c "set NPM_CONFIG_CACHE=${npmCache}&& npm view lodash version"`,
      {
        ...fx.config,
        network: {
          allowedDomains: ['registry.npmjs.org', '*.npmjs.org'],
          deniedDomains: [],
        },
      },
    )
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toMatch(/\b\d+\.\d+\.\d+\b/)
  })

  test(
    'startup-to-exit < 1500ms (10-path config)',
    async () => {
      const cfg = {
        ...fx.config,
        filesystem: {
          ...fx.config.filesystem,
          allowWrite: Array.from({ length: 10 }, (_, i) =>
            path.join(fx.allowWrite, `d${i}`),
          ),
        },
      }
      const r = await runSandboxed('echo ok', cfg)
      expect(r.exitCode).toBe(0)
      // ACL stamping does a single TreeSetNamedSecurityInfo per root
      // (not N icacls spawns); 10 paths should still come in under
      // 1500ms with a warm manifest.
      expect(r.durationMs).toBeLessThan(1500)
    },
    20_000,
  )

  test(
    'read from ambient path NOT in allowRead (allow-all-except)',
    async () => {
      const cfg = {
        ...fx.config,
        filesystem: { ...fx.config.filesystem, allowRead: [] },
      }
      const r = await runSandboxed(`type "${fx.ambientFile}"`, cfg)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('PUBLIC')
    },
    20_000,
  )

  test(
    'whoami /priv shows only SeChangeNotifyPrivilege',
    async () => {
      // `whoami /priv` calls LSA via `LookupPrivilegeNameW` to humanise
      // each LUID. Earlier we worked around an LSA wall by using a
      // ntdll-only probe; the real wall was actually the broker's
      // grandchild SetThreadToken layering USER_RESTRICTED_SAME_ACCESS
      // on top of the lowbox primary, whose restricting-SID set
      // (user + enabled groups, no Everyone) intersected against
      // LSA's per-AC RPC endpoint DACL (grants Everyone) to a null
      // pass. Dropping the redundant impersonation lets LSA through.
      //
      // PATH ordering matters too: the broker now prepends
      // `%SystemRoot%\System32` to PATH (windows-sandbox-utils.ts) so
      // bare `whoami` resolves to the native System32 binary, not
      // Git-for-Windows' Cygwin shim (which AVs in cygwin1.dll's
      // DllMain — Phase L wall 1).
      const r = await runSandboxed('whoami /priv', fx.config)
      expect(r.exitCode).toBe(0)
      // Exactly one privilege is expected on the lockdown token; assert
      // its presence and that no other Se*Privilege is visible.
      expect(r.stdout).toMatch(/SeChangeNotifyPrivilege/)
      const otherPrivs = r.stdout
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => /^Se\w+Privilege\b/.test(l))
        .filter(l => !l.startsWith('SeChangeNotifyPrivilege'))
      expect(otherPrivs).toEqual([])
    },
    20_000,
  )

  // ───────────────────────── safety ─────────────────────────

  test(
    'write outside allowWrite is denied',
    async () => {
      const target = path.join(fx.outsideWrite, 'no.txt')
      await runSandboxed(`echo no > "${target}"`, fx.config)
      expect(fs.existsSync(target)).toBe(false)
    },
    20_000,
  )

  test(
    'read from denyRead is denied',
    async () => {
      const r = await runSandboxed(`type "${fx.denyReadFile}"`, fx.config)
      expect(r.stdout.includes('SECRET')).toBe(false)
    },
    20_000,
  )

  test(
    'curl direct to denied domain (proxy env unset) is blocked',
    async () => {
      // http://, not https:// — under lowbox Schannel fails before
      // the socket is even attempted, which would mask whether the
      // network boundary itself holds.
      const r = await runSandboxed(
        'curl.exe -sS --noproxy "*" --max-time 8 -o NUL -w "%{http_code}" http://example.org/',
        fx.config,
      )
      const violated = r.exitCode === 0 && /^[23]\d\d$/.test(r.stdout.trim())
      expect(violated).toBe(false)
    },
    20_000,
  )

  test(
    'connect to other host loopback service is blocked',
    async () => {
      await withHostListener(async port => {
        const r = await runSandboxed(
          `curl.exe -sS --noproxy "*" --max-time 5 http://127.0.0.1:${port}/`,
          fx.config,
        )
        expect(r.stdout.includes('LEAK')).toBe(false)
      })
    },
    20_000,
  )

  test(
    'grandchild write outside allowWrite is denied',
    async () => {
      const target = path.join(fx.outsideWrite, 'gc.txt')
      await runSandboxed(`cmd /c cmd /c echo no > "${target}"`, fx.config)
      expect(fs.existsSync(target)).toBe(false)
    },
    20_000,
  )

  test(
    'sandboxed process cannot terminate a Medium-IL host process',
    async () => {
      // Spawn a sacrificial Medium-IL process outside the sandbox; have
      // the sandboxed command try to kill it. Low/Untrusted IL cannot
      // OpenProcess(TERMINATE) on a Medium-IL target.
      const { spawn } = await import('node:child_process')
      const victim = spawn(
        'powershell',
        ['-NoProfile', '-Command', 'Start-Sleep -Seconds 30'],
        { stdio: 'ignore' },
      )
      const vpid = victim.pid!
      try {
        await runSandboxed(`taskkill /F /PID ${vpid}`, fx.config)
        // Give the victim a moment to die if the kill landed.
        await new Promise(r => setTimeout(r, 300))
        const stillAlive = victim.exitCode === null && !victim.killed
        expect(stillAlive).toBe(true)
      } finally {
        try {
          victim.kill()
        } catch {
          /* */
        }
      }
    },
    20_000,
  )
})
