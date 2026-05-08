import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
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

  // Toolchain compat tests: skip the test (rather than fail) when the
  // host's toolchain install isn't reachable from inside the AC. The
  // user-installed `node.msi` and `python` Microsoft-Store-alias don't
  // grant `ALL APPLICATION PACKAGES` on their install dirs, so the AC
  // token's PATH lookup returns "not recognized". Granting that ACE
  // requires admin and is out of scope for the test suite — cf.
  // `isAcAccessible` in `helpers/windows.ts`. On hosts that DID grant
  // it (winget defaults, admin pre-stamping), these tests run.
  const nodeUsable = isToolchainUsable('node')
  const pythonUsable = isToolchainUsable('python')
  // Git for Windows ships cygwin1.dll which AVs in DllMain under our
  // lockdown token (Phase L). Even when git is on PATH and AC-readable,
  // it can't actually start. Treat it as a known-failing compat case
  // alongside the bash MSYS2 tests below.
  const gitUsable = isToolchainUsable('git') && !isCygwinGit()

  ;(nodeUsable ? test : test.skip)(
    'node prints hello',
    async () => {
      const r = await runSandboxed(`node -e "console.log('hello')"`, fx.config)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('hello')
    },
    20_000,
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

  // MSYS2/Cygwin compat is a known-failing case in this PR; tracked as
  // separate follow-up. See examples/smoke_bash.rs for the diagnostic
  // trail.
  test.skip('bash (msys2) prints hello', async () => {
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
  // Phase M will land broker-side TLS termination so curl can use
  // `--proxy http://127.0.0.1:port` with cleartext upstream and
  // bypass Schannel entirely; this skip lifts at that point.
  test.skip(
    'curl allowed domain via proxy succeeds (https — needs Phase M broker-side TLS)',
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
    'token has only SeChangeNotifyPrivilege (probe_priv.exe)',
    async () => {
      // `whoami /priv` calls LSA via `LookupPrivilegeNameW` to humanise
      // each LUID, but the lowbox token can't reach the LSA ALPC port
      // (`\RPC Control\lsasspirpc`) so `whoami` exits non-zero. We use
      // a tiny ntdll-only probe (`probe_priv.exe`, built from
      // `vendor/winsbox-src/src/bin/probe_priv.rs` and staged next to
      // `sbox-exec.exe`) that prints raw `0xHIGH:0xLOW` LUIDs without
      // the LSA round-trip. Exactly one LUID — `0x0:0x17`,
      // SeChangeNotifyPrivilege's well-known value on every shipping
      // Windows release — must appear; nothing else.
      const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
      const here = path.dirname(fileURLToPath(import.meta.url))
      const probe = path.resolve(
        here, '../..',
        'vendor', 'winsbox', arch, 'probe_priv.exe',
      )
      expect(fs.existsSync(probe)).toBe(true)
      const r = await runSandboxed(`"${probe}"`, fx.config)
      expect(r.exitCode).toBe(0)
      const luids = r.stdout
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => /^0x[0-9a-f]+:0x[0-9a-f]+$/.test(l))
      // SeChangeNotifyPrivilege LUID = (HighPart=0, LowPart=0x17).
      expect(luids).toEqual(['0x0:0x17'])
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
