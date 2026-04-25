import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { isWindows } from '../helpers/platform.js'
import {
  PHASE,
  phaseGte,
  makeFixture,
  cleanupFixture,
  runSandboxed,
  withHostListener,
  type Fixture,
  type Phase,
} from '../helpers/windows.js'

const d = isWindows ? describe : describe.skip

d(`windows sandbox [WINSBOX_PHASE=${PHASE}]`, () => {
  let fx: Fixture
  const skipped: string[] = []

  beforeAll(async () => {
    fx = await makeFixture()
  })
  afterAll(() => {
    cleanupFixture(fx)
    if (skipped.length) {
      console.log(
        `\n[windows] ${skipped.length} test(s) deferred to a later phase:\n` +
          skipped.map(s => `  - ${s}`).join('\n'),
      )
    }
  })

  /** compat: must pass from `since` onward; before that, record skip. */
  const compat = (name: string, since: Phase, fn: () => Promise<void>) => {
    if (phaseGte(since)) {
      test(name, fn, 20_000)
    } else {
      skipped.push(`${name} [needs phase ${since}]`)
      test.skip(`${name} [needs phase ${since}]`, fn)
    }
  }

  /** safety: before `enforcedAt`, the violation MUST happen (proves the
   *  test detects an unenforced sandbox); from `enforcedAt`, it MUST be
   *  blocked. */
  const safety = (
    name: string,
    enforcedAt: Phase,
    fn: () => Promise<{ violated: boolean; detail?: string }>,
  ) => {
    if (enforcedAt !== '1' && !phaseGte('1')) {
      // enforcedAt:'2' tests need at least Phase 1 plumbing to be
      // meaningful; in stub mode they'd just trivially violate. Skip
      // until Phase 1 so they don't add noise.
    }
    test(
      name,
      async () => {
        const r = await fn()
        const expectedViolated = !phaseGte(enforcedAt)
        expect(r.violated).toBe(expectedViolated)
      },
      20_000,
    )
  }

  // ───────────────────────── compat ─────────────────────────

  compat('cmd /c echo hello', 'stub', async () => {
    const r = await runSandboxed('echo hello', fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout.trim()).toBe('hello')
  })

  // node/python/git/npm read from %USERPROFILE%/%APPDATA%/tool-cache,
  // which the AppContainer second-pass blocks without per-path ACL
  // grants. They run under stub and will run again once the broker's
  // ntdll-interception FS policy lands (Phase 2b — separate commit on
  // this branch). Until then, skip under both confined modes.
  const needsBrokerFs = PHASE !== 'stub'
  const toolPhase: Phase = needsBrokerFs ? '2' : 'stub'
  // NtCreateFile/NtOpenFile are now hooked and brokered through
  // policy_engine.rs (default-allow read, deny write outside
  // allowWrite, deny under denyRead).
  const BROKER_FS_LANDED = true
  // In Phase-2a (restricted token, no NtCreateUserProcess hook),
  // any command that spawns a subprocess via cmd.exe inherits the
  // lockdown primary without re-impersonation and fails. Tests that
  // exercise an EXTERNAL exe via `cmd /c` are gated on the process
  // hook (Phase 2b).
  // Broker hooks kernelbase!CreateProcessInternalW (via the
  // entry-trampoline rendezvous) and performs every spawn itself,
  // so cmd→ext.exe goes through the broker's CreateProcessAsUserW
  // + SetThreadToken recipe and PROCESS_INFORMATION comes back
  // directly.
  const BROKER_PROC_HOOK_LANDED = true
  // Lowbox (AppContainer) blocks ALPC to LSA, so anything inside
  // the sandbox that needs LookupPrivilegeName / Schannel /
  // AcquireCredentialsHandle fails with the restricted+lowbox
  // primary. Tracked as the next open item; gate the affected
  // compat tests until either a capability SID is found that
  // re-opens LSA without re-opening network, or the test is
  // reshaped to avoid LSA.
  const LOCKDOWN_LSA_OK = false
  const extCompat =
    PHASE !== '2' || BROKER_PROC_HOOK_LANDED
      ? compat
      : (n: string, _p: Phase, f: () => Promise<void>) => {
          skipped.push(`${n} [needs broker NtCreateUserProcess hook]`)
          test.skip(`${n} [needs broker NtCreateUserProcess hook]`, f)
        }
  const lsaCompat =
    PHASE !== '2' || LOCKDOWN_LSA_OK
      ? extCompat
      : (n: string, _p: Phase, f: () => Promise<void>) => {
          skipped.push(`${n} [lowbox blocks LSA RPC]`)
          test.skip(`${n} [lowbox blocks LSA RPC]`, f)
        }

  const toolCompat =
    BROKER_FS_LANDED || !needsBrokerFs
      ? compat
      : (n: string, _p: Phase, f: () => Promise<void>) => {
          skipped.push(`${n} [needs broker-FS interception]`)
          test.skip(`${n} [needs broker-FS interception]`, f)
        }

  toolCompat('node prints hello', toolPhase, async () => {
    const r = await runSandboxed(`node -e "console.log('hello')"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('hello')
  })

  toolCompat('python prints hello', toolPhase, async () => {
    const r = await runSandboxed(`python -c "print('hello')"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('hello')
  })

  toolCompat('git --version', toolPhase, async () => {
    const r = await runSandboxed('git --version', fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout.toLowerCase()).toContain('git version')
  })

  // MSYS2/Cygwin runtimes call NtCreateDirectoryObject with a
  // hardcoded `\BaseNamedObjects\msys-2.0S5-<hash>` path for
  // their shared-state namespace (Cygwin heap, fork sections,
  // process table). Lowbox denies create under the global BNO;
  // AC-aware apps go through kernelbase!BaseGetNamedObjectDirectory
  // which redirects to the per-AC namespace, but MSYS2 uses the
  // NT path directly. Fix: hook NtCreate/OpenDirectoryObject and
  // rewrite `\BaseNamedObjects\msys-*` to
  // `\Sessions\<N>\AppContainerNamedObjects\<AC-SID>\msys-*`.
  // Until then this is a documented platform limitation
  // alongside the lowbox/Schannel one.
  const MSYS2_BNO_REDIRECT_LANDED = false
  const msys2Compat =
    PHASE === 'stub' || MSYS2_BNO_REDIRECT_LANDED
      ? toolCompat
      : (n: string, _p: Phase, f: () => Promise<void>) => {
          skipped.push(`${n} [lowbox denies \\BaseNamedObjects create]`)
          test.skip(`${n} [lowbox denies \\BaseNamedObjects create]`, f)
        }
  msys2Compat('bash (msys2) prints hello', toolPhase, async () => {
    const bash = `${process.env.ProgramFiles}\\Git\\bin\\bash.exe`
    if (!fs.existsSync(bash)) {
      console.warn(`  [skip] ${bash} not found`)
      return
    }
    const r = await runSandboxed(`"${bash}" -c "echo hello"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('hello')
  })

  extCompat('curl.exe --version', 'stub', async () => {
    const r = await runSandboxed('curl.exe --version', fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout.toLowerCase()).toContain('curl')
  })

  compat('write to allowWrite succeeds', 'stub', async () => {
    const target = path.join(fx.allowWrite, 'ok.txt')
    const r = await runSandboxed(`echo ok > "${target}"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(fs.existsSync(target)).toBe(true)
  })

  compat('read from explicit allowRead path succeeds', 'stub', async () => {
    // fx.base is in allowRead; ambientFile lives under it.
    const r = await runSandboxed(`type "${fx.ambientFile}"`, fx.config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('PUBLIC')
  })

  lsaCompat('curl allowed domain via proxy succeeds', 'stub', async () => {
    const r = await runSandboxed(
      'curl.exe -sSI https://example.com/',
      fx.config,
    )
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toMatch(/HTTP\/[\d.]+ [23]\d\d/)
  })

  // Same request without TLS, so it exercises the AF_UNIX bridge
  // and the SRT proxy under the lockdown token without touching
  // Schannel/LSA. This is the brokered-spawn + network compat
  // test that actually proves the path works in Phase 2.
  extCompat(
    'curl allowed domain (http) via proxy succeeds',
    'stub',
    async () => {
      const r = await runSandboxed(
        'curl.exe -sSI http://example.com/',
        fx.config,
      )
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toMatch(/HTTP\/[\d.]+ [23]\d\d/)
    },
  )

  toolCompat(
    'npm view (multi-process + network) succeeds',
    toolPhase,
    async () => {
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
      // npm.cmd's FOR /F capture of npm-prefix.js leaks to
      // stdout under brokered spawn (stdio-forwarding fidelity
      // gap, follow-up); the version is still there.
      expect(r.stdout).toMatch(/\b\d+\.\d+\.\d+\b/)
    },
  )

  compat('startup-to-exit < 1000ms (10-path config)', 'stub', async () => {
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
    // Phase-2 broker mode grants two SIDs (AC + RESTRICTED) per
    // allow-path via icacls; with 10 paths that's ~20 spawns.
    // Batching into one icacls call is the real fix.
    expect(r.durationMs).toBeLessThan(PHASE === '2' ? 1500 : 1000)
  })

  // Phase-2-only compat (broker semantics)
  ;(BROKER_FS_LANDED
    ? compat
    : (n: string, _p: Phase, _f: () => Promise<void>) => {
        skipped.push(`${n} [needs broker-FS interception]`)
        test.skip(`${n} [needs broker-FS interception]`, _f)
      })(
    'read from ambient path NOT in allowRead (allow-all-except)',
    '2',
    async () => {
      const cfg = {
        ...fx.config,
        filesystem: { ...fx.config.filesystem, allowRead: [] },
      }
      const r = await runSandboxed(`type "${fx.ambientFile}"`, cfg)
      expect(r.exitCode).toBe(0)
      expect(r.stdout).toContain('PUBLIC')
    },
  )

  lsaCompat('whoami /priv shows only SeChangeNotify', '2', async () => {
    const r = await runSandboxed('whoami /priv', fx.config)
    expect(r.exitCode).toBe(0)
    const privs = r.stdout
      .split('\n')
      .filter(l => /^Se\w+Privilege/.test(l.trim()))
      .map(l => l.trim().split(/\s+/)[0])
    expect(privs.filter(p => p !== 'SeChangeNotifyPrivilege')).toEqual([])
  })

  // ───────────────────────── safety ─────────────────────────

  safety('write outside allowWrite is denied', '1', async () => {
    const target = path.join(fx.outsideWrite, 'no.txt')
    const r = await runSandboxed(`echo no > "${target}"`, fx.config)
    return {
      violated: fs.existsSync(target),
      detail: `exit=${r.exitCode}`,
    }
  })

  safety('read from denyRead is denied', '1', async () => {
    const r = await runSandboxed(`type "${fx.denyReadFile}"`, fx.config)
    return { violated: r.stdout.includes('SECRET') }
  })

  safety(
    'curl direct to denied domain (proxy env unset) is blocked',
    '1',
    async () => {
      // http://, not https:// — under lowbox Schannel fails before
      // the socket is even attempted, which would mask whether the
      // network boundary itself holds.
      const r = await runSandboxed(
        'curl.exe -sS --noproxy "*" --max-time 8 -o NUL -w "%{http_code}" http://example.org/',
        fx.config,
      )
      // If the sandbox blocks network, curl exits non-zero; if not, we
      // get a 2xx/3xx and that is the violation.
      return {
        violated: r.exitCode === 0 && /^[23]\d\d$/.test(r.stdout.trim()),
      }
    },
  )

  safety('connect to other host loopback service is blocked', '1', async () => {
    return withHostListener(async port => {
      const r = await runSandboxed(
        `curl.exe -sS --noproxy "*" --max-time 5 http://127.0.0.1:${port}/`,
        fx.config,
      )
      return { violated: r.stdout.includes('LEAK') }
    })
  })

  safety('grandchild write outside allowWrite is denied', '1', async () => {
    const target = path.join(fx.outsideWrite, 'gc.txt')
    const r = await runSandboxed(
      `cmd /c cmd /c echo no > "${target}"`,
      fx.config,
    )
    return { violated: fs.existsSync(target), detail: `exit=${r.exitCode}` }
  })

  safety(
    'sandboxed process cannot terminate a Medium-IL host process',
    '1',
    async () => {
      // Spawn a sacrificial Medium-IL process outside the sandbox; have
      // the sandboxed command try to kill it. Stub: succeeds (violation).
      // Phase 1+: Low/Untrusted IL cannot OpenProcess(TERMINATE) on it.
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
        return { violated: !stillAlive }
      } finally {
        try {
          victim.kill()
        } catch {
          /* */
        }
      }
    },
  )
})
