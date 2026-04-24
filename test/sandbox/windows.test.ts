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
  // Mark interception-dependent since:'2' tests as TODO until 2b.
  const BROKER_FS_LANDED = false

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

  compat('curl.exe --version', 'stub', async () => {
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

  compat('curl allowed domain via proxy succeeds', 'stub', async () => {
    const r = await runSandboxed(
      'curl.exe -sSI https://example.com/',
      fx.config,
    )
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toMatch(/HTTP\/[\d.]+ [23]\d\d/)
  })

  toolCompat(
    'npm view (multi-process + network) succeeds',
    toolPhase,
    async () => {
      const r = await runSandboxed('npm view lodash version', {
        ...fx.config,
        network: {
          allowedDomains: ['registry.npmjs.org', '*.npmjs.org'],
          deniedDomains: [],
        },
      })
      expect(r.exitCode).toBe(0)
      expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/)
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
    expect(r.durationMs).toBeLessThan(1000)
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

  compat('whoami /priv shows only SeChangeNotify', '2', async () => {
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
      const r = await runSandboxed(
        'curl.exe -sS --noproxy "*" --max-time 8 -o NUL -w "%{http_code}" https://example.org/',
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
