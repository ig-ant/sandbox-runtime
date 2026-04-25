import { spawn } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as net from 'node:net'
import { SandboxManager } from '../../src/index.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

export type Phase = 'stub' | '1' | '2'
const ORDER: Phase[] = ['stub', '1', '2']
export const PHASE: Phase = ((): Phase => {
  const v = process.env.WINSBOX_PHASE
  return v === '1' || v === '2' ? v : 'stub'
})()
export const phaseGte = (p: Phase): boolean =>
  ORDER.indexOf(PHASE) >= ORDER.indexOf(p)

export interface RunResult {
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
}

export interface Fixture {
  base: string
  allowWrite: string
  outsideWrite: string
  denyRead: string
  denyReadFile: string
  ambientRead: string
  ambientFile: string
  config: SandboxRuntimeConfig
}

export async function makeFixture(): Promise<Fixture> {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-win-'))
  const allowWrite = path.join(base, 'allowWrite')
  const outsideWrite = path.join(base, 'outsideWrite')
  const denyRead = path.join(base, 'denyRead')
  const ambientRead = path.join(base, 'ambient')
  for (const d of [allowWrite, outsideWrite, denyRead, ambientRead]) {
    fs.mkdirSync(d, { recursive: true })
  }
  const denyReadFile = path.join(denyRead, 'secret.txt')
  fs.writeFileSync(denyReadFile, 'SECRET')
  const ambientFile = path.join(ambientRead, 'public.txt')
  fs.writeFileSync(ambientFile, 'PUBLIC')

  const config: SandboxRuntimeConfig = {
    network: {
      // example.com is in allowedDomains so the proxy lets it through;
      // anything else is denied at the proxy.
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      // Phase-1 AC is deny-read-by-default, so allowRead must cover the
      // tool install dirs + USERPROFILE for the compat tests (see plan
      // §"known Phase-1 limitation"). Phase 2 ignores allowRead and
      // applies allow-all-except-denyRead.
      // Phase-1 ACL grants propagate to every existing child, so
      // broad roots (USERPROFILE, Program Files) take minutes. Keep
      // allowRead to the small fixture tree only; system dirs are
      // already ACL'd to ALL APPLICATION PACKAGES. Compat tests that
      // need user-profile reads are tagged since:'2'.
      allowRead: [base],
      denyRead: [denyRead],
      allowWrite: [allowWrite],
      denyWrite: [],
    },
  }
  return {
    base,
    allowWrite,
    outsideWrite,
    denyRead,
    denyReadFile,
    ambientRead,
    ambientFile,
    config,
  }
}

export function cleanupFixture(f: Fixture): void {
  try {
    fs.rmSync(f.base, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
}

export async function runSandboxed(
  command: string,
  config: SandboxRuntimeConfig,
  opts: { timeoutMs?: number } = {},
): Promise<RunResult> {
  await SandboxManager.reset()
  await SandboxManager.initialize(config)
  const wrapped = await SandboxManager.wrapWithSandbox(command)
  const start = Date.now()
  return new Promise(resolve => {
    const child = spawn(wrapped, { shell: true })
    let stdout = ''
    let stderr = ''
    let done = false
    child.stdout?.on('data', d => (stdout += d.toString()))
    child.stderr?.on('data', d => (stderr += d.toString()))
    const finish = (code: number) => {
      if (done) return
      done = true
      clearTimeout(to)
      SandboxManager.cleanupAfterCommand()
      // Surface broker diagnostics in the bun test output.
      if (stderr.trim()) {
        for (const l of stderr.split(/\r?\n/)) {
          if (l.trim()) console.error(`  [stderr] ${l}`)
        }
      }
      if (code < 0)
        console.error(
          `  [timeout/error] exit=${code} stdout=${JSON.stringify(stdout.slice(0, 200))}`,
        )
      resolve({
        exitCode: code,
        stdout,
        stderr,
        durationMs: Date.now() - start,
      })
    }
    const to = setTimeout(() => {
      // child.kill() only kills the cmd.exe wrapper; sbox-exec and its
      // tree survive and keep the pipes open. Kill the whole tree.
      if (child.pid) {
        spawn('taskkill', ['/T', '/F', '/PID', String(child.pid)], {
          stdio: 'ignore',
        })
      }
      // Resolve immediately on timeout regardless of pipe state.
      finish(-2)
    }, opts.timeoutMs ?? 18_000)
    child.on('exit', code => finish(code ?? -1))
    child.on('error', () => finish(-3))
  })
}

/** Bind a localhost TCP port and return it; the test asserts the
 *  sandboxed process cannot reach it. */
export async function withHostListener<T>(
  fn: (port: number) => Promise<T>,
): Promise<T> {
  const srv = net.createServer(s =>
    s.end('HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nLEAK'),
  )
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r))
  const port = (srv.address() as net.AddressInfo).port
  try {
    return await fn(port)
  } finally {
    srv.close()
  }
}
