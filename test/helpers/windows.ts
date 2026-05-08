import { spawn, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as net from 'node:net'
import { SandboxManager } from '../../src/index.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

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

/**
 * Locate a toolchain binary on PATH and return its parent directory.
 * Skips Windows App Execution Alias reparse points under
 * `…\Microsoft\WindowsApps` (UWP redirectors that need package
 * activation, which our AC token can't reach).
 */
function findToolchainDir(bin: string): string | undefined {
  const PATH = process.env.PATH || ''
  const PATHEXT = (process.env.PATHEXT || '.EXE').toLowerCase().split(';')
  const exts = bin.toLowerCase().endsWith('.exe') ? [''] : PATHEXT
  for (const dir of PATH.split(';')) {
    if (!dir) continue
    // Skip the App-Execution-Alias dir — entries there are reparse
    // points to UWP packages that AC can't activate.
    if (/\\Microsoft\\WindowsApps$/i.test(dir)) continue
    for (const ext of exts) {
      const candidate = path.join(dir, bin + ext)
      try {
        const st = fs.statSync(candidate)
        if (st.isFile()) return dir
      } catch {
        /* not present */
      }
    }
  }
  return undefined
}

/**
 * Whether `dir` already has an `ALL APPLICATION PACKAGES` (or
 * `ALL RESTRICTED APPLICATION PACKAGES`) RX ACE — either explicit or
 * inherited from a parent. AC tokens skip the normal `Users:RX` ACE
 * during access checks, so without an AC-aware ACE the AC simply
 * can't enumerate the directory or execute binaries inside it.
 *
 * We probe via `icacls` rather than the native ACL APIs because the
 * test helper runs in TS — the broker uses the equivalent
 * `existing_ace_grants_all_app_packages` check (acl_stamper.rs:177)
 * to short-circuit redundant stamps; the two MUST agree.
 */
function isAcAccessible(dir: string): boolean {
  const r = spawnSync('icacls', [dir], { encoding: 'utf-8' })
  if (r.status !== 0) return false
  // Match either the friendly name or the well-known SIDs:
  //   ALL APPLICATION PACKAGES = S-1-15-2-1
  //   ALL RESTRICTED APPLICATION PACKAGES = S-1-15-2-2
  // and require an "(RX)" or "(R,X)" or generic "(F)" mask token after
  // the principal — `(I)` alone (inherited only) doesn't carry rights.
  const re = /(ALL APPLICATION PACKAGES|ALL RESTRICTED APPLICATION PACKAGES|S-1-15-2-1\b|S-1-15-2-2\b):[^\n]*\((?:[^)]*\b(?:RX|F|R,?X|GR,?GE)\b)/i
  return re.test(r.stdout)
}

/**
 * Whether a binary is reachable from inside an AC token via PATH —
 * i.e. it exists AND its parent dir already has an AC-aware ACE.
 *
 * Returns `false` for the Windows-Store `python.exe` alias since the
 * UWP redirector lives under `…\Microsoft\WindowsApps`, which is
 * filtered out at the PATH-scan step (`findToolchainDir`); even if
 * we let the alias through, the UWP redirector itself needs the
 * package activation runtime which our lockdown token can't reach.
 *
 * Toolchains installed without `ALL APPLICATION PACKAGES` (e.g. the
 * stock node.msi for Windows) require an admin one-time stamp before
 * the AC can see them. The affected tests gate on this and skip
 * rather than fail when the host's install isn't AC-friendly.
 */
export function isToolchainUsable(bin: string): boolean {
  const dir = findToolchainDir(bin)
  return !!dir && isAcAccessible(dir)
}

/**
 * Whether the resolved `git` is the MSYS2/Cygwin variant — those
 * binaries depend on `cygwin1.dll` / `msys-2.0.dll` which AVs in
 * `DllMain` under our lockdown token (Phase L). Skip the
 * `git --version` test in that case; the tracked workaround is to
 * land the cygwin compat hooks (separate follow-up).
 */
export function isCygwinGit(): boolean {
  const dir = findToolchainDir('git')
  if (!dir) return false
  // Detect a "Git for Windows" install layout: any sibling subtree
  // containing cygwin1.dll or msys-2.0.dll means git was built on
  // the MSYS2 runtime and re-execs through it. The Git\cmd\git.exe
  // wrapper also defers to the same backing binary.
  const dlls = ['cygwin1.dll', 'msys-2.0.dll']
  const candidateRoots: string[] = [dir]
  // Walk up to a parent that looks like a Git-for-Windows root
  // (contains a `cmd` subdir) and probe its known bin subtrees.
  // PATH entries are typically `<root>\<flavour>\bin` (one level
  // deep) or `<root>\cmd` (zero deep), so try one and two levels up.
  for (let up = 1; up <= 2; up++) {
    const root = path.resolve(dir, ...Array(up).fill('..'))
    for (const sibling of ['usr/bin', 'clangarm64/bin', 'mingw64/bin', 'bin']) {
      candidateRoots.push(path.join(root, ...sibling.split('/')))
    }
  }
  // The Git\cmd wrapper has no cygwin DLLs in its dir, but every
  // Git-for-Windows install reachable from it does.
  if (/\\Git\\cmd$/i.test(dir)) return true
  for (const root of candidateRoots) {
    for (const dll of dlls) {
      if (fs.existsSync(path.join(root, dll))) return true
    }
  }
  return false
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
      // ACL stamping uses (OI)(CI) ALLOW on each allowRead root and
      // (OI)(CI) DENY on each denyRead/denyWrite path that nests
      // under an ALLOW. System dirs are already ACL'd to
      // ALL APPLICATION PACKAGES; the fixture tree is the only
      // path that needs an explicit stamp here. User-installed
      // toolchains (node.msi, git, python alias) typically lack
      // an AC ACE on their install dir — those tests gate on
      // `isToolchainUsable` and skip when the AC token's PATH
      // lookup can't see the binary at all (granting that ACE
      // requires admin and is out of scope for the suite).
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
