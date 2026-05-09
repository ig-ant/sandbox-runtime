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
 * Static probe: parse the PE import directory of `exePath` and return
 * true iff it imports `msys-2.0.dll` or `cygwin1.dll` (case-
 * insensitive). Cygwin-runtime binaries AV in `cygwin1.dll!DllMain`
 * under our lockdown token (Phase L); the affected tests gate on
 * this and skip rather than fail.
 *
 * Reads the first ~64KB of the file — enough to cover the DOS
 * stub, NT headers, section table, and (typically) the import
 * directory's name strings. Returns `false` on any parse error or
 * if the binary genuinely doesn't import a Cygwin runtime DLL.
 *
 * NOTE: this is **static** detection. A binary that dynamically
 * `LoadLibrary`s msys-2.0.dll at runtime won't be classified by
 * this probe. Runtime detection (e.g., a hooked LdrLoadDll path
 * for Cygwin-aware behavior switching) is a future N-5/N-6 lever.
 */
export function isCygwinBinary(exePath: string): boolean {
  let fd: number
  try {
    fd = fs.openSync(exePath, 'r')
  } catch {
    return false
  }
  try {
    // Read just the headers first (4KB always covers DOS+NT+section
    // table on every PE produced by linkers since 1995). Real
    // binaries (bash, git, etc.) often have the import directory in
    // a section past 1MB on disk, so we can't snarf the whole file
    // up-front; we read each region we need with explicit pread.
    const hdrBuf = Buffer.alloc(4096)
    const hdrN = fs.readSync(fd, hdrBuf, 0, hdrBuf.length, 0)
    if (hdrN < 0x40) return false

    if (hdrBuf.readUInt16LE(0) !== 0x5a4d /* 'MZ' */) return false
    const ntOff = hdrBuf.readUInt32LE(0x3c)
    if (ntOff + 24 + 240 > hdrN) return false
    if (hdrBuf.readUInt32LE(ntOff) !== 0x4550 /* 'PE\0\0' */) return false

    const ohOff = ntOff + 4 + 20
    const ohMagic = hdrBuf.readUInt16LE(ohOff)
    const isPE32Plus = ohMagic === 0x20b
    // DataDirectory at OptionalHeader+96 (PE32) or +112 (PE32+);
    // entry [1] = IMAGE_DIRECTORY_ENTRY_IMPORT.
    const ddOff = ohOff + (isPE32Plus ? 112 : 96)
    if (ddOff + 16 > hdrN) return false
    const importRva = hdrBuf.readUInt32LE(ddOff + 8)
    const importSize = hdrBuf.readUInt32LE(ddOff + 12)
    if (importRva === 0 || importSize === 0) return false

    const numSections = hdrBuf.readUInt16LE(ntOff + 4 + 2)
    const sizeOfOpt = hdrBuf.readUInt16LE(ntOff + 4 + 16)
    const secOff = ntOff + 4 + 20 + sizeOfOpt
    if (secOff + numSections * 40 > hdrN) return false
    type Sec = { va: number; vsize: number; raw: number; rsize: number }
    const secs: Sec[] = []
    for (let i = 0; i < numSections; i++) {
      const o = secOff + i * 40
      const vsize = hdrBuf.readUInt32LE(o + 8)
      const va = hdrBuf.readUInt32LE(o + 12)
      const rsize = hdrBuf.readUInt32LE(o + 16)
      const raw = hdrBuf.readUInt32LE(o + 20)
      secs.push({ va, vsize, raw, rsize })
    }

    // Find the section containing the import directory and read just
    // that section's data. Then index by RVA-relative offsets.
    const importSec = secs.find(
      (s) =>
        importRva >= s.va && importRva < s.va + Math.max(s.vsize, s.rsize),
    )
    if (!importSec) return false
    const secSize = Math.max(importSec.vsize, importSec.rsize)
    const secBuf = Buffer.alloc(secSize)
    const secN = fs.readSync(fd, secBuf, 0, secSize, importSec.raw)
    if (secN === 0) return false
    const data = secBuf.subarray(0, secN)
    const rvaToSecOff = (rva: number): number | undefined => {
      if (rva < importSec.va || rva >= importSec.va + secSize) return undefined
      const off = rva - importSec.va
      return off < data.length ? off : undefined
    }
    const importOff = rvaToSecOff(importRva)
    if (importOff === undefined) return false

    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; NULL-descriptor terminator.
    // Field of interest: Name at +12 (RVA of NUL-terminated ASCII).
    const cygDlls = ['msys-2.0.dll', 'cygwin1.dll']
    for (let off = importOff; off + 20 <= data.length; off += 20) {
      const nameRva = data.readUInt32LE(off + 12)
      const ofth = data.readUInt32LE(off)
      const fth = data.readUInt32LE(off + 16)
      if (nameRva === 0 && ofth === 0 && fth === 0) break
      if (nameRva === 0) continue
      const nameOff = rvaToSecOff(nameRva)
      if (nameOff === undefined) continue
      let end = nameOff
      while (end < data.length && data[end] !== 0) end++
      if (end > nameOff) {
        const dllName = data.toString('latin1', nameOff, end).toLowerCase()
        if (cygDlls.includes(dllName)) return true
      }
    }
    return false
  } catch {
    return false
  } finally {
    fs.closeSync(fd)
  }
}

/**
 * Wrapper-aware Cygwin-prone-git detection. Resolves git on PATH and
 * probes the located .exe via {@link isCygwinBinary}. If the resolved
 * exe lives in a Git-for-Windows `cmd` subdir (the standard layout's
 * `<install>/cmd/git.exe` is a thin pure-Win32 wrapper that
 * `CreateProcess`es `<install>/bin/git.exe`, which IS Cygwin-flavored),
 * also probe the sibling `bin/git.exe`. Either being Cygwin classifies
 * the resolved git as Cygwin-prone — the test would AV in `cygwin1.dll!
 * DllMain` (Phase L Wall 1) under our lockdown token.
 *
 * Local hosts that resolve to a non-wrapper native git (e.g.
 * `<install>/clangarm64/bin/git.exe` on the ARM64 dev box) skip the
 * sibling check and stay green. CI runners that resolve to the standard
 * `cmd/git.exe` wrapper get classified Cygwin-prone via the sibling
 * check and skip cleanly. Returns `false` when git isn't on PATH.
 */
export function isCygwinGit(): boolean {
  const dir = findToolchainDir('git')
  if (!dir) return false
  const exe = path.join(dir, 'git.exe')
  if (!fs.existsSync(exe)) return false
  if (isCygwinBinary(exe)) return true
  // Wrapper-aware: when resolved to `<install>/cmd/git.exe`, the
  // wrapper re-execs `<install>/bin/git.exe` which is the actual
  // Cygwin binary on standard Git for Windows installs.
  if (path.basename(dir).toLowerCase() === 'cmd') {
    const altExe = path.join(path.dirname(dir), 'bin', 'git.exe')
    if (fs.existsSync(altExe) && isCygwinBinary(altExe)) return true
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
