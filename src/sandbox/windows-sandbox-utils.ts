import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'

/**
 * Windows sandbox parameters. Mirrors the macOS/Linux shape but the
 * v1 WFP+SID (deny-only-group) design does NOT enforce filesystem
 * restrictions inside the sandbox — the child runs as the broker
 * user at Medium IL with a single discriminator group flipped
 * deny-only and `SidsToDisable` for `BUILTIN\Administrators`. The
 * `readConfig`/`writeConfig` fields are accepted for API parity and
 * logged for debugging, but not enforced.
 */
export interface WindowsSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  // Caller-facing port numbers are accepted but ignored: the v1
  // network jail terminates at the broker-managed SOCKS proxy that
  // `sbox-exec` reads from the install marker, not from the host
  // sandbox-runtime SOCKS/HTTP listeners. They are accepted purely
  // so the dispatch in `sandbox-manager.ts` doesn't have to special-
  // case Windows further.
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  binShell?: string
}

function repoRoot(): string {
  // src/sandbox/windows-sandbox-utils.ts → repo root
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

/**
 * Locate the `sbox-exec.exe` binary. Resolution order:
 *   1. `SBOX_EXEC_PATH` env var.
 *   2. `<repo>/vendor/winsbox-src/target/release/sbox-exec.exe`
 *   3. `<repo>/dist/vendor/winsbox/sbox-exec.exe` (post-`npm run build` shape).
 *   4. `<userprofile>/.cargo-target/winsbox-wfp-sid/release/sbox-exec.exe`
 *      (the worktree-style target we use for development on this branch).
 *   5. `which sbox-exec`.
 */
export function getSboxExecPath(): string {
  if (process.env.SBOX_EXEC_PATH && fs.existsSync(process.env.SBOX_EXEC_PATH)) {
    return process.env.SBOX_EXEC_PATH
  }
  const home = process.env.USERPROFILE || os.homedir()
  const candidates = [
    path.join(repoRoot(), 'vendor', 'winsbox-src', 'target', 'release', 'sbox-exec.exe'),
    path.join(repoRoot(), 'dist', 'vendor', 'winsbox', 'sbox-exec.exe'),
    // Phase 5 worktree target dir (preferred on this branch).
    path.join(home, '.cargo-target', 'winsbox-phase5', 'release', 'sbox-exec.exe'),
    path.join(home, '.cargo-target', 'winsbox-wfp-sid', 'release', 'sbox-exec.exe'),
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  const onPath = whichSync('sbox-exec')
  if (onPath) return onPath
  // Fall through to first candidate so callers see a stable, debuggable
  // path in the "not found" error message.
  return candidates[0]
}

/**
 * Check that WFP filters are installed (`sbox-exec install --check`).
 * Returns `{installed: true, port}` on success, `{installed: false}` if
 * the marker file is absent. Throws on binary-not-found or exec
 * failure.
 */
export function checkSboxInstalled(): { installed: boolean; port?: number; raw: string } {
  const exe = getSboxExecPath()
  if (!fs.existsSync(exe)) {
    throw new Error(
      `sbox-exec.exe not found at ${exe}. ` +
        `Build with \`cd vendor/winsbox-src && cargo build --release\` ` +
        `or set SBOX_EXEC_PATH.`,
    )
  }
  const r = spawnSync(exe, ['install', '--check'], {
    encoding: 'utf-8',
    timeout: 5000,
  })
  const raw = `${r.stdout ?? ''}${r.stderr ?? ''}`
  if (r.status !== 0) {
    return { installed: false, raw }
  }
  const m = /installed:\s*port=(\d+)/i.exec(raw)
  if (m) return { installed: true, port: Number(m[1]), raw }
  return { installed: false, raw }
}

export function checkWindowsDependencies(): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []
  const exe = getSboxExecPath()
  if (!fs.existsSync(exe)) {
    errors.push(
      `sbox-exec.exe not found at ${exe}. ` +
        `Build with 'cd vendor/winsbox-src && cargo build --release' ` +
        `or set SBOX_EXEC_PATH.`,
    )
    return { errors, warnings }
  }
  try {
    const r = checkSboxInstalled()
    if (!r.installed) {
      // Warning rather than error so non-network tests can still
      // exercise the sandbox; tests that need the proxy can gate on
      // checkSboxInstalled() directly.
      warnings.push(
        `WFP filters not installed (run \`sbox-exec install\` as administrator). ` +
          `Output: ${r.raw.trim()}`,
      )
    }
  } catch (e) {
    warnings.push(`sbox-exec install --check failed: ${(e as Error).message}`)
  }
  return { errors, warnings }
}

/**
 * Quote a single argv element for cmd.exe + CreateProcess parsing.
 * Conservative: wrap in double quotes and escape embedded quotes /
 * backslash-runs preceding a quote per MSDN's argv quoting rules.
 */
function quoteWindowsArg(arg: string): string {
  if (arg === '') return '""'
  // Fast path: nothing requiring quoting.
  if (!/[\s"^&|<>()%!]/.test(arg)) return arg
  let result = '"'
  let backslashes = 0
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes++
      continue
    }
    if (ch === '"') {
      result += '\\'.repeat(backslashes * 2 + 1) + '"'
      backslashes = 0
      continue
    }
    if (backslashes > 0) {
      result += '\\'.repeat(backslashes)
      backslashes = 0
    }
    result += ch
  }
  result += '\\'.repeat(backslashes * 2) + '"'
  return result
}

/**
 * Wrap a shell command string for the Windows WFP+SID sandbox.
 *
 * v1 strategy (per `we-ll-sync-with-upstream-linked-axolotl.md`):
 *   `sbox-exec [policy-args] -- <bin-shell> /d /s /c "<command>"`
 *
 * The user's `command` is a free-form shell string (consistent with
 * Linux/macOS), so we hand it to a cmd.exe / powershell child invoked
 * by `sbox-exec`. `sbox-exec` itself sets `HTTP_PROXY` / `HTTPS_PROXY`
 * / `ALL_PROXY` env vars on the target so well-behaved clients route
 * through the broker SOCKS proxy reachable at the marker-file port.
 *
 * Filesystem restrictions in `readConfig` / `writeConfig` are NOT
 * enforced in v1; they are accepted for API parity with the
 * Linux/macOS surface and logged.
 */
export function wrapCommandWithSandboxWindows(
  p: WindowsSandboxParams,
): string {
  // Phase 5B: `readConfig.denyOnly` is now enforced (per-path
  // share-mode-0 lock acquired by the broker). The JS API still
  // accepts the field for parity; we pass it through to sbox-exec via
  // a policy JSON over stdin when wrapCommandWithSandboxWindows is
  // used as a shell command string. (Direct `runSboxed`-style spawns
  // can opt in by setting denyRead in `runSboxedWithDenyRead`.)
  //
  // `readConfig.allowWithinDeny` and `writeConfig.*` remain unenforced
  // in v1 — they are accepted for API parity and logged.
  if (
    p.readConfig &&
    (p.readConfig.allowWithinDeny ?? []).length > 0
  ) {
    logForDebugging(
      `[Sandbox Windows] readConfig.allowWithinDeny present but \`allowWithinDeny\` is not enforced in WFP+SID v1; ignoring`,
      { level: 'warn' },
    )
  }
  if (
    p.writeConfig &&
    ((p.writeConfig.allowOnly ?? []).length > 0 ||
      (p.writeConfig.denyWithinAllow ?? []).length > 0)
  ) {
    logForDebugging(
      `[Sandbox Windows] writeConfig present but FS restrictions are not enforced in WFP+SID v1; ignoring`,
      { level: 'warn' },
    )
  }

  const exe = getSboxExecPath()
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const shell = (p.binShell || 'cmd').toLowerCase()
  // Resolve an absolute path for the shell to avoid surprises from the
  // child's PATH.
  const shellExe = shell.includes('powershell')
    ? path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    : shell === 'pwsh'
      ? 'pwsh.exe'
      : path.join(systemRoot, 'System32', 'cmd.exe')

  // Inner shell invocation.
  let innerArgs: string[]
  if (shell.includes('powershell') || shell === 'pwsh') {
    innerArgs = ['-NoProfile', '-Command', p.command]
  } else {
    // cmd /d (no AutoRun) /s (literal quotes) /c (run-then-exit).
    innerArgs = ['/d', '/s', '/c', p.command]
  }

  // Phase 5B: when `readConfig.denyOnly` is non-empty, write a policy
  // JSON to a temp file and invoke `sbox-exec --policy <file> -- ...`.
  // The broker reads it and acquires share-mode-0 locks on each path
  // before spawning the child. Cleanup of the temp file is best-effort;
  // the OS tmp dir handles long-tail garbage.
  const denyRead = p.readConfig?.denyOnly ?? []
  let policyFile: string | undefined
  if (denyRead.length > 0) {
    const tmpDir = os.tmpdir()
    policyFile = path.join(
      tmpDir,
      `winsbox-policy-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.json`,
    )
    // `target_exe` is required by the policy schema even though we
    // override it via trailing args. Use a placeholder; the broker
    // overwrites it with `cli.target[0]` post-parse.
    const policy = {
      target_exe: shellExe,
      fs_deny_read: denyRead,
    }
    fs.writeFileSync(policyFile, JSON.stringify(policy), { encoding: 'utf-8' })
  }

  const argv: string[] = policyFile
    ? [exe, '--policy', policyFile, '--', shellExe, ...innerArgs]
    : [exe, '--', shellExe, ...innerArgs]
  return argv.map(quoteWindowsArg).join(' ')
}

export function cleanupWindows(): void {
  // No persistent per-command state to clean. WFP filters are
  // host-global and managed by `sbox-exec install` / `install --remove`.
}
