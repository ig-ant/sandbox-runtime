import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import type { WindowsConfig } from './sandbox-config.js'

export interface WindowsSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  binShell?: string
  windowsConfig?: WindowsConfig
}

function pkgRoot(): string {
  // dist/sandbox/windows-sandbox-utils.js → repo (or installed package) root
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

export function getSboxExecPath(cfg?: WindowsConfig): string {
  if (cfg?.sboxExecPath) return cfg.sboxExecPath
  if (process.env.SBOX_EXEC_PATH) return process.env.SBOX_EXEC_PATH
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
  // Resolution mirrors getApplySeccompBinaryPath: vendor dir lives next to
  // dist/ in the published package, or at repo root in dev.
  const candidates = [
    path.join(pkgRoot(), 'vendor', 'winsbox', arch, 'sbox-exec.exe'),
    path.join(pkgRoot(), 'dist', 'vendor', 'winsbox', arch, 'sbox-exec.exe'),
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return candidates[0]
}

export function checkWindowsDependencies(
  cfg?: WindowsConfig,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []
  const exe = getSboxExecPath(cfg)
  if (!fs.existsSync(exe)) {
    errors.push(
      `sbox-exec.exe not found at ${exe}. Run 'bun vendor/winsbox/build.ts' or set SBOX_EXEC_PATH.`,
    )
  }
  // The broker must NOT run elevated — see plan §"never elevate".
  // (Detection deferred to the Rust side which can call IsUserAnAdmin;
  //  Node has no portable check.)
  return { errors, warnings }
}

function envPairs(
  httpProxyPort?: number,
  socksProxyPort?: number,
): [string, string][] {
  const list = generateProxyEnvVars(httpProxyPort, socksProxyPort)
  const pairs: [string, string][] = []
  for (const e of list) {
    const i = e.indexOf('=')
    if (i > 0) pairs.push([e.slice(0, i), e.slice(i + 1)])
  }
  // Windows uses TEMP/TMP, not TMPDIR.
  const tmpdir = process.env.CLAUDE_TMPDIR || path.join(os.tmpdir(), 'claude')
  pairs.push(['TEMP', tmpdir], ['TMP', tmpdir])
  return pairs
}

function defaultMode(cfg?: WindowsConfig): 'stub' | 'app-container' | 'broker' {
  if (cfg?.mode) return cfg.mode
  const p = process.env.WINSBOX_PHASE
  if (p === '2') return 'broker'
  if (p === '1') return 'app-container'
  return 'stub'
}

/**
 * Write a JSON policy describing the desired confinement and return a
 * cmd.exe-safe command string that runs sbox-exec.exe against it. The
 * policy carries the user command verbatim so we never have to escape
 * it through cmd.exe ourselves.
 */
export async function wrapCommandWithSandboxWindows(
  p: WindowsSandboxParams,
): Promise<string> {
  const exe = getSboxExecPath(p.windowsConfig)
  const shell = p.binShell || 'cmd'
  // Build the inner command line. cmd.exe /d /s /c "<cmd>" with /s makes
  // the outer quotes literal, so the user's command passes through.
  const inner =
    shell.toLowerCase().includes('powershell') || shell.toLowerCase() === 'pwsh'
      ? `${shell} -NoProfile -Command ${p.command}`
      : `${shell} /d /s /c "${p.command}"`

  const policy = {
    commandLine: inner,
    cwd: process.cwd(),
    env: envPairs(
      p.needsNetworkRestriction ? p.httpProxyPort : undefined,
      p.needsNetworkRestriction ? p.socksProxyPort : undefined,
    ),
    allowRead: (p.readConfig?.allowWithinDeny ?? []).map(
      normalizePathForSandbox,
    ),
    denyRead: (p.readConfig?.denyOnly ?? []).map(normalizePathForSandbox),
    allowWrite: (p.writeConfig?.allowOnly ?? []).map(normalizePathForSandbox),
    denyWrite: (p.writeConfig?.denyWithinAllow ?? []).map(
      normalizePathForSandbox,
    ),
    network: {
      httpProxyPort: p.httpProxyPort,
      socksProxyPort: p.socksProxyPort,
    },
    // Off by default until conhost-on-alt-desktop is sorted; the Job
    // UI restrictions already block the cross-process window vectors.
    useAlternateDesktop: p.windowsConfig?.useAlternateDesktop ?? false,
    // Hook NtCreateFile/NtOpenFile so reads/writes go through the
    // broker's policy engine instead of relying on Phase-1 ACL
    // grants alone. Lets the lockdown token open paths the AC SID
    // wasn't granted on (tool install dirs, ambient reads).
    brokerFs:
      p.windowsConfig?.brokerFs ?? defaultMode(p.windowsConfig) === 'broker',
    mode: defaultMode(p.windowsConfig),
  }

  const policyPath = path.join(
    os.tmpdir(),
    `srt-policy-${process.pid}-${randomBytes(4).toString('hex')}.json`,
  )
  fs.writeFileSync(policyPath, JSON.stringify(policy))
  logForDebugging(`[Sandbox Windows] policy → ${policyPath}`)

  // cmd.exe-safe: only double-quoted absolute paths, no shell metachars.
  return `"${exe}" --policy "${policyPath}"`
}

export function cleanupWindows(): void {
  // Phase 0.5: stub launcher leaves nothing persistent. Phase 1 will
  // spawnSync `${exe} --cleanup` here.
}
