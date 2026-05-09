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

/**
 * Resolve `ac_cdylib.dll`. Mirrors `getSboxExecPath`, but returns
 * `undefined` when the cdylib is not present so the broker treats it
 * as no-cdylib (native-PE-only workloads do not require it).
 */
export function getAcCdylibPath(cfg?: WindowsConfig): string | undefined {
  if (cfg?.cdylibPath) {
    return fs.existsSync(cfg.cdylibPath) ? cfg.cdylibPath : undefined
  }
  if (process.env.WINSBOX_CDYLIB) {
    return fs.existsSync(process.env.WINSBOX_CDYLIB)
      ? process.env.WINSBOX_CDYLIB
      : undefined
  }
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
  const candidates = [
    path.join(pkgRoot(), 'vendor', 'winsbox', arch, 'ac_cdylib.dll'),
    path.join(pkgRoot(), 'dist', 'vendor', 'winsbox', arch, 'ac_cdylib.dll'),
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return undefined
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

  // Force System32-first PATH so cmd.exe resolves native binaries
  // (whoami, hostname, find, ...) before any user-PATH Cygwin shims.
  // Git for Windows ships its own `whoami.exe`/`hostname.exe` under
  // `C:\Program Files\Git\usr\bin` which load `cygwin1.dll`; that DLL
  // AVs in `DllMain` under our lockdown token (Phase L wall 1). The
  // user's PATH commonly lists the Git dir before System32, so without
  // this prepend the AC sees the broken Cygwin variants first.
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const sysDirs = [
    `${systemRoot}\\System32`,
    systemRoot,
    `${systemRoot}\\System32\\Wbem`,
  ].join(';')
  const inheritedPath = process.env.PATH ?? process.env.Path ?? ''
  pairs.push(['PATH', `${sysDirs};${inheritedPath}`])
  // SystemRoot/windir aren't strictly needed for the PATH-first
  // resolution above, but explicit values guarantee `%SystemRoot%`
  // expansion inside user commands works regardless of how the
  // broker's own env was sourced.
  pairs.push(['SystemRoot', systemRoot], ['windir', systemRoot])

  // Forward home-locator vars. Without these, git on Windows can't
  // find `~/.gitconfig` and exits 0x80 ("fatal: ...") at startup;
  // similar story for any tool that reads dotfiles. Forwarding them
  // alone isn't sufficient when the resolved home directory is
  // outside `allowRead` (the AC's stat() returns ACCESS_DENIED, also
  // fatal) — callers that need git to actually use a config should
  // either include the home dir in `allowRead` or override `HOME` to
  // a path inside `allowWrite`. Forwarding here at least gives the
  // tool the information it needs to attempt the lookup.
  for (const k of ['USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'HOME']) {
    const v = process.env[k]
    if (v) pairs.push([k, v])
  }
  return pairs
}

// One-shot deprecation warning for the obsolete WINSBOX_PHASE env var.
let warnedDeprecatedPhase = false
function warnIfPhaseEnvSet(): void {
  if (warnedDeprecatedPhase) return
  if (process.env.WINSBOX_PHASE !== undefined) {
    process.stderr.write(
      '[winsbox] WINSBOX_PHASE is deprecated and ignored; the sandbox now ' +
        'has a single mode (ACL stamping + cdylib hooks).\n',
    )
    warnedDeprecatedPhase = true
  }
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
  warnIfPhaseEnvSet()
  const exe = getSboxExecPath(p.windowsConfig)
  const shell = p.binShell || 'cmd'
  // Build the inner command line. cmd.exe /d /s /c "<cmd>" with /s makes
  // the outer quotes literal, so the user's command passes through.
  const inner =
    shell.toLowerCase().includes('powershell') || shell.toLowerCase() === 'pwsh'
      ? `${shell} -NoProfile -Command ${p.command}`
      : `${shell} /d /s /c "${p.command}"`

  const cdylibPath = getAcCdylibPath(p.windowsConfig)
  const manifestDir =
    p.windowsConfig?.manifestDir ?? process.env.WINSBOX_STAMP_DIR

  const policy: Record<string, unknown> = {
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
  }
  // Opt-in: only emit cdylibPath when we resolved a real DLL. Native-PE
  // workloads do not need it; the broker treats absence as no-cdylib.
  if (cdylibPath) policy.cdylibPath = cdylibPath
  // Opt-in: stamp manifest directory override (broker also honours
  // WINSBOX_STAMP_DIR on its side; we forward it explicitly when set
  // here so the policy is self-contained).
  if (manifestDir) policy.manifestDir = manifestDir
  // Opt-in: stableSidKey drives a deterministic AC profile name so the
  // SID stays the same across launches and the broker's manifest cache
  // hits (skipping the multi-second ACL stamping walk on warm restart).
  if (p.windowsConfig?.stableSidKey) {
    policy.stableSidKey = p.windowsConfig.stableSidKey
  }

  const policyPath = path.join(
    os.tmpdir(),
    `srt-policy-${process.pid}-${randomBytes(4).toString('hex')}.json`,
  )
  fs.writeFileSync(policyPath, JSON.stringify(policy))
  logForDebugging(`[Sandbox Windows] policy → ${policyPath}`)

  // Phase N-0: WINSBOX_DEBUG=1 dumps the resolved policy to stderr
  // before spawn so the per-test log shows exactly what the broker
  // got. Off by default — JSON snapshots clutter normal runs.
  if (process.env.WINSBOX_DEBUG === '1') {
    console.error('[srt-ts] resolved policy:', JSON.stringify(policy, null, 2))
  }

  // cmd.exe-safe: only double-quoted absolute paths, no shell metachars.
  return `"${exe}" --policy "${policyPath}"`
}

export function cleanupWindows(): void {
  // Phase 0.5: stub launcher leaves nothing persistent. Phase 1 will
  // spawnSync `${exe} --cleanup` here.
}
