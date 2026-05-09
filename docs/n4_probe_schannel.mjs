#!/usr/bin/env bun
// Phase N-4 follow-up: drive `probe_schannel.exe` inside the AC and
// capture its full output. Mirrors the runSandboxed harness used by
// test/sandbox/windows.test.ts so the broker, ACL stamping, lowbox
// token, AC capabilities, broker-mediated FS, and cdylib injection are
// all live exactly as in the curl-https case the N-4 agent observed.
//
// Usage: bun docs/n4_probe_schannel.mjs [variant]
// Variants:
//   default        - WINSBOX_BROKER_OPEN=1, no syscall trace
//   no-broker-open - WINSBOX_BROKER_OPEN=0
//   syscall-trace  - WINSBOX_TRACE_SYSCALLS=1
//   outside-ac     - skip the broker entirely (sanity baseline)

import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { spawn } from 'node:child_process'

const variant = process.argv[2] ?? 'default'

const PROBE = String.raw`Y:\vendor\winsbox\arm64\probe_schannel.exe`

if (!fs.existsSync(PROBE)) {
  console.error(`probe binary not found at ${PROBE}`)
  process.exit(2)
}

if (variant === 'outside-ac') {
  // Run the binary directly, no broker.
  const child = spawn(PROBE, [], { stdio: 'inherit' })
  child.on('exit', code => process.exit(code ?? 1))
} else {
  // Set per-variant env vars before importing SandboxManager so the
  // broker invocation picks them up.
  if (variant === 'no-broker-open') {
    process.env.WINSBOX_BROKER_OPEN = '0'
  } else if (variant === 'syscall-trace') {
    process.env.WINSBOX_TRACE_SYSCALLS = '1'
  }

  const { SandboxManager } = await import('../src/index.ts')

  // Build a minimal config that mirrors makeFixture(): allow read on
  // tmpdir base + the probe binary's parent dir, no extra deny.
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-probe-'))
  const allowWrite = path.join(base, 'allowWrite')
  fs.mkdirSync(allowWrite, { recursive: true })

  await SandboxManager.reset()
  await SandboxManager.initialize({
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      // Probe binary lives under \\?\UNC\Mac\... or under Y:\vendor.
      // Both should already be AC-readable via inherited ALL APP
      // PACKAGES on this host (verified for sbox-exec.exe). If not,
      // ACL stamping will pick it up.
      allowRead: [base, String.raw`Y:\vendor\winsbox\arm64`],
      denyRead: [],
      allowWrite: [allowWrite],
      denyWrite: [],
    },
  })

  const wrapped = await SandboxManager.wrapWithSandbox(`"${PROBE}"`)
  console.error(`# variant=${variant}`)
  console.error(`# wrapped command: ${wrapped}`)

  const start = Date.now()
  const child = spawn(wrapped, { shell: true })
  let stdout = ''
  let stderr = ''
  child.stdout?.on('data', d => {
    const s = d.toString()
    stdout += s
    process.stdout.write(s)
  })
  child.stderr?.on('data', d => {
    const s = d.toString()
    stderr += s
    process.stderr.write(s)
  })
  await new Promise(resolve => {
    child.on('exit', code => {
      console.error(
        `# exit=${code} duration=${Date.now() - start}ms ` +
        `stdout_bytes=${stdout.length} stderr_bytes=${stderr.length}`,
      )
      try {
        SandboxManager.cleanupAfterCommand?.()
      } catch {}
      try {
        fs.rmSync(base, { recursive: true, force: true })
      } catch {}
      resolve()
      process.exit(code ?? 1)
    })
  })
}
