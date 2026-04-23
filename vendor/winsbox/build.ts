#!/usr/bin/env bun
/**
 * Build sbox-exec.exe for the host architecture and copy it into
 * vendor/winsbox/<arch>/sbox-exec.exe so the TS side can resolve it
 * the same way the seccomp helper is resolved.
 *
 * Run on a Windows host (CI does this); cross-compilation from non-
 * Windows would need an MSVC linker, which we don't assume here.
 */
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as path from 'node:path'

if (process.platform !== 'win32') {
  console.error('vendor/winsbox/build.ts: skipping (not Windows)')
  process.exit(0)
}

const repoRoot = path.resolve(import.meta.dir, '..', '..')
const srcDir = path.join(repoRoot, 'vendor', 'winsbox-src')
const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
const outDir = path.join(repoRoot, 'vendor', 'winsbox', arch)

console.log(`Building sbox-exec for ${arch}...`)
const r = spawnSync(
  'cargo',
  ['build', '--release', '--manifest-path', path.join(srcDir, 'Cargo.toml')],
  { stdio: 'inherit' },
)
if (r.status !== 0) {
  console.error('cargo build failed')
  process.exit(r.status ?? 1)
}

fs.mkdirSync(outDir, { recursive: true })
const built = path.join(srcDir, 'target', 'release', 'sbox-exec.exe')
const dest = path.join(outDir, 'sbox-exec.exe')
fs.copyFileSync(built, dest)
console.log(`Wrote ${dest}`)
