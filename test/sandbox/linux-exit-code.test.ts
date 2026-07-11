import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { whichSync } from '../../src/utils/which.js'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'

/**
 * Exit-code propagation through the full Linux bwrap wrapper when network
 * restrictions are active.
 *
 * With allowedDomains configured, the wrapped command runs inside a
 * `<shell> -c` script that starts two background socat forwarders and
 * installs an EXIT trap to clean them up. That trap must not overwrite the
 * user command's exit status: capturing `$?` before the `kill` (which
 * succeeds and would otherwise reset `$?` to 0) and passing it to `exit`
 * is required for shells whose bare `exit` inside a trap does not fall back
 * to the pre-trap status. bash/dash restore the original status for a bare
 * `exit`; zsh does not, so a wrapped `exit 3` under `binShell=zsh` used to
 * report status 0.
 */

function createTestConfig(): SandboxRuntimeConfig {
  return {
    // A non-empty allowlist so wrapCommandWithSandboxLinux takes the
    // socat-bridge path (buildSandboxCommand) rather than invoking
    // apply-seccomp directly.
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: ['/tmp'],
      denyWrite: [],
    },
  }
}

describe.if(isLinux)('Linux sandbox exit-code propagation', () => {
  beforeAll(async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  const cases: Array<[string, number]> = [
    ['exit 0', 0],
    ['exit 1', 1],
    ['exit 3', 3],
    ['exit 42', 42],
  ]

  for (const shell of ['bash', 'zsh'] as const) {
    // CI installs zsh; skip on dev boxes without it rather than throwing
    // "Shell 'zsh' not found in PATH" from wrapCommandWithSandboxLinux.
    describe.if(whichSync(shell) !== null)(`binShell=${shell}`, () => {
      for (const [cmd, expected] of cases) {
        it(`propagates \`${cmd}\` as status ${expected}`, async () => {
          const wrapped = await SandboxManager.wrapWithSandbox(cmd, shell)
          // The socat/trap wrapper is only present when the network bridge
          // path is taken; guard so the test fails loudly if that changes.
          expect(wrapped).toContain('trap')

          const result = await spawnAsync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 10000,
          })
          expect(result.status).toBe(expected)
        })
      }

      it('propagates a signal exit as 128+signo', async () => {
        // apply-seccomp's inner init already re-encodes a signal death as
        // 128+n before it reaches the trap, so the trap sees it as an
        // ordinary non-zero status.
        const wrapped = await SandboxManager.wrapWithSandbox(
          'kill -TERM $$',
          shell,
        )
        const result = await spawnAsync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })
        expect(result.status).toBe(128 + 15)
      })
    })
  }
})
