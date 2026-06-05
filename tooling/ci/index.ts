// pnpm ci — ordered, all-green, no green-by-omission (REQ-BUILD-005/007).
// Steps: static bans → typecheck → tests. (App builds + adversarial battery wire in here as the
// client packages land — REQ-SEC-010.)

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

interface CIStep {
  readonly name: string;
  readonly cmd: string;
  readonly args: readonly string[];
  readonly cwd?: string; // relative to ROOT
  readonly env?: Readonly<Record<string, string>>;
}

const GO = 'go';

const STEPS: CIStep[] = [
  { name: 'static bans (REQ-BAN-001..005)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/check-bans/index.ts'] },
  { name: 'SAST gate (SANS/CWE + NASA P10 + MS SDL)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/sast/index.ts'] },
  { name: 'requirement trace (REQ-TRACE-001/004)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/trace/index.ts'] },
  { name: 'reproduce golden vectors (REQ-TEST-006 provenance)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/diff/reproduce.ts'] },
  { name: 'typecheck', cmd: 'npx', args: ['tsc', '-p', 'tsconfig.json', '--noEmit'] },
  { name: 'tests', cmd: 'node', args: ['--experimental-strip-types', '--test', 'packages/**/test/**/*.test.ts'] },
  // REQ-TEST-010 coverage gate: 100% FUNCTION coverage on the determinism-critical consensus core
  // (every function exercised by a test). Line/branch are reported; exact-100 line is not gated
  // because Node attributes type-only lines as "uncovered". Deeper assurance: the differentials + fuzz.
  {
    name: 'coverage gate (REQ-TEST-010: 100% functions on consensus core)',
    cmd: 'node',
    args: [
      '--experimental-strip-types', '--test', '--experimental-test-coverage', '--test-coverage-functions=100',
      '--test-coverage-include=packages/protocol-types/src/**',
      '--test-coverage-include=packages/crypto/src/**',
      '--test-coverage-include=packages/engine/src/**',
      '--test-coverage-include=packages/script/src/**',
      'packages/protocol-types/test/**/*.test.ts', 'packages/crypto/test/**/*.test.ts',
      'packages/engine/test/**/*.test.ts', 'packages/script/test/**/*.test.ts',
    ],
  },
  // native client render/play battery (drives the real entry over scripted stdin — not "process alive")
  { name: 'desktop play tests', cmd: 'node', args: ['--experimental-strip-types', '--test', 'apps/desktop/test/**/*.test.ts'] },
  // TS↔Go differential (REQ-TEST-003): regenerate the corpus from TS, then assert the independent
  // Go engine is byte-identical. Plus the Go unit tests. Divergence fails the build.
  { name: 'differential corpus (TS)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/diff/gen-vectors.ts'] },
  { name: 'TS↔Go differential (engine)', cmd: GO, args: ['run', './diff'], cwd: 'go', env: { GOFLAGS: '-trimpath' } },
  { name: 'value differential corpus (TS)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/diff/gen-value-vectors.ts'] },
  { name: 'TS↔Go differential (value layer: script/tx/sighash/covenant)', cmd: GO, args: ['run', './valuediff'], cwd: 'go', env: { GOFLAGS: '-trimpath' } },
  { name: 'Go unit tests', cmd: GO, args: ['test', './...'], cwd: 'go', env: { GOFLAGS: '-trimpath' } },
  // REQ-SEC-010: the shippable app MUST build AND its render/adversarial battery MUST pass — no
  // green-by-omission. A web client that does not build or render is a CI failure, not a pass.
  { name: 'client-web render tests', cmd: 'pnpm', args: ['--filter', '@bsv-universal/client-web', 'test'] },
  { name: 'client-web build (vite)', cmd: 'pnpm', args: ['--filter', '@bsv-universal/client-web', 'build'] },
];

let failed = false;
for (const step of STEPS) {
  process.stdout.write(`\n=== ${step.name} ===\n`);
  const cwd = step.cwd ? join(ROOT, step.cwd) : ROOT;
  const env = step.env ? { ...process.env, ...step.env } : process.env;
  const r = spawnSync(step.cmd, step.args, { cwd, env, stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) {
    process.stderr.write(`\nCI FAILED at: ${step.name} (exit ${r.status})\n`);
    failed = true;
    break;
  }
}

if (failed) process.exit(1);
process.stdout.write('\nCI OK — bans + trace + typecheck + tests all green.\n');
