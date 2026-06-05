// pnpm ci — ordered, all-green, no green-by-omission (REQ-BUILD-005/007).
// Steps: static bans → typecheck → tests. (App builds + adversarial battery wire in here as the
// client packages land — REQ-SEC-010.)

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

interface CIStep {
  readonly name: string;
  readonly cmd: string;
  readonly args: readonly string[];
}

const STEPS: CIStep[] = [
  { name: 'static bans (REQ-BAN-001..005)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/check-bans/index.ts'] },
  { name: 'SAST gate (SANS/CWE + NASA P10 + MS SDL)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/sast/index.ts'] },
  { name: 'requirement trace (REQ-TRACE-001/004)', cmd: 'node', args: ['--experimental-strip-types', 'tooling/trace/index.ts'] },
  { name: 'typecheck', cmd: 'npx', args: ['tsc', '-p', 'tsconfig.json', '--noEmit'] },
  { name: 'tests', cmd: 'node', args: ['--experimental-strip-types', '--test', 'packages/**/test/**/*.test.ts'] },
  // native client render/play battery (drives the real entry over scripted stdin — not "process alive")
  { name: 'desktop play tests', cmd: 'node', args: ['--experimental-strip-types', '--test', 'apps/desktop/test/**/*.test.ts'] },
  // REQ-SEC-010: the shippable app MUST build AND its render/adversarial battery MUST pass — no
  // green-by-omission. A web client that does not build or render is a CI failure, not a pass.
  { name: 'client-web render tests', cmd: 'pnpm', args: ['--filter', '@bsv-universal/client-web', 'test'] },
  { name: 'client-web build (vite)', cmd: 'pnpm', args: ['--filter', '@bsv-universal/client-web', 'build'] },
];

let failed = false;
for (const step of STEPS) {
  process.stdout.write(`\n=== ${step.name} ===\n`);
  const r = spawnSync(step.cmd, step.args, { cwd: ROOT, stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) {
    process.stderr.write(`\nCI FAILED at: ${step.name} (exit ${r.status})\n`);
    failed = true;
    break;
  }
}

if (failed) process.exit(1);
process.stdout.write('\nCI OK — bans + trace + typecheck + tests all green.\n');
