// pnpm reproduce (REQ-TEST-006): re-derive the golden vectors from source and assert they match the
// committed vectors/golden.json byte-for-byte. Drift — whether a hand-edited expected value or a
// silent output change — fails the build. `--write` regenerates the committed file (intentional update).

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { goldenJson } from './gen-golden.ts';

const goldenPath = fileURLToPath(new URL('../../vectors/golden.json', import.meta.url));
const fresh = goldenJson();
const norm = (s: string) => s.replace(/\r\n/g, '\n');

if (process.argv.includes('--write')) {
  mkdirSync(dirname(goldenPath), { recursive: true });
  writeFileSync(goldenPath, fresh);
  console.log(`golden vectors written to vectors/golden.json (${fresh.length} bytes)`);
  process.exit(0);
}

let committed: string;
try {
  committed = readFileSync(goldenPath, 'utf8');
} catch {
  console.error('reproduce FAILED — vectors/golden.json is missing. Run `pnpm reproduce -- --write` to create it.');
  process.exit(1);
}

if (norm(committed) !== norm(fresh)) {
  console.error('reproduce FAILED — re-derived golden vectors DIFFER from the committed vectors/golden.json.');
  console.error('Either a committed expected value was hand-edited, or a code change altered an output.');
  console.error('If the change is intentional, review the diff and run `pnpm reproduce -- --write`.');
  process.exit(1);
}
console.log('reproduce OK — golden vectors re-derive byte-for-byte from source (REQ-TEST-006).');
