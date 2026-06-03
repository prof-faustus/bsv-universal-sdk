// pnpm trace — verify the requirement index is internally consistent (REQ-TRACE-001/003/004).
// Checks: (1) the declared STATUS TALLY in traceability.txt matches the actual REQ rows, and
// (2) BUILD-STATUS.md §1 TOTAL agrees. Divergence between prose and index is a defect (REQ-BAN-006).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const trace = readFileSync(new URL('../../traceability.txt', import.meta.url), 'utf8');
const build = readFileSync(new URL('../../BUILD-STATUS.md', import.meta.url), 'utf8');

const errors: string[] = [];

// Count actual requirement rows (exclude comments and the REQ-MOD-000 template row).
const rows = trace.split(/\r?\n/).filter((l) => /^REQ-[A-Z]/.test(l));
const counted = rows.filter((l) => !/^REQ-MOD-000\b/.test(l));
const actualTotal = counted.length;

// Declared tally in traceability.txt header.
const declared = /STATUS TALLY \(this file\): total=(\d+)/.exec(trace);
if (!declared) errors.push('traceability.txt: missing "STATUS TALLY ... total=" line');
else if (Number(declared[1]) !== actualTotal) {
  errors.push(`traceability.txt: declared total=${declared[1]} but counted ${actualTotal} requirement rows`);
}

// core vs module split.
const core = counted.filter((l) => !/^REQ-MOD-/.test(l)).length;
const mod = counted.filter((l) => /^REQ-MOD-/.test(l)).length;
const split = /core REQs = (\d+) +\| +module REQs = (\d+)/.exec(trace);
if (!split) errors.push('traceability.txt: missing "core REQs = N | module REQs = M" line');
else {
  if (Number(split[1]) !== core) errors.push(`core REQs: declared ${split[1]} but counted ${core}`);
  if (Number(split[2]) !== mod) errors.push(`module REQs: declared ${split[2]} but counted ${mod}`);
}

// BUILD-STATUS.md TOTAL must agree.
const bsTotal = /\|\s*\*\*TOTAL\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|/.exec(build);
if (!bsTotal) errors.push('BUILD-STATUS.md: missing **TOTAL** row');
else if (Number(bsTotal[1]) !== actualTotal) {
  errors.push(`BUILD-STATUS.md: TOTAL=${bsTotal[1]} but traceability has ${actualTotal} rows`);
}

if (errors.length) {
  console.error('trace FAILED:');
  for (const e of errors) console.error('  - ' + e);
  process.exit(1);
}
console.log(`trace OK — ${actualTotal} requirements (core ${core} + module ${mod}); traceability.txt and BUILD-STATUS.md agree.`);
