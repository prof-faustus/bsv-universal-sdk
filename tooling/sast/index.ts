// check:sast — static analysis gate enforcing the mission-critical standard by construction
// (SANS/CWE + NASA P10 + MS SDL). Scans production source (packages/*/src) and FAILS the build on
// any unsafe pattern. A defect CLASS forbidden here cannot re-enter the codebase silently.
//
// An intentional, justified exception must be fenced on the same line: `/* sast-ok: <reason> */`.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SRC_ROOTS = ['packages', 'apps'];
const FENCE = /\/\* *sast-ok:[^*]*\*\//;

interface Rule {
  readonly id: string; // CWE / NASA reference
  readonly name: string;
  readonly re: RegExp;
  readonly allow?: (relPath: string) => boolean; // file-scoped exception
}

const RULES: Rule[] = [
  { id: 'CWE-502', name: 'JSON.parse outside the safe wrapper (unsafe deserialization)', re: /\bJSON\.parse\s*\(/, allow: (p) => p.endsWith('protocol-types/src/index.ts') },
  { id: 'CWE-704', name: '`as any` unsafe cast', re: /\bas\s+any\b/ },
  { id: 'SUPPRESS', name: 'type/lint suppression (zero-suppression policy)', re: /@ts-(ignore|nocheck|expect-error)|eslint-disable/ },
  { id: 'NASA-P10-2', name: 'unbounded loop `for(;;)`', re: /\bfor\s*\(\s*;\s*;\s*\)/ },
  { id: 'NASA-P10-2', name: 'unbounded loop `while(true)`', re: /\bwhile\s*\(\s*true\s*\)/ },
  { id: 'CWE-338', name: 'Math.random in production code (non-crypto RNG)', re: /\bMath\.random\s*\(/ },
];

function* walkSrc(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      // production source only — tests are adversarial harnesses, scanned by their own bar
      if (name === 'test') continue;
      yield* walkSrc(p);
    } else if (name.endsWith('.ts') || name.endsWith('.tsx')) {
      yield p;
    }
  }
}

type Hit = { file: string; line: number; id: string; name: string; text: string };
const hits: Hit[] = [];

for (const root of SRC_ROOTS) {
  let base: string;
  try {
    base = join(ROOT, root);
    statSync(base);
  } catch {
    continue;
  }
  for (const file of walkSrc(base)) {
    const rel = file.slice(ROOT.length).split(sep).join('/');
    const lines = readFileSync(file, 'utf8').split(/\r?\n/);
    lines.forEach((text, i) => {
      if (FENCE.test(text)) return;
      for (const rule of RULES) {
        if (rule.allow?.(rel)) continue;
        if (rule.re.test(text)) hits.push({ file: rel, line: i + 1, id: rule.id, name: rule.name, text: text.trim() });
      }
    });
  }
}

if (hits.length > 0) {
  console.error(`check:sast FAILED — ${hits.length} unsafe pattern(s) in production source:\n`);
  for (const h of hits) {
    console.error(`  ${h.file}:${h.line}  [${h.id}] ${h.name}`);
    console.error(`      ${h.text}`);
  }
  console.error('\nFix the pattern, or (only if truly justified) fence the line with /* sast-ok: reason */');
  process.exit(1);
}

console.log('check:sast OK — no unsafe deserialization / casts / suppressions / unbounded loops / weak RNG.');
