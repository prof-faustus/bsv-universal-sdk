// check:bans — static ban scanner (REQ-BAN-001..005).
//
// Hard bans, AUTOMATIC-REJECT: BSV-only, no BTC artifacts. Any hit outside an explicit
// negative-test fence fails the build. The fence lets REQ-TEST-002 ship ban-bearing-script
// NEGATIVES (a test that asserts a banned construct is rejected) without tripping the scanner:
// a line ending with the marker `/* ban-ok: <reason> */` is allowed, and a file may open a
// block fence with `// ban-fence:open <reason>` ... `// ban-fence:close`.
//
// Scope: TypeScript under packages/ and tooling/. Spec/markdown docs are NOT scanned (they
// legitimately name the banned opcodes to forbid them).

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCAN_DIRS = ['packages', 'apps', 'tooling'];
// The scanner itself must NAME the banned tokens to detect them; exclude its own directory.
const EXCLUDE = ['tooling/check-bans'];
const FENCE_LINE = /\/\* *ban-ok:[^*]*\*\/ *$/;
const FENCE_OPEN = /\/\/ *ban-fence:open\b/;
const FENCE_CLOSE = /\/\/ *ban-fence:close\b/;

// Each rule: a REQ id and a matcher. Matchers are word-bounded to avoid matching this file's
// own prose in comments like "the OP_RETURN ban" — we match the opcode TOKEN as code would use it.
const RULES: { req: string; name: string; re: RegExp }[] = [
  { req: 'REQ-BAN-001', name: 'OP_RETURN', re: /\bOP_RETURN\b/ },
  { req: 'REQ-BAN-002', name: 'OP_CHECKLOCKTIMEVERIFY (CLTV)', re: /\bOP_CHECKLOCKTIMEVERIFY\b/ },
  { req: 'REQ-BAN-003', name: 'OP_CHECKSEQUENCEVERIFY (CSV)', re: /\bOP_CHECKSEQUENCEVERIFY\b/ },
  // BTC-only artifacts: mainnet BTC address prefixes / chains / explorers that imply non-BSV.
  { req: 'REQ-BAN-004', name: 'BTC-only token', re: /\b(blockstream\.info|bitcoincore|testnet3|signet|taproot|OP_CHECKLOCKTIMEVERIFY)\b/i },
];

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) yield* walk(p);
    else if (name.endsWith('.ts')) yield p;
  }
}

type Hit = { file: string; line: number; req: string; name: string; text: string };
const hits: Hit[] = [];

for (const d of SCAN_DIRS) {
  let base: string;
  try {
    base = join(ROOT, d);
    statSync(base);
  } catch {
    continue;
  }
  for (const file of walk(base)) {
    const rel = file.slice(ROOT.length).split(sep).join('/');
    if (EXCLUDE.some((x) => rel.includes(x))) continue;
    const lines = readFileSync(file, 'utf8').split(/\r?\n/);
    let fenced = false;
    lines.forEach((text, i) => {
      if (FENCE_OPEN.test(text)) fenced = true;
      if (FENCE_CLOSE.test(text)) fenced = false;
      if (fenced || FENCE_LINE.test(text)) return;
      for (const rule of RULES) {
        if (rule.re.test(text)) {
          hits.push({ file: file.slice(ROOT.length), line: i + 1, req: rule.req, name: rule.name, text: text.trim() });
        }
      }
    });
  }
}

if (hits.length > 0) {
  console.error(`check:bans FAILED — ${hits.length} banned construct(s) outside a negative-test fence:\n`);
  for (const h of hits) {
    console.error(`  ${h.file.split(sep).join('/')}:${h.line}  [${h.req}] ${h.name}`);
    console.error(`      ${h.text}`);
  }
  console.error('\nIf this is an intentional negative test, fence it: end the line with /* ban-ok: reason */');
  process.exit(1);
}

console.log('check:bans OK — no OP_RETURN / CLTV / CSV / BTC-only tokens (REQ-BAN-001..005).');
