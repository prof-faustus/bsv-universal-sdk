// Fuzz battery (MS SDL / SANS): the script parser and interpreter are total on hostile bytes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { parseScript, evalScript, DEFAULT_LIMITS, type SigChecker } from '../src/index.ts';

const ITER = 8000;
const STUB: SigChecker = { check: () => randomBytes(1)[0]! % 2 === 0 };

test('parseScript is total over random byte strings', () => {
  for (let i = 0; i < ITER; i++) {
    const bytes = new Uint8Array(randomBytes(randomBytes(1)[0]! % 200));
    const r = parseScript(bytes, DEFAULT_LIMITS); // never throws
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('evalScript is total over random unlocking/locking scripts (never throws)', () => {
  for (let i = 0; i < ITER; i++) {
    const u = new Uint8Array(randomBytes(randomBytes(1)[0]! % 80));
    const l = new Uint8Array(randomBytes(randomBytes(1)[0]! % 120));
    const r = evalScript(u, l, STUB); // never throws on any bytes
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('evalScript never exceeds its bounds under adversarial nesting', () => {
  // deeply nested IFs without ENDIF, huge depth — must reject, not overflow
  const deep = new Uint8Array(Array.from({ length: 5000 }, () => 0x63 /* OP_IF */));
  const r = evalScript(new Uint8Array([0x51]), deep, STUB);
  assert.equal(r.ok, false);
});
