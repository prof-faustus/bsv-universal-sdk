// Property-based invariants for protocol-types (REQ-TEST-004 / REQ-DET-001/003): canonical output is
// independent of key insertion order, hashing is deterministic, and the hex codec round-trips.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { canonicalStringify, canonicalHash, fromHex, toHex, type Canonical } from '../src/index.ts';

// build a random canonical value of bounded depth
function randomCanon(depth: number): Canonical {
  const k = randomBytes(1)[0]! % (depth > 0 ? 6 : 4);
  switch (k) {
    case 0: return randomBytes(1)[0]!; // small int
    case 1: return randomBytes(4).toString('hex'); // string
    case 2: return randomBytes(1)[0]! % 2 === 0; // bool
    case 3: return null;
    case 4: return Array.from({ length: randomBytes(1)[0]! % 4 }, () => randomCanon(depth - 1));
    default: {
      const o: Record<string, Canonical> = {};
      const count = randomBytes(1)[0]! % 5;
      for (let i = 0; i < count; i++) o['k' + (randomBytes(1)[0]!)] = randomCanon(depth - 1);
      return o;
    }
  }
}

// rebuild an object with keys inserted in shuffled order (and recurse) — same logical value
function shuffleKeys(v: Canonical): Canonical {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v !== null && typeof v === 'object') {
    const keys = Object.keys(v);
    for (let i = keys.length - 1; i > 0; i--) {
      const j = randomBytes(1)[0]! % (i + 1);
      [keys[i], keys[j]] = [keys[j]!, keys[i]!];
    }
    const o: Record<string, Canonical> = {};
    for (const key of keys) o[key] = shuffleKeys((v as Record<string, Canonical>)[key]!);
    return o;
  }
  return v;
}

test('INVARIANT: canonicalStringify is independent of key insertion order (1000 values)', () => {
  for (let i = 0; i < 1000; i++) {
    const v = randomCanon(3);
    const a = canonicalStringify(v);
    const b = canonicalStringify(shuffleKeys(v));
    assert.equal(a, b);
    assert.equal(toHex(canonicalHash(v)), toHex(canonicalHash(shuffleKeys(v)))); // hash also stable
  }
});

test('INVARIANT: hex codec round-trips for arbitrary bytes (2000 cases)', () => {
  for (let i = 0; i < 2000; i++) {
    const b = new Uint8Array(randomBytes(randomBytes(1)[0]!));
    assert.deepEqual([...fromHex(toHex(b))], [...b]);
  }
});
