import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  fromHex,
  tryFromHex,
  toHex,
  txidFromHex,
  canonicalStringify,
  canonicalHash,
  taggedHash,
  HASH_TAGS,
  expectInt,
  expectOneOf,
  u32be,
  u64be,
} from '../src/index.ts';

// ---- REQ-SEC-009 : strict hex codec
test('fromHex rejects odd length, non-hex; accepts valid', () => {
  assert.deepEqual([...fromHex('00ff10')], [0, 255, 16]);
  assert.throws(() => fromHex('abc'), /bad hex/); // odd length
  assert.throws(() => fromHex('zz'), /bad hex/); // non-hex
  assert.throws(() => fromHex('0x10'), /bad hex/); // 0x prefix not hex
  // no silent zero-bytes: a malformed string never becomes a buffer
  const r = tryFromHex('nothex');
  assert.equal(r.ok, false);
});

test('toHex round-trips fromHex', () => {
  const b = new Uint8Array([0, 1, 254, 255]);
  assert.equal(toHex(b), '0001feff');
  assert.deepEqual([...fromHex(toHex(b))], [...b]);
});

test('txidFromHex requires exactly 64 hex chars (REQ-SEC-006)', () => {
  assert.throws(() => txidFromHex('00'.repeat(31)), /64 hex/);
  assert.equal(txidFromHex('ab'.repeat(32)).length, 32);
});

// ---- REQ-DET-001/002/003 : canonical serialization
test('canonicalStringify sorts keys and is order-independent', () => {
  const a = canonicalStringify({ b: 1, a: 2, c: [3, 2, 1] });
  const b = canonicalStringify({ c: [3, 2, 1], a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":2,"b":1,"c":[3,2,1]}');
});

test('canonicalStringify rejects floats (REQ-DET-002)', () => {
  assert.throws(() => canonicalStringify({ x: 1.5 }), /non-integer/);
});

test('canonicalStringify encodes bigint unambiguously', () => {
  assert.equal(canonicalStringify({ sats: 2100000000000000n }), '{"sats":"2100000000000000n"}');
});

test('canonicalHash is stable and domain-separated', () => {
  const h1 = canonicalHash({ a: 1, b: 2 });
  const h2 = canonicalHash({ b: 2, a: 1 });
  assert.deepEqual([...h1], [...h2]);
  // different tag → different hash for same bytes (REQ-DET-005)
  const raw = new Uint8Array([1, 2, 3]);
  assert.notDeepEqual([...taggedHash(HASH_TAGS.state, raw)], [...taggedHash(HASH_TAGS.commit, raw)]);
});

// ---- REQ-SEC-006 : strict integer/enum guards
test('expectInt / expectOneOf reject out-of-range', () => {
  assert.equal(expectInt(5, 0, 5, 'x'), 5);
  assert.throws(() => expectInt(6, 0, 5, 'x'), /out of range/);
  assert.throws(() => expectInt(1.2, 0, 5, 'x'), /out of range/);
  assert.equal(expectOneOf('TITLE', ['TITLE', 'REPRIEVE'], 'kind'), 'TITLE');
  assert.throws(() => expectOneOf('BOGUS', ['TITLE', 'REPRIEVE'], 'kind'), /must be one of/);
});

test('u32be / u64be range-check', () => {
  assert.deepEqual([...u32be(0x01020304)], [1, 2, 3, 4]);
  assert.throws(() => u32be(-1), /out of range/);
  assert.deepEqual([...u64be(1n)], [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.throws(() => u64be(-1n), /out of range/);
});
