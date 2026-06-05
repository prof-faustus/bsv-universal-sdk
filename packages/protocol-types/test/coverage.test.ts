// Branch-completion battery for protocol-types (REQ-TEST-010): exercises every exported guard/codec
// path so the determinism-critical serialization surface has no untested line/function.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  tryFromHex, txidFromHex, u32be, u64be, taggedHash, HASH_TAGS, bytesEqual,
  canonicalStringify, safeJsonParse, isObject, expectArray, expectHex, expectBoundedHex,
  expectInt, expectBool, expectOneOf,
} from '../src/index.ts';

test('tryFromHex both branches', () => {
  const ok = tryFromHex('00ff');
  assert.equal(ok.ok, true);
  if (ok.ok) assert.deepEqual([...ok.bytes], [0, 255]);
  assert.equal(tryFromHex('zz').ok, false);
});

test('txidFromHex valid + wrong length', () => {
  assert.equal(txidFromHex('ab'.repeat(32)).length, 32);
  assert.throws(() => txidFromHex('abcd'), /64 hex/);
});

test('u32be/u64be valid and range errors', () => {
  assert.deepEqual([...u32be(1)], [0, 0, 0, 1]);
  assert.throws(() => u32be(0x1_0000_0000), /out of range/);
  assert.deepEqual([...u64be(0n)], [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.throws(() => u64be(-1n), /out of range/);
  assert.throws(() => u64be(0x1_0000_0000_0000_0000n), /out of range/);
});

test('taggedHash domain separation + bytesEqual both branches', () => {
  const a = taggedHash(HASH_TAGS.state, new Uint8Array([1]));
  const b = taggedHash(HASH_TAGS.beacon, new Uint8Array([1]));
  assert.equal(bytesEqual(a, a), true);
  assert.equal(bytesEqual(a, b), false);
  assert.equal(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2])), false);
});

test('canonicalStringify covers string/bool/null/bigint values', () => {
  assert.equal(canonicalStringify({ s: 'hi', b: true, z: null, n: 5, big: 9n }), '{"b":true,"big":"9n","n":5,"s":"hi","z":null}');
  assert.equal(canonicalStringify(['x', false, null]), '["x",false,null]');
});

test('safeJsonParse: valid, non-string, oversize, malformed', () => {
  assert.equal(safeJsonParse('{"a":1}').ok, true);
  assert.equal(safeJsonParse(123 as unknown as string).ok, false);
  assert.equal(safeJsonParse('"' + 'a'.repeat(2_000_000) + '"', 1024).ok, false);
  assert.equal(safeJsonParse('{bad').ok, false);
});

test('isObject / expectArray / expectHex / expectBoundedHex guards', () => {
  assert.equal(isObject({}), true);
  assert.equal(isObject(null), false);
  assert.equal(isObject([]), false);
  assert.equal(isObject(5), false);
  assert.deepEqual(expectArray([1, 2], 5, 'f'), [1, 2]);
  assert.throws(() => expectArray('x', 5, 'f'), /must be an array/);
  assert.throws(() => expectArray([1, 2, 3], 2, 'f'), /exceeds max/);
  assert.equal(expectHex('aa'.repeat(4), 4, 'f').length, 4);
  assert.throws(() => expectHex('aa', 4, 'f'), /4-byte hex/);
  assert.throws(() => expectHex(5, 4, 'f'), /4-byte hex/);
  assert.equal(expectBoundedHex('aabb', 4, 'f').length, 2);
  assert.throws(() => expectBoundedHex('', 4, 'f'), /non-empty/);
  assert.throws(() => expectBoundedHex('abc', 4, 'f'), /non-empty/); // odd
  assert.throws(() => expectBoundedHex('aa'.repeat(5), 4, 'f'), /at most/);
});

test('expectInt / expectBool / expectOneOf', () => {
  assert.equal(expectInt(3, 0, 5, 'f'), 3);
  assert.throws(() => expectInt(9, 0, 5, 'f'), /out of range/);
  assert.equal(expectBool(true, 'f'), true);
  assert.throws(() => expectBool('x', 'f'), /must be a boolean/);
  assert.equal(expectOneOf('a', ['a', 'b'], 'f'), 'a');
  assert.throws(() => expectOneOf('z', ['a', 'b'], 'f'), /must be one of/);
});
