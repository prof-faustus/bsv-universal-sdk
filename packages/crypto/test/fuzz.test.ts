// Fuzz battery (MS SDL / SANS): crypto verifiers are total on hostile input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { verifyBeaconRound, verifyData, drawValue, genKeyPair, type BeaconRound } from '../src/index.ts';
import { taggedHash, HASH_TAGS, u32be } from '@bsv-universal/protocol-types';

const ITER = 4000;
const rb = (n: number) => new Uint8Array(randomBytes(n));

test('verifyBeaconRound is total over random hostile rounds (never throws)', () => {
  const eligible = [rb(33), rb(33)];
  for (let i = 0; i < ITER; i++) {
    const nC = randomBytes(1)[0]! % 80; // sometimes exceeds MAX_PARTIES → must reject, not crash
    const nR = randomBytes(1)[0]! % 80;
    const round: BeaconRound = {
      roundNo: (randomBytes(4).readUInt32BE(0) % 0xffffffff),
      commits: Array.from({ length: nC }, () => ({ party: rb(33), commitment: rb(32) })),
      reveals: Array.from({ length: nR }, () => ({ party: rb(33), secret: rb(1 + (randomBytes(1)[0]! % 64)) })),
      prevBeacon: rb(32),
    };
    const r = verifyBeaconRound(round, eligible); // must never throw
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('verifyBeaconRound rejects malformed shapes without throwing', () => {
  const eligible = [rb(33)];
  const bad = [
    null,
    {},
    { commits: 'x', reveals: [], roundNo: 0, prevBeacon: rb(32) },
    { commits: [], reveals: [], roundNo: -1, prevBeacon: rb(32) },
    { commits: [], reveals: [], roundNo: 0, prevBeacon: rb(8) },
  ];
  for (const b of bad) {
    const r = verifyBeaconRound(b as unknown as BeaconRound, eligible);
    assert.equal(r.ok, false);
  }
});

test('verifyData is total over random sig/pub/payload (never throws)', () => {
  const kp = genKeyPair();
  for (let i = 0; i < ITER; i++) {
    const payload = rb(1 + (randomBytes(1)[0]! % 64));
    const sig = rb(randomBytes(1)[0]! % 80);
    const pub = randomBytes(1)[0]! % 2 === 0 ? rb(65) : kp.pub;
    const r = verifyData(payload, sig, pub); // must never throw
    assert.equal(typeof r, 'boolean');
  }
});

test('drawValue stays in range and rejects bad modulus', () => {
  for (let i = 0; i < 1000; i++) {
    const seed = taggedHash(HASH_TAGS.state, u32be(i));
    const m = 1 + (randomBytes(1)[0]! % 200);
    const v = drawValue(seed, i % 7, m);
    assert.ok(v >= 0 && v < m);
  }
  assert.throws(() => drawValue(rb(32), 0, 0));
  assert.throws(() => drawValue(rb(32), 0, 257));
});
