// Property-based invariants for crypto (REQ-TEST-004): beacon seed is order-independent, sign/verify
// and commit/reveal always round-trip, and drawValue is always in range.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  genKeyPair, signData, verifyData, commit, verifyReveal, drawValue,
  verifyBeaconRound, partyId, keyPairFromPriv, ZERO_BEACON, type BeaconRound,
} from '../src/index.ts';
import { toHex } from '@bsv-universal/protocol-types';

function shuffle<T>(a: T[]): T[] {
  const out = [...a];
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomBytes(1)[0]! % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

test('INVARIANT: beacon seed is independent of reveal/commit ordering (200 rounds)', () => {
  for (let g = 0; g < 200; g++) {
    const n = 2 + (randomBytes(1)[0]! % 4);
    const ids = Array.from({ length: n }, (_, i) => partyId(keyPairFromPriv(new Uint8Array(32).fill((i + g) % 250 + 1)).pub));
    const secrets = ids.map(() => new Uint8Array(randomBytes(32)));
    const commits = ids.map((id, i) => ({ party: id, commitment: commit(secrets[i]!) }));
    const reveals = ids.map((id, i) => ({ party: id, secret: secrets[i]! }));
    const base: BeaconRound = { roundNo: 1, commits, reveals, prevBeacon: ZERO_BEACON };
    const r0 = verifyBeaconRound(base, ids);
    assert.equal(r0.ok, true);
    if (!r0.ok) continue;
    // permute commits + reveals + eligible — seed must be identical
    const permuted: BeaconRound = { roundNo: 1, commits: shuffle(commits), reveals: shuffle(reveals), prevBeacon: ZERO_BEACON };
    const r1 = verifyBeaconRound(permuted, shuffle(ids));
    assert.equal(r1.ok, true);
    if (r1.ok) assert.equal(toHex(r1.seed), toHex(r0.seed));
  }
});

test('INVARIANT: signData/verifyData always round-trips; wrong key always rejects (300 cases)', () => {
  for (let i = 0; i < 300; i++) {
    const kp = genKeyPair();
    const other = genKeyPair();
    const msg = new Uint8Array(randomBytes(1 + (randomBytes(1)[0]! % 80)));
    const sig = signData(msg, kp);
    assert.equal(verifyData(msg, sig, kp.pub), true);
    assert.equal(verifyData(msg, sig, other.pub), false);
  }
});

test('INVARIANT: commit/verifyReveal round-trips; foreign secret always rejects (500 cases)', () => {
  for (let i = 0; i < 500; i++) {
    const secret = new Uint8Array(randomBytes(1 + (randomBytes(1)[0]! % 64)));
    const other = new Uint8Array(randomBytes(32));
    const c = commit(secret);
    assert.equal(verifyReveal(secret, c), true);
    assert.equal(verifyReveal(other, c), false);
  }
});

test('INVARIANT: drawValue is always in [0, modulus) (5000 cases)', () => {
  for (let i = 0; i < 5000; i++) {
    const m = 1 + (randomBytes(1)[0]! % 200);
    const v = drawValue(new Uint8Array(randomBytes(32)), randomBytes(1)[0]!, m);
    assert.ok(v >= 0 && v < m, `out of range: ${v} not in [0,${m})`);
  }
});
