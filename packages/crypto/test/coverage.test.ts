// Branch-completion battery for crypto (REQ-TEST-010): bitcoin-sighash sign/verify, hash160,
// randomBytes, and every early-reject branch of verifyBeaconRound.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  genKeyPair, keyPairFromPriv, partyId, signBitcoin, verifyBitcoin, hash160, randomBytes,
  drawValue, beaconValue, verifyBeaconRound, commit, MAX_PARTIES, ZERO_BEACON, type BeaconRound,
} from '../src/index.ts';
import { taggedHash, HASH_TAGS, u32be, toHex } from '@bsv-universal/protocol-types';

test('signBitcoin / verifyBitcoin round-trip + rejections', () => {
  const kp = genKeyPair();
  const other = genKeyPair();
  const pre = randomBytes(48);
  const der = signBitcoin(pre, kp);
  assert.equal(verifyBitcoin(pre, der, kp.pub), true);
  assert.equal(verifyBitcoin(pre, der, other.pub), false); // wrong key
  assert.equal(verifyBitcoin(randomBytes(48), der, kp.pub), false); // tampered preimage
  assert.equal(verifyBitcoin(pre, der, randomBytes(33)), false); // bad pub (not 65/0x04) → false, no throw
  assert.equal(verifyBitcoin(pre, new Uint8Array([1, 2, 3]), kp.pub), false); // junk sig
});

test('hash160 length, randomBytes bounds, keyPairFromPriv validation', () => {
  assert.equal(hash160(new Uint8Array([1, 2, 3])).length, 20);
  assert.equal(randomBytes(16).length, 16);
  assert.throws(() => randomBytes(-1), /out of range/);
  assert.throws(() => keyPairFromPriv(new Uint8Array(31)), /32 bytes/);
});

test('drawValue loop + bad modulus; beaconValue length', () => {
  const seed = taggedHash(HASH_TAGS.state, u32be(7));
  assert.ok(drawValue(seed, 0, 6) >= 0);
  assert.throws(() => drawValue(seed, 0, 0), /modulus/);
  assert.equal(beaconValue(seed).length, 32);
});

function idOf(seed: number) {
  return partyId(keyPairFromPriv(new Uint8Array(32).fill(seed || 1)).pub);
}

test('verifyBeaconRound early-reject branches', () => {
  const a = idOf(1);
  const b = idOf(2);
  const eligible = [a, b];
  const secrets = [new Uint8Array([1]), new Uint8Array([2])];
  const valid: BeaconRound = {
    roundNo: 1,
    commits: [{ party: a, commitment: commit(secrets[0]!) }, { party: b, commitment: commit(secrets[1]!) }],
    reveals: [{ party: a, secret: secrets[0]! }, { party: b, secret: secrets[1]! }],
    prevBeacon: ZERO_BEACON,
  };
  assert.equal(verifyBeaconRound(valid, eligible).ok, true);
  // non-object round
  assert.equal(verifyBeaconRound(null as unknown as BeaconRound, eligible).ok, false);
  // commits/reveals not arrays
  assert.equal(verifyBeaconRound({ ...valid, commits: 'x' as unknown as [] }, eligible).ok, false);
  // roundNo out of range
  assert.equal(verifyBeaconRound({ ...valid, roundNo: -1 }, eligible).ok, false);
  // eligible empty
  assert.equal(verifyBeaconRound(valid, []).ok, false);
  // eligible too big
  assert.equal(verifyBeaconRound(valid, Array.from({ length: MAX_PARTIES + 1 }, (_, i) => idOf(i + 3))).ok, false);
  // too many commits
  assert.equal(verifyBeaconRound({ ...valid, commits: Array.from({ length: MAX_PARTIES + 1 }, () => ({ party: a, commitment: commit(secrets[0]!) })) }, eligible).ok, false);
  // commitment not 32 bytes
  assert.equal(verifyBeaconRound({ ...valid, commits: [{ party: a, commitment: new Uint8Array(5) }] }, eligible).ok, false);
  // prevBeacon not 32 bytes (with otherwise-valid single-party round)
  const single: BeaconRound = { roundNo: 1, commits: [{ party: a, commitment: commit(secrets[0]!) }], reveals: [{ party: a, secret: secrets[0]! }], prevBeacon: new Uint8Array(8) };
  assert.equal(verifyBeaconRound(single, [a]).ok, false);
  void toHex;
});
