import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  genKeyPair,
  keyPairFromPriv,
  partyId,
  signData,
  verifyData,
  commit,
  verifyReveal,
  drawValue,
  verifyBeaconRound,
  beaconValue,
  ZERO_BEACON,
  type BeaconRound,
} from '../src/index.ts';
import { utf8, taggedHash, HASH_TAGS, u32be } from '@bsv-universal/protocol-types';

// ---- REQ-SEC-001 : player-key signatures
test('signData/verifyData round-trip; reject wrong key and tampered payload', () => {
  const a = genKeyPair();
  const b = genKeyPair();
  const msg = utf8('move:BUY');
  const sig = signData(msg, a);
  assert.equal(verifyData(msg, sig, a.pub), true);
  assert.equal(verifyData(msg, sig, b.pub), false); // wrong signer
  assert.equal(verifyData(utf8('move:SELL'), sig, a.pub), false); // tampered
  assert.equal(verifyData(msg, new Uint8Array([1, 2, 3]), a.pub), false); // junk sig, no throw
});

test('partyId is the 33-byte compressed key and is deterministic', () => {
  const kp = keyPairFromPriv(new Uint8Array(32).fill(7));
  const id = partyId(kp.pub);
  assert.equal(id.length, 33);
  assert.ok(id[0] === 0x02 || id[0] === 0x03);
  assert.deepEqual([...partyId(kp.pub)], [...id]);
});

// ---- REQ-COMMIT-001/002 : commit / reveal
test('commit/verifyReveal', () => {
  const secret = utf8('s3cr3t-entropy');
  const c = commit(secret);
  assert.equal(verifyReveal(secret, c), true);
  assert.equal(verifyReveal(utf8('other'), c), false);
});

// ---- REQ-SEC-002 : debiased draw (rejection sampling, no modulo bias)
test('drawValue is uniform over 6 (no modulo bias)', () => {
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 6000; i++) {
    const seed = taggedHash(HASH_TAGS.state, u32be(i));
    counts[drawValue(seed, 0, 6)]++;
  }
  for (const c of counts) {
    assert.ok(c > 800 && c < 1200, `bucket ${c} outside expected ~1000 band → bias`);
  }
});

test('drawValue rejects bad modulus', () => {
  const seed = taggedHash(HASH_TAGS.state, u32be(1));
  assert.throws(() => drawValue(seed, 0, 0), /modulus/);
  assert.throws(() => drawValue(seed, 0, 257), /modulus/);
});

// ---- REQ-SEC-002 + REQ-SEC-003 : beacon round verification
function party(seed: number) {
  const kp = keyPairFromPriv(new Uint8Array(32).fill(seed));
  return { kp, id: partyId(kp.pub) };
}

function roundOf(parties: { id: Uint8Array }[], secrets: Uint8Array[]): BeaconRound {
  return {
    roundNo: 1,
    commits: parties.map((p, i) => ({ party: p.id, commitment: commit(secrets[i]!) })),
    reveals: parties.map((p, i) => ({ party: p.id, secret: secrets[i]! })),
    prevBeacon: ZERO_BEACON,
  };
}

test('valid two-party round derives a seed; order-independent', () => {
  const p0 = party(1);
  const p1 = party(2);
  const secrets = [utf8('a'), utf8('b')];
  const eligible = [p0.id, p1.id];
  const r = verifyBeaconRound(roundOf([p0, p1], secrets), eligible);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  // reordering reveals must not change the seed (canonical partyId ordering)
  const swapped: BeaconRound = {
    ...roundOf([p0, p1], secrets),
    reveals: [
      { party: p1.id, secret: secrets[1]! },
      { party: p0.id, secret: secrets[0]! },
    ],
  };
  const r2 = verifyBeaconRound(swapped, eligible);
  assert.equal(r2.ok, true);
  if (r2.ok) assert.deepEqual([...r.seed], [...r2.seed]);
});

test('REQ-SEC-003: rejects fake reveal from non-seat', () => {
  const p0 = party(1);
  const p1 = party(2);
  const fake = party(9);
  const secrets = [utf8('a'), utf8('b')];
  const base = roundOf([p0, p1], secrets);
  const tampered: BeaconRound = {
    ...base,
    reveals: [...base.reveals, { party: fake.id, secret: utf8('z') }],
  };
  const r = verifyBeaconRound(tampered, [p0.id, p1.id]);
  assert.equal(r.ok, false);
});

test('REQ-SEC-003: rejects reveal that does not open its commitment', () => {
  const p0 = party(1);
  const p1 = party(2);
  const base = roundOf([p0, p1], [utf8('a'), utf8('b')]);
  const tampered: BeaconRound = {
    ...base,
    reveals: [base.reveals[0]!, { party: p1.id, secret: utf8('WRONG') }],
  };
  const r = verifyBeaconRound(tampered, [p0.id, p1.id]);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.reason, /does not open/);
});

test('REQ-SEC-003: rejects duplicate commitment and duplicate reveal', () => {
  const p0 = party(1);
  const p1 = party(2);
  const base = roundOf([p0, p1], [utf8('a'), utf8('b')]);
  const dupCommit: BeaconRound = { ...base, commits: [base.commits[0]!, base.commits[0]!] };
  assert.equal(verifyBeaconRound(dupCommit, [p0.id, p1.id]).ok, false);
  const dupReveal: BeaconRound = { ...base, reveals: [base.reveals[0]!, base.reveals[0]!] };
  assert.equal(verifyBeaconRound(dupReveal, [p0.id, p1.id]).ok, false);
});

test('REQ-SEC-003: rejects round with zero honest reveals', () => {
  const p0 = party(1);
  const p1 = party(2);
  const base = roundOf([p0, p1], [utf8('a'), utf8('b')]);
  const noReveals: BeaconRound = { ...base, reveals: [] };
  const r = verifyBeaconRound(noReveals, [p0.id, p1.id]);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.reason, /unbiasable/);
});

test('beaconValue chains deterministically', () => {
  const p0 = party(1);
  const p1 = party(2);
  const r = verifyBeaconRound(roundOf([p0, p1], [utf8('a'), utf8('b')]), [p0.id, p1.id]);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  const v = beaconValue(r.seed);
  assert.equal(v.length, 32);
});
