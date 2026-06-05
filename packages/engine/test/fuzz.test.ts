// Fuzz battery (MS SDL / SANS): the engine apply/replay are total on hostile steps (REQ-ENG-004).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inBetweenModule as M, initInBetween, replay, type InBetweenState, type Ruleset, type Step } from '../src/index.ts';
import { keyPairFromPriv, partyId } from '@bsv-universal/crypto';
import { toHex } from '@bsv-universal/protocol-types';

const ITER = 5000;

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};

function freshState(): InBetweenState {
  const parts = [1, 2, 3].map((i) => toHex(partyId(keyPairFromPriv(new Uint8Array(32).fill(i)).pub)));
  return initInBetween({ gameId: 'ab', parties: parts, startingStack: 100n, roundsTotal: 4, ruleset: RULESET });
}

function randomStep(parties: readonly string[]): Step {
  const k = randomBytes(1)[0]! % 3;
  if (k === 0) return { kind: 'randomness', seedHex: randomBytes(randomBytes(1)[0]! % 40).toString('hex') };
  if (k === 1) return { kind: 'timeout', branch: ['pass', 'evil', ''][randomBytes(1)[0]! % 3]! };
  const party = randomBytes(1)[0]! % 2 ? parties[randomBytes(1)[0]! % parties.length]! : randomBytes(33).toString('hex');
  const type = ['BET', 'PASS', 'HACK'][randomBytes(1)[0]! % 3]!;
  return { kind: 'action', action: { type, party, amount: BigInt(randomBytes(2).readUInt16BE(0)) } };
}

test('apply is total over 5000 random steps from a fresh state (never throws)', () => {
  const s = freshState();
  for (let i = 0; i < ITER; i++) {
    const r = M.apply(s, randomStep(s.parties)); // never throws
    assert.equal(typeof r.ok, 'boolean');
    if (r.ok) assert.equal(M.settle(r.state).conserved, true); // any accepted transition conserves value
  }
});

test('replay is total over random step sequences (REQ-ENG-004) and conserves on success', () => {
  for (let t = 0; t < 300; t++) {
    const s = freshState();
    const steps: Step[] = Array.from({ length: randomBytes(1)[0]! % 40 }, () => randomStep(s.parties));
    const r = replay(M, s, steps); // never throws
    assert.equal(typeof r.ok, 'boolean');
    if (r.ok) assert.equal(M.settle(r.state).conserved, true);
  }
});

test('apply rejects steps whose seed is bad hex without throwing', () => {
  const s = freshState();
  for (const bad of ['', 'zz', 'abc', '0'.repeat(63), '0'.repeat(66)]) {
    const r = M.apply(s, { kind: 'randomness', seedHex: bad });
    assert.equal(r.ok, false);
  }
});
