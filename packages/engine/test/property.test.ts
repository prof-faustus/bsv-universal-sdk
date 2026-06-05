// Property-based invariants for the engine (REQ-TEST-004). Over thousands of generated games these
// universal properties MUST always hold — value conservation, non-negative balances, and replay
// determinism / incremental==replay equivalence.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inBetweenModule as M, initInBetween, replay, type InBetweenState, type Ruleset, type Step } from '../src/index.ts';
import { keyPairFromPriv, partyId } from '@bsv-universal/crypto';
import { toHex, canonicalHash } from '@bsv-universal/protocol-types';

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};
function parties(n: number, salt: number): string[] {
  return Array.from({ length: n }, (_, i) => toHex(partyId(keyPairFromPriv(new Uint8Array(32).fill((i + salt) % 250 + 1)).pub)));
}
function freshGame(salt: number): InBetweenState {
  const n = 2 + (randomBytes(1)[0]! % 5);
  return initInBetween({ gameId: toHex(randomBytes(4)), parties: parties(n, salt), startingStack: 100n, roundsTotal: 5, ruleset: RULESET });
}

// play a random game, recording the steps actually applied
function playRandom(salt: number): { initial: InBetweenState; steps: Step[]; final: InBetweenState } {
  const initial = freshGame(salt);
  let s = initial;
  const steps: Step[] = [];
  let guard = 0;
  while (!M.isComplete(s) && guard++ < 80) {
    let step: Step;
    if (M.expectsRandomness(s)) {
      step = { kind: 'randomness', seedHex: toHex(randomBytes(32)) };
    } else {
      const bet = M.getLegalActions(s).find((a) => a.type === 'BET') as { party: string; min: bigint; max: bigint };
      const c = randomBytes(1)[0]! % 3;
      step = c === 0
        ? { kind: 'action', action: { type: 'PASS', party: bet.party } }
        : { kind: 'action', action: { type: 'BET', party: bet.party, amount: bet.max >= bet.min ? bet.max : bet.min } };
    }
    const r = M.apply(s, step);
    if (!r.ok) continue;
    s = r.state;
    steps.push(step);
  }
  return { initial, steps, final: s };
}

test('INVARIANT: value is conserved and balances stay non-negative at every step (500 games)', () => {
  for (let g = 0; g < 500; g++) {
    let s = freshGame(g);
    let guard = 0;
    while (!M.isComplete(s) && guard++ < 80) {
      const step: Step = M.expectsRandomness(s)
        ? { kind: 'randomness', seedHex: toHex(randomBytes(32)) }
        : (() => {
            const bet = M.getLegalActions(s).find((a) => a.type === 'BET') as { party: string; min: bigint; max: bigint };
            return randomBytes(1)[0]! % 2 === 0
              ? { kind: 'action', action: { type: 'BET', party: bet.party, amount: bet.max >= bet.min ? bet.max : bet.min } }
              : { kind: 'action', action: { type: 'PASS', party: bet.party } };
          })();
      const r = M.apply(s, step);
      if (!r.ok) continue;
      s = r.state;
      const settle = M.settle(s);
      assert.equal(settle.conserved, true, `conservation broke (${s.lastOutcome})`);
      for (const [, bal] of s.balances) assert.ok(bal >= 0n, 'balance went negative');
      assert.ok(s.pot >= 0n, 'pot went negative');
    }
  }
});

test('INVARIANT: replay is deterministic and equals incremental application (300 games)', () => {
  for (let g = 0; g < 300; g++) {
    const { initial, steps, final } = playRandom(g + 1000);
    const r1 = replay(M, initial, steps);
    const r2 = replay(M, initial, steps);
    assert.equal(r1.ok, true);
    assert.equal(r2.ok, true);
    if (r1.ok && r2.ok) {
      assert.deepEqual(toHex(canonicalHash(r1.state as never)), toHex(canonicalHash(r2.state as never))); // deterministic
      assert.deepEqual(toHex(canonicalHash(r1.state as never)), toHex(canonicalHash(final as never))); // == incremental
      assert.deepEqual(r1.state, final);
    }
  }
});

test('INVARIANT: total value never changes from the initial total (200 games)', () => {
  for (let g = 0; g < 200; g++) {
    const { initial, final } = playRandom(g + 5000);
    assert.equal(final.total, initial.total);
    let sum = final.pot;
    for (const [, b] of final.balances) sum += b;
    assert.equal(sum, initial.total);
  }
});
