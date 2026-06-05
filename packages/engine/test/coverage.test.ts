// Branch-completion battery for the engine (REQ-TEST-010): the deal special-cases (equal-visible,
// consecutive), every settlement outcome (win/loss/loss-post), validateRuleset, and replay's
// total-on-throw guard.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  inBetweenModule as M, initInBetween, replay, validateRuleset,
  type InBetweenState, type Ruleset, type ContractModule, type Step,
} from '../src/index.ts';
import { keyPairFromPriv, partyId, randomBytes } from '@bsv-universal/crypto';
import { toHex } from '@bsv-universal/protocol-types';

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};
function fresh(): InBetweenState {
  const parties = [1, 2].map((i) => toHex(partyId(keyPairFromPriv(new Uint8Array(32).fill(i)).pub)));
  return initInBetween({ gameId: 'aa', parties, startingStack: 100n, roundsTotal: 99, ruleset: RULESET });
}
function dealOnce(s: InBetweenState, seedHex: string) {
  return M.apply(s, { kind: 'randomness', seedHex });
}
// find a randomness seed whose deal yields a state matching `want`
function findDeal(want: (s: InBetweenState) => boolean): { s: InBetweenState; outcome: string | null } {
  for (let i = 0; i < 5000; i++) {
    const r = dealOnce(fresh(), toHex(randomBytes(32)));
    if (r.ok && want(r.state)) return { s: r.state, outcome: r.state.lastOutcome };
  }
  throw new Error('no matching deal found');
}

test('deal special-cases: equal-visible penalty and consecutive auto-pass', () => {
  const eq = findDeal((s) => s.lastOutcome === 'equal-visible-penalty');
  assert.equal(eq.outcome, 'equal-visible-penalty');
  assert.equal(M.settle(eq.s).conserved, true);
  const cons = findDeal((s) => s.lastOutcome === 'consecutive-auto-pass');
  assert.equal(cons.outcome, 'consecutive-auto-pass');
  assert.equal(M.settle(cons.s).conserved, true);
});

test('settlement outcomes: win, loss, loss-post all reachable + conserve', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 8000 && seen.size < 3; i++) {
    const d = dealOnce(fresh(), toHex(randomBytes(32)));
    if (!d.ok || d.state.phase !== 'await-bet') continue;
    const bet = M.getLegalActions(d.state).find((a) => a.type === 'BET') as { party: string; max: bigint };
    const r = M.apply(d.state, { kind: 'action', action: { type: 'BET', party: bet.party, amount: bet.max >= 1n ? bet.max : 1n } });
    if (r.ok && r.state.lastOutcome) {
      seen.add(r.state.lastOutcome);
      assert.equal(M.settle(r.state).conserved, true);
    }
  }
  for (const o of ['win', 'loss', 'loss-post']) assert.ok(seen.has(o), `outcome ${o} not reached`);
});

test('validateRuleset accepts valid and rejects each invalid', () => {
  assert.doesNotThrow(() => validateRuleset(RULESET));
  assert.throws(() => validateRuleset({ ...RULESET, postPenaltyMultiplier: 0 }), /postPenaltyMultiplier/);
  assert.throws(() => validateRuleset({ ...RULESET, minPlayers: 1 }), /minPlayers/);
  assert.throws(() => validateRuleset({ ...RULESET, maxPlayers: 9 }), /maxPlayers/);
  assert.throws(() => validateRuleset({ ...RULESET, maxBet: 0n }), /bet bounds/);
  assert.throws(() => validateRuleset({ ...RULESET, ante: -1n }), /must be ≥ 0/);
});

test('init validation + timeoutBranch both branches', () => {
  const p = [1, 2].map((i) => toHex(partyId(keyPairFromPriv(new Uint8Array(32).fill(i)).pub)));
  assert.throws(() => initInBetween({ gameId: 'a', parties: [p[0]!], startingStack: 100n, roundsTotal: 3, ruleset: RULESET }), /player count/);
  assert.throws(() => initInBetween({ gameId: 'a', parties: [p[0]!, p[0]!], startingStack: 100n, roundsTotal: 3, ruleset: RULESET }), /duplicate party/);
  const s = fresh();
  assert.equal(M.timeoutBranch(s), null); // deck-commitment → null
  const dealt = (() => {
    for (let i = 0; i < 5000; i++) {
      const r = dealOnce(fresh(), toHex(randomBytes(32)));
      if (r.ok && r.state.phase === 'await-bet') return r.state;
    }
    throw new Error('no await-bet');
  })();
  assert.equal(M.timeoutBranch(dealt), 'pass'); // await-bet → 'pass'
});

test('replay is total even if a module throws (REQ-ENG-004)', () => {
  const throwing: ContractModule<{ x: number }> = {
    id: 'throwing',
    apply() {
      throw new Error('boom');
    },
    getLegalActions: () => [],
    expectsRandomness: () => false,
    timeoutBranch: () => null,
    isComplete: () => false,
    settle: () => ({ balances: {}, conserved: true }),
  };
  const steps: Step[] = [{ kind: 'timeout', branch: 'x' }];
  const r = replay(throwing, { x: 0 }, steps);
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.match(r.reason, /threw/);
    assert.equal(r.atStep, 0);
  }
});
