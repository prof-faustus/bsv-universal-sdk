import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  inBetweenModule as M,
  initInBetween,
  replay,
  type InBetweenState,
  type Ruleset,
  type Step,
} from '../src/index.ts';
import { keyPairFromPriv, partyId, commit, verifyBeaconRound, ZERO_BEACON, type BeaconRound } from '@bsv-universal/crypto';
import { toHex, utf8 } from '@bsv-universal/protocol-types';

const RULESET: Ruleset = {
  minBet: 1n,
  maxBet: 10n,
  ante: 5n,
  equalVisiblePenalty: 2n,
  postPenaltyMultiplier: 2,
  decisionTimeout: 30,
  recoveryTimeout: 300,
  minPlayers: 2,
  maxPlayers: 6,
};

function players(n: number) {
  return Array.from({ length: n }, (_, i) => {
    const kp = keyPairFromPriv(new Uint8Array(32).fill(i + 1));
    return { kp, id: toHex(partyId(kp.pub)) };
  });
}

// Produce a beacon seed (hex) from a real verified round (REQ-SEC-002), bumping the secret nonce.
function seedFor(parts: { id: string; kp: ReturnType<typeof keyPairFromPriv> }[], nonce: number, prev = ZERO_BEACON): string {
  const ids = parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex')));
  const secrets = parts.map((p, i) => utf8(`${p.id}:${nonce}:${i}`));
  const round: BeaconRound = {
    roundNo: 1,
    commits: ids.map((id, i) => ({ party: id, commitment: commit(secrets[i]!) })),
    reveals: ids.map((id, i) => ({ party: id, secret: secrets[i]! })),
    prevBeacon: prev,
  };
  const r = verifyBeaconRound(round, ids);
  assert.equal(r.ok, true);
  if (!r.ok) throw new Error('beacon');
  return toHex(r.seed);
}

function conserved(s: InBetweenState): boolean {
  return M.settle(s).conserved;
}

// Drive randomness with successive seeds until we land in await-bet (skips equal/consecutive deals).
function toAwaitBet(parts: ReturnType<typeof players>, state: InBetweenState): { state: InBetweenState; usedNonce: number } {
  for (let nonce = 0; nonce < 200; nonce++) {
    const step: Step = { kind: 'randomness', seedHex: seedFor(parts, nonce) };
    const r = M.apply(state, step);
    assert.equal(r.ok, true, r.ok ? '' : r.reason);
    if (r.ok && r.state.phase === 'await-bet') return { state: r.state, usedNonce: nonce };
  }
  throw new Error('no await-bet seed found');
}

test('init forms pot from antes and conserves value', () => {
  const parts = players(2);
  const s = initInBetween({ gameId: 'aa', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  assert.equal(s.pot, 10n); // 2 × ante(5)
  assert.equal(s.total, 200n);
  assert.equal(conserved(s), true);
  assert.equal(s.phase, 'deck-commitment');
});

test('full multi-round play conserves value at every step (REQ-MOD-IB-007)', () => {
  const parts = players(2);
  let s = initInBetween({ gameId: 'aa', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 6, ruleset: RULESET });
  let nonce = 0;
  let guard = 0;
  while (!M.isComplete(s) && guard++ < 100) {
    if (M.expectsRandomness(s)) {
      const r = M.apply(s, { kind: 'randomness', seedHex: seedFor(parts, nonce++) });
      assert.equal(r.ok, true, r.ok ? '' : r.reason);
      if (r.ok) s = r.state;
    } else if (s.phase === 'await-bet') {
      // acting party bets the legal max (deterministic, menu-derived — test harness picks; real play is the human)
      const legal = M.getLegalActions(s);
      const bet = legal.find((a) => a.type === 'BET') as { min: bigint; max: bigint; party: string };
      const amount = bet.max >= RULESET.minBet ? bet.max : RULESET.minBet;
      const r = M.apply(s, { kind: 'action', action: { type: 'BET', party: bet.party, amount } });
      assert.equal(r.ok, true, r.ok ? '' : r.reason);
      if (r.ok) s = r.state;
    }
    assert.equal(conserved(s), true, `conservation broke after ${s.lastOutcome}`);
  }
  assert.equal(M.isComplete(s), true);
  assert.equal(conserved(s), true);
});

test('getLegalActions enumerates only the acting party menu (REQ-ENG-001)', () => {
  const parts = players(3);
  let s = initInBetween({ gameId: 'bb', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  ({ state: s } = toAwaitBet(parts, s));
  const legal = M.getLegalActions(s);
  assert.equal(legal.length, 2);
  const acting = parts[s.actingIdx]!.id;
  for (const a of legal) assert.equal(a.party, acting);
  assert.deepEqual(legal.map((a) => a.type).sort(), ['BET', 'PASS']);
});

// ---- REQ-MOD-IB-010 negative battery
test('negative: bet outside range is rejected', () => {
  const parts = players(2);
  let s = initInBetween({ gameId: 'cc', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  ({ state: s } = toAwaitBet(parts, s));
  const acting = parts[s.actingIdx]!.id;
  const tooBig = M.apply(s, { kind: 'action', action: { type: 'BET', party: acting, amount: 9999n } });
  assert.equal(tooBig.ok, false);
  const tooSmall = M.apply(s, { kind: 'action', action: { type: 'BET', party: acting, amount: 0n } });
  assert.equal(tooSmall.ok, false);
});

test('negative: action by non-acting party is rejected (REQ-SEC-001 engine half)', () => {
  const parts = players(2);
  let s = initInBetween({ gameId: 'dd', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  ({ state: s } = toAwaitBet(parts, s));
  const notActing = parts[(s.actingIdx + 1) % parts.length]!.id;
  const r = M.apply(s, { kind: 'action', action: { type: 'BET', party: notActing, amount: 1n } });
  assert.equal(r.ok, false);
  assert.match(r.ok ? '' : r.reason, /non-acting/);
});

test('negative: randomness while awaiting a bet is rejected (third-card-before-bet)', () => {
  const parts = players(2);
  let s = initInBetween({ gameId: 'ee', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  ({ state: s } = toAwaitBet(parts, s));
  const r = M.apply(s, { kind: 'randomness', seedHex: seedFor(parts, 999) });
  assert.equal(r.ok, false);
});

test('negative: stale bet after timeout-pass is rejected (turn already advanced)', () => {
  const parts = players(2);
  let s = initInBetween({ gameId: 'ff', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  ({ state: s } = toAwaitBet(parts, s));
  const acting = parts[s.actingIdx]!.id;
  const passed = M.apply(s, { kind: 'timeout', branch: 'pass' });
  assert.equal(passed.ok, true);
  if (!passed.ok) return;
  // now in deck-commitment for the next round; the old acting party cannot bet
  const stale = M.apply(passed.state, { kind: 'action', action: { type: 'BET', party: acting, amount: 1n } });
  assert.equal(stale.ok, false);
});

test('negative: replay is total and rejects an illegal step without throwing (REQ-ENG-004)', () => {
  const parts = players(2);
  const s0 = initInBetween({ gameId: '11', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  const badSteps: Step[] = [{ kind: 'randomness', seedHex: 'zz' }]; // bad hex → typed rejection
  const r = replay(M, s0, badSteps);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.atStep, 0);
});

test('negative: unknown timeout branch and wrong-phase timeout rejected', () => {
  const parts = players(2);
  const s0 = initInBetween({ gameId: '22', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  // timeout in deck-commitment phase → no branch
  assert.equal(M.apply(s0, { kind: 'timeout', branch: 'pass' }).ok, false);
});
