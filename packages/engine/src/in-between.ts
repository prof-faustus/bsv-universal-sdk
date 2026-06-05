// @bsv-universal/engine — the `in-between` module (REQ-MOD-IB-001..009).
//
// Open-information reference game and engine regression anchor. Pure, deterministic, total.
// Randomness (the three card ranks) enters ONLY as a verified beacon seed (REQ-SEC-002); there is
// no action carrying a raw card. The decision-timeout default is "pass / no bet", encoded as an
// explicit branch (REQ-MOD-IB-006). Settlement conserves value against the locked pot
// (REQ-MOD-IB-007).

import {
  taggedHash,
  HASH_TAGS,
  canonicalStringify,
  utf8,
  fromHex,
  expectInt,
  type Canonical,
} from '@bsv-universal/protocol-types';
import { drawValue } from '@bsv-universal/crypto';
import type { ContractModule, LegalAction, Step, Applied } from './module.ts';

export interface Ruleset {
  readonly minBet: bigint;
  readonly maxBet: bigint;
  readonly ante: bigint;
  readonly equalVisiblePenalty: bigint;
  readonly postPenaltyMultiplier: number; // third == a visible card ("hits the post")
  readonly decisionTimeout: number;
  readonly recoveryTimeout: number;
  readonly minPlayers: number;
  readonly maxPlayers: number;
}

export type Phase = 'deck-commitment' | 'await-bet' | 'complete';

export interface InBetweenState {
  readonly module: 'in-between';
  readonly gameId: string;
  readonly rulesetHash: string;
  readonly ruleset: Ruleset;
  readonly parties: readonly string[]; // partyId hex, seat order
  readonly balances: readonly (readonly [string, bigint])[]; // sorted by party hex
  readonly pot: bigint;
  readonly total: bigint; // invariant: Σ balances + pot
  readonly roundNo: number;
  readonly actingIdx: number;
  readonly phase: Phase;
  readonly visible: readonly [number, number] | null;
  readonly third: number | null;
  readonly lastOutcome: string | null;
  readonly roundsRemaining: number;
}

function rulesetHash(r: Ruleset): string {
  const h = taggedHash(HASH_TAGS.ruleset, utf8(canonicalStringify(r as unknown as Canonical)));
  let s = '';
  for (const b of h) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Locale-INDEPENDENT codepoint comparison (REQ-DET-003: ordering must be deterministic everywhere). */
function cmpCodepoint(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
function sortedBalances(entries: (readonly [string, bigint])[]): (readonly [string, bigint])[] {
  return [...entries].sort((a, b) => cmpCodepoint(a[0], b[0]));
}
function bal(state: InBetweenState, party: string): bigint {
  for (const [p, v] of state.balances) if (p === party) return v;
  return 0n;
}
function withBalance(state: InBetweenState, party: string, next: bigint): (readonly [string, bigint])[] {
  return sortedBalances(state.balances.map(([p, v]) => (p === party ? ([p, next] as const) : ([p, v] as const))));
}
function sumBalances(state: InBetweenState): bigint {
  let s = 0n;
  for (const [, v] of state.balances) s += v;
  return s;
}

export interface InitParams {
  readonly gameId: string; // hex
  readonly parties: readonly string[]; // partyId hex
  readonly startingStack: bigint;
  readonly roundsTotal: number;
  readonly ruleset: Ruleset;
}

/** REQ-MOD-IB-001: init fixes & hashes the ruleset; forms the pot from antes. */
export function initInBetween(p: InitParams): InBetweenState {
  if (p.parties.length < p.ruleset.minPlayers || p.parties.length > p.ruleset.maxPlayers) {
    throw new Error(`player count ${p.parties.length} outside ${p.ruleset.minPlayers}..${p.ruleset.maxPlayers}`);
  }
  if (new Set(p.parties).size !== p.parties.length) throw new Error('duplicate party');
  const ante = p.ruleset.ante;
  const balances = sortedBalances(p.parties.map((q) => [q, p.startingStack - ante] as const));
  const pot = ante * BigInt(p.parties.length);
  const total = p.startingStack * BigInt(p.parties.length);
  return {
    module: 'in-between',
    gameId: p.gameId,
    rulesetHash: rulesetHash(p.ruleset),
    ruleset: p.ruleset,
    parties: [...p.parties],
    balances,
    pot,
    total,
    roundNo: 1,
    actingIdx: 0,
    phase: 'deck-commitment',
    visible: null,
    third: null,
    lastOutcome: null,
    roundsRemaining: p.roundsTotal,
  };
}

function legalMax(state: InBetweenState): bigint {
  const acting = state.parties[state.actingIdx]!;
  const balance = bal(state, acting);
  const byBalance = balance / BigInt(Math.max(1, state.ruleset.postPenaltyMultiplier)); // keep balances ≥ 0
  let m = state.ruleset.maxBet;
  if (state.pot < m) m = state.pot;
  if (byBalance < m) m = byBalance;
  return m;
}

function advance(state: InBetweenState, outcome: string, balances: (readonly [string, bigint])[], pot: bigint): InBetweenState {
  const roundsRemaining = state.roundsRemaining - 1;
  const done = roundsRemaining <= 0 || pot <= 0n;
  return {
    ...state,
    balances: sortedBalances(balances),
    pot,
    roundNo: state.roundNo + 1,
    actingIdx: (state.actingIdx + 1) % state.parties.length,
    phase: done ? 'complete' : 'deck-commitment',
    visible: null,
    third: null,
    lastOutcome: outcome,
    roundsRemaining,
  };
}

function resolveBet(state: InBetweenState, amount: bigint): InBetweenState {
  const acting = state.parties[state.actingIdx]!;
  const [lo, hi] = state.visible!;
  const third = state.third!;
  let balances: (readonly [string, bigint])[];
  let pot: bigint;
  let outcome: string;
  if (third > lo && third < hi) {
    // win: take `amount` from the pot
    balances = withBalance(state, acting, bal(state, acting) + amount);
    pot = state.pot - amount;
    outcome = 'win';
  } else if (third === lo || third === hi) {
    // hits the post: pay multiplier × amount into the pot
    const pay = amount * BigInt(state.ruleset.postPenaltyMultiplier);
    balances = withBalance(state, acting, bal(state, acting) - pay);
    pot = state.pot + pay;
    outcome = 'loss-post';
  } else {
    // outside: pay `amount` into the pot
    balances = withBalance(state, acting, bal(state, acting) - amount);
    pot = state.pot + amount;
    outcome = 'loss';
  }
  return advance(state, outcome, balances, pot);
}

export const inBetweenModule: ContractModule<InBetweenState> = {
  id: 'in-between',

  apply(state, step): Applied<InBetweenState> {
    if (state.phase === 'complete') return { ok: false, reason: 'game complete' };

    if (step.kind === 'randomness') {
      if (state.phase !== 'deck-commitment') return { ok: false, reason: `randomness not expected in phase ${state.phase}` };
      let seed: Uint8Array;
      try {
        seed = fromHex(step.seedHex);
      } catch (e) {
        return { ok: false, reason: `bad seed hex: ${(e as Error).message}` };
      }
      if (seed.length !== 32) return { ok: false, reason: 'seed must be 32 bytes' };
      const a = drawValue(seed, 1, 13) + 1;
      const b = drawValue(seed, 2, 13) + 1;
      const third = drawValue(seed, 3, 13) + 1;
      const lo = Math.min(a, b);
      const hi = Math.max(a, b);
      if (lo === hi) {
        // REQ-MOD-IB-007: equal visible → fixed penalty from the acting party, no bet this round.
        const acting = state.parties[state.actingIdx]!;
        const pen = state.ruleset.equalVisiblePenalty;
        return {
          ok: true,
          state: advance(state, 'equal-visible-penalty', withBalance(state, acting, bal(state, acting) - pen), state.pot + pen),
        };
      }
      if (hi - lo === 1) {
        // consecutive visible → no room; auto-pass (REQ-MOD-IB-006 spirit), no value change.
        return { ok: true, state: advance(state, 'consecutive-auto-pass', [...state.balances], state.pot) };
      }
      return { ok: true, state: { ...state, visible: [lo, hi], third, phase: 'await-bet' } };
    }

    if (step.kind === 'timeout') {
      if (state.phase !== 'await-bet') return { ok: false, reason: 'no timeout branch in this phase' };
      if (step.branch !== 'pass') return { ok: false, reason: `unknown timeout branch ${step.branch}` };
      // REQ-MOD-IB-006: decision-timeout default is no bet / pass.
      return { ok: true, state: advance(state, 'timeout-pass', [...state.balances], state.pot) };
    }

    // action
    const act = step.action;
    if (state.phase !== 'await-bet') return { ok: false, reason: `no action expected in phase ${state.phase}` };
    const acting = state.parties[state.actingIdx]!;
    // REQ-SEC-001 (engine half): only the to-move party may act.
    if (act.party !== acting) return { ok: false, reason: 'action by a non-acting party' };
    if (act.type === 'PASS') return { ok: true, state: advance(state, 'pass', [...state.balances], state.pot) };
    if (act.type === 'BET') {
      if (typeof act.amount !== 'bigint') return { ok: false, reason: 'BET requires an amount' };
      const max = legalMax(state);
      if (act.amount < state.ruleset.minBet || act.amount > max) {
        return { ok: false, reason: `bet ${act.amount} outside [${state.ruleset.minBet}, ${max}]` };
      }
      return { ok: true, state: resolveBet(state, act.amount) };
    }
    return { ok: false, reason: `unknown action type ${act.type}` };
  },

  getLegalActions(state): readonly LegalAction[] {
    if (state.phase !== 'await-bet') return [];
    const acting = state.parties[state.actingIdx]!;
    const max = legalMax(state);
    // Enumerated menu only — the engine never picks one (REQ-BAN-009 / REQ-ENG-001).
    return [
      { type: 'BET', party: acting, min: state.ruleset.minBet, max },
      { type: 'PASS', party: acting },
    ];
  },

  expectsRandomness(state) {
    return state.phase === 'deck-commitment';
  },

  timeoutBranch(state) {
    return state.phase === 'await-bet' ? 'pass' : null;
  },

  isComplete(state) {
    return state.phase === 'complete';
  },

  settle(state) {
    const out: Record<string, string> = {};
    for (const [p, v] of state.balances) out[p] = v.toString();
    const conserved = sumBalances(state) + state.pot === state.total;
    return { balances: out, conserved };
  },
};

// Re-export validation helper for negative tests / decoders (REQ-SEC-006).
export function validateRuleset(r: Ruleset): void {
  expectInt(r.postPenaltyMultiplier, 1, 16, 'postPenaltyMultiplier');
  expectInt(r.minPlayers, 2, 6, 'minPlayers');
  expectInt(r.maxPlayers, r.minPlayers, 6, 'maxPlayers');
  if (r.minBet < 0n || r.maxBet < r.minBet) throw new Error('bet bounds invalid');
  if (r.ante < 0n || r.equalVisiblePenalty < 0n) throw new Error('penalty/ante must be ≥ 0');
}
