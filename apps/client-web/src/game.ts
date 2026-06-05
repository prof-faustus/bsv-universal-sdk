// Local-practice in-between game (offline, single device). Runs the real engine + crypto in the
// browser. The HUMAN chooses every action (REQ-BAN-009 / REQ-CLIENT-001): nothing auto-advances —
// even dealing is a button. Randomness is a genuine commit→reveal beacon round built from local
// CSPRNG entropy and verified before use (REQ-SEC-002/003).

import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset, type Step } from '@bsv-universal/engine';
import { keyPairFromPriv, partyId, commit, verifyBeaconRound, randomBytes, ZERO_BEACON, type BeaconRound } from '@bsv-universal/crypto';
import { toHex } from '@bsv-universal/protocol-types';

export const PRACTICE_RULESET: Ruleset = {
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

export interface GameSetup {
  readonly state: InBetweenState;
  readonly partyIds: readonly string[];
}

/** Start a fresh local practice game with `n` seats (each a distinct local key). */
export function newGame(n: number, gameId: string = toHex(randomBytes(4))): GameSetup {
  const parties: string[] = [];
  for (let i = 0; i < n; i++) {
    // distinct deterministic-but-unique local keys for practice seats
    const seed = randomBytes(32);
    parties.push(toHex(partyId(keyPairFromPriv(seed).pub)));
  }
  const state = initInBetween({ gameId, parties, startingStack: 100n, roundsTotal: 8, ruleset: PRACTICE_RULESET });
  return { state, partyIds: parties };
}

export type ApplyOutcome = { ok: true; state: InBetweenState } | { ok: false; reason: string };

/** Deal: build + verify a beacon round from local entropy, then apply (human-initiated). */
export function deal(state: InBetweenState): ApplyOutcome {
  const eligible = state.parties.map((p) => Uint8Array.from(hexToBytes(p)));
  const secrets = eligible.map(() => randomBytes(32));
  const round: BeaconRound = {
    roundNo: state.roundNo,
    commits: eligible.map((party, i) => ({ party, commitment: commit(secrets[i]!) })),
    reveals: eligible.map((party, i) => ({ party, secret: secrets[i]! })),
    prevBeacon: ZERO_BEACON,
  };
  const r = verifyBeaconRound(round, eligible);
  if (!r.ok) return { ok: false, reason: r.reason };
  return apply(state, { kind: 'randomness', seedHex: toHex(r.seed) });
}

/** The acting seat bets a chosen amount (human input). */
export function bet(state: InBetweenState, amount: bigint): ApplyOutcome {
  const acting = state.parties[state.actingIdx]!;
  return apply(state, { kind: 'action', action: { type: 'BET', party: acting, amount } });
}

/** The acting seat passes (human choice; same outcome as the decision-timeout default). */
export function pass(state: InBetweenState): ApplyOutcome {
  const acting = state.parties[state.actingIdx]!;
  return apply(state, { kind: 'action', action: { type: 'PASS', party: acting } });
}

function apply(state: InBetweenState, step: Step): ApplyOutcome {
  const r = M.apply(state, step);
  return r.ok ? { ok: true, state: r.state } : { ok: false, reason: r.reason };
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
