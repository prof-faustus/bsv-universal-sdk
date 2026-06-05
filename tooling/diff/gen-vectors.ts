// Generates the differential vector corpus (REQ-TEST-003): drives the TS in-between engine through
// many varied branches and records, for each step, the canonical state hash. The Go implementation
// must reproduce every hash byte-for-byte. Randomness is supplied as explicit seeds in each step, so
// both implementations are fully deterministic from the corpus (no RNG divergence).

import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset, type Step } from '@bsv-universal/engine';
import { canonicalHash, toHex } from '@bsv-universal/protocol-types';

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};

interface Init {
  gameId: string;
  parties: string[];
  startingStack: string; // bigint as decimal string
  roundsTotal: number;
  ruleset: Record<string, string | number>;
}
interface Vector {
  init: Init;
  steps: Step[];
  hashes: string[]; // canonical state hash after each step (hex)
  initHash: string; // canonical state hash of the initial state
  settle: { balances: Record<string, string>; conserved: boolean };
}

function rulesetJson(r: Ruleset): Record<string, string | number> {
  return {
    minBet: r.minBet.toString(), maxBet: r.maxBet.toString(), ante: r.ante.toString(),
    equalVisiblePenalty: r.equalVisiblePenalty.toString(), postPenaltyMultiplier: r.postPenaltyMultiplier,
    decisionTimeout: r.decisionTimeout, recoveryTimeout: r.recoveryTimeout, minPlayers: r.minPlayers, maxPlayers: r.maxPlayers,
  };
}

function fakeParty(i: number): string {
  // a deterministic-looking 33-byte compressed pubkey hex (02/03 prefix); content is opaque to the engine
  const b = randomBytes(33);
  b[0] = 0x02 + (i & 1);
  return toHex(b);
}

function serializeStep(step: Step): Step {
  if (step.kind === 'action' && step.action.amount !== undefined) {
    // amount is bigint → emit as decimal string in the corpus; the in-memory Step keeps bigint
    return { kind: 'action', action: { type: step.action.type, party: step.action.party, amount: step.action.amount } };
  }
  return step;
}

function genScenario(n: number, scenarioIdx: number): Vector {
  const parties = Array.from({ length: n }, (_, i) => fakeParty(i + scenarioIdx * 7));
  const startingStack = 100n;
  const roundsTotal = 6;
  let state: InBetweenState = initInBetween({ gameId: toHex(randomBytes(4)), parties, startingStack, roundsTotal, ruleset: RULESET });
  const initHash = toHex(canonicalHash(state as never));
  const steps: Step[] = [];
  const hashes: string[] = [];

  let guard = 0;
  while (!M.isComplete(state) && guard++ < 60) {
    let step: Step;
    if (M.expectsRandomness(state)) {
      step = { kind: 'randomness', seedHex: toHex(randomBytes(32)) };
    } else {
      // await-bet: choose bet (varied legal amount) or pass, deterministically by a coin
      const legal = M.getLegalActions(state);
      const betvm = legal.find((a) => a.type === 'BET') as { party: string; min: bigint; max: bigint } | undefined;
      const coin = randomBytes(1)[0]! % 3;
      if (betvm && coin !== 0) {
        const span = betvm.max - betvm.min;
        const amount = span > 0n ? betvm.min + (BigInt(randomBytes(1)[0]!) % (span + 1n)) : betvm.min;
        step = { kind: 'action', action: { type: 'BET', party: betvm.party, amount } };
      } else if (coin === 2) {
        step = { kind: 'timeout', branch: 'pass' };
      } else {
        const acting = state.parties[state.actingIdx]!;
        step = { kind: 'action', action: { type: 'PASS', party: acting } };
      }
    }
    const r = M.apply(state, step);
    if (!r.ok) continue; // skip an illegal coin (rare); try again
    state = r.state;
    steps.push(serializeStep(step));
    hashes.push(toHex(canonicalHash(state as never)));
  }

  return {
    init: { gameId: state.gameId, parties, startingStack: startingStack.toString(), roundsTotal, ruleset: rulesetJson(RULESET) },
    steps,
    hashes,
    initHash,
    settle: M.settle(state),
  };
}

// build a corpus across player counts and many scenarios → covers win/loss/loss-post/equal/consecutive/pass/timeout
const vectors: Vector[] = [];
for (let s = 0; s < 60; s++) {
  const n = 2 + (s % 5); // 2..6 players
  vectors.push(genScenario(n, s));
}

const outDir = fileURLToPath(new URL('../../go/', import.meta.url));
mkdirSync(outDir, { recursive: true });
// amounts are bigint in Step; JSON.stringify can't serialize bigint → replacer to decimal string
const json = JSON.stringify(
  { version: 1, vectors },
  (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
  0,
);
writeFileSync(outDir + 'vectors.json', json);
console.log(`wrote ${vectors.length} differential vectors (${vectors.reduce((a, v) => a + v.steps.length, 0)} steps) to go/vectors.json`);
