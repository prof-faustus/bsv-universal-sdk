// Deterministic reference ("golden") vector generator (REQ-TEST-006). Produces a fully reproducible
// set of input→output vectors for the consensus/value/auth primitives. `pnpm reproduce` re-derives
// this from source and asserts it matches the committed vectors/golden.json byte-for-byte — so a
// hand-edited expected value, or any silent change in output, fails the build (anti-tamper provenance).
//
// EVERYTHING here is deterministic: fixed keys + counter-hash byte streams, no RNG.

import { createHash } from 'node:crypto';
import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset, type Step } from '@bsv-universal/engine';
import { canonicalHash, taggedHash, HASH_TAGS, toHex, u32be, utf8, type Canonical } from '@bsv-universal/protocol-types';
import { keyPairFromPriv, partyId, commit, verifyBeaconRound, ZERO_BEACON, signData, verifyData, signBitcoin, verifyBitcoin, drawValue, type BeaconRound } from '@bsv-universal/crypto';
import { evalScript, OP, type SigChecker } from '@bsv-universal/script';
import { serializeTx, txid, sighash, verifyTxValue, p2pkhLockingFromPkh, covenantOutput, verifyCovenantSpend, type Tx } from '@bsv-universal/tx';

// deterministic byte stream from a label (counter-hash); never RNG.
function det(label: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let filled = 0;
  let ctr = 0;
  while (filled < len) {
    const h = new Uint8Array(createHash('sha256').update(u32be(label)).update(u32be(ctr++)).digest());
    const take = Math.min(h.length, len - filled);
    out.set(h.subarray(0, take), filled);
    filled += take;
  }
  return out;
}
// small, always-valid fixed private key for index i (well below the curve order).
function fixedPriv(i: number): Uint8Array {
  const p = new Uint8Array(32);
  p[31] = (i % 250) + 1;
  p[30] = ((i >> 8) % 250) + 1;
  return p;
}
function pid(i: number): string {
  return toHex(partyId(keyPairFromPriv(fixedPriv(i)).pub));
}

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};
const STUB: SigChecker = { check: (s, p) => s.length > 0 && p.length > 0 && s[0] === p[0] };
const push = (d: number[]) => [d.length, ...d];
const B = (...n: number[]) => new Uint8Array(n);

export function buildGolden(): unknown {
  // 1. canonical hashes of fixed objects
  const canonObjs: Canonical[] = [
    { b: 1, a: 2, c: [3, 2, 1] },
    { s: 'hi', big: 2100000000000000n, z: null, ok: true },
    [1, 2, 3, { nested: ['x', false] }],
  ];
  const canon = canonObjs.map((o) => toHex(canonicalHash(o)));

  // 2. tagged hashes
  const tagged = [
    toHex(taggedHash(HASH_TAGS.state, utf8('alpha'))),
    toHex(taggedHash(HASH_TAGS.commit, B(1, 2, 3))),
    toHex(taggedHash(HASH_TAGS.beacon, det(7, 32), u32be(5))),
  ];

  // 3. drawValue
  const draws: number[] = [];
  for (let i = 0; i < 6; i++) draws.push(drawValue(det(100 + i, 32), i, 13));

  // 4. in-between scenarios (deterministic steps) → per-step canonical hashes + settle
  const scenarios: { initHash: string; hashes: string[]; settle: unknown }[] = [];
  for (let sc = 0; sc < 3; sc++) {
    const n = 2 + sc;
    const parties = Array.from({ length: n }, (_, i) => pid(i + sc * 10));
    let s: InBetweenState = initInBetween({ gameId: toHex(det(200 + sc, 4)), parties, startingStack: 100n, roundsTotal: 4, ruleset: RULESET });
    const initHash = toHex(canonicalHash(s as never));
    const hashes: string[] = [];
    let label = 300 + sc * 50;
    let guard = 0;
    while (!M.isComplete(s) && guard++ < 60) {
      let step: Step;
      if (M.expectsRandomness(s)) {
        step = { kind: 'randomness', seedHex: toHex(det(label++, 32)) };
      } else {
        const bet = M.getLegalActions(s).find((a) => a.type === 'BET') as { party: string; min: bigint; max: bigint };
        // deterministic choice: bet on even rounds, pass on odd
        step = s.roundNo % 2 === 0
          ? { kind: 'action', action: { type: 'BET', party: bet.party, amount: bet.max >= bet.min ? bet.max : bet.min } }
          : { kind: 'action', action: { type: 'PASS', party: s.parties[s.actingIdx]! } };
      }
      const r = M.apply(s, step);
      if (!r.ok) continue;
      s = r.state;
      hashes.push(toHex(canonicalHash(s as never)));
    }
    scenarios.push({ initHash, hashes, settle: M.settle(s) });
  }

  // 5. beacon rounds (deterministic) → {ok, seed}
  const beacons: { ok: boolean; seed: string }[] = [];
  for (let bk = 0; bk < 2; bk++) {
    const n = 2 + bk;
    const ids = Array.from({ length: n }, (_, i) => partyId(keyPairFromPriv(fixedPriv(i + bk * 5)).pub));
    const secrets = ids.map((_, i) => det(400 + bk * 10 + i, 32));
    const round: BeaconRound = {
      roundNo: 1 + bk,
      commits: ids.map((id, i) => ({ party: id, commitment: commit(secrets[i]!) })),
      reveals: ids.map((id, i) => ({ party: id, secret: secrets[i]! })),
      prevBeacon: ZERO_BEACON,
    };
    const r = verifyBeaconRound(round, ids);
    beacons.push({ ok: r.ok, seed: r.ok ? toHex(r.seed) : '' });
  }

  // 6. script evaluation (fixed stub)
  const data = [0xde, 0xad, 0xbe, 0xef];
  const scripts = [
    evalScript(B(...push(data)), B(...push(data), OP.OP_EQUAL), STUB).ok,
    evalScript(B(), B(OP.OP_1, OP.OP_1, OP.OP_ADD, OP.OP_1 + 1, OP.OP_EQUAL), STUB).ok,
    evalScript(B(...push([0x07, 0x01]), ...push([0x07, 0x02])), B(OP.OP_CHECKSIG), STUB).ok,
    evalScript(B(...push([0x01])), B(0x6a), STUB).ok, // banned → false
  ];

  // 7. tx: txid / sighash / value / covenant
  const tx: Tx = {
    version: 1,
    inputs: [{ outpoint: { txid: det(500, 32), vout: 0 }, unlockingScript: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ satoshis: 900n, lockingScript: p2pkhLockingFromPkh(det(501, 20)) }],
    lockTime: 0,
  };
  const prevScript = p2pkhLockingFromPkh(det(502, 20));
  const reserve = 1000n;
  const rulesHash = det(503, 32);
  const recipientPkh = det(504, 20);
  const covPrevScript = covenantOutput(reserve, rulesHash).lockingScript;
  const covTx: Tx = {
    version: 1,
    inputs: [{ outpoint: { txid: det(505, 32), vout: 0 }, unlockingScript: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ satoshis: 300n, lockingScript: p2pkhLockingFromPkh(recipientPkh) }, covenantOutput(reserve - 300n, rulesHash)],
    lockTime: 0,
  };
  const txOut = {
    serializeHex: toHex(serializeTx(tx)),
    txid: toHex(txid(tx)),
    sighash: toHex(sighash(tx, 0, prevScript, 1000n)),
    valueOk: verifyTxValue(tx, [1000n], 100n).ok,
    covenantOk: verifyCovenantSpend({ reserve, rulesHash }, { txid: det(505, 32), vout: 0 }, covPrevScript, covTx, recipientPkh, 300n).ok,
  };

  // 8. auth: deterministic (RFC6979) signatures
  const auth: { der: string; data: boolean; bitcoin: boolean }[] = [];
  for (let i = 0; i < 3; i++) {
    const kp = keyPairFromPriv(fixedPriv(900 + i));
    const msg = det(600 + i, 20);
    const der = signData(msg, kp);
    const pre = det(700 + i, 40);
    const bder = signBitcoin(pre, kp);
    auth.push({ der: toHex(der), data: verifyData(msg, der, kp.pub), bitcoin: verifyBitcoin(pre, bder, kp.pub) });
  }

  return { version: 1, canon, tagged, draws, scenarios, beacons, scripts, tx: txOut, auth };
}

export function goldenJson(): string {
  return JSON.stringify(buildGolden(), (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n';
}
