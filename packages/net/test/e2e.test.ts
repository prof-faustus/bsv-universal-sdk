// Two-peer end-to-end: signed envelopes over a bounded relay, ordered delivery, engine convergence.
// Exercises REQ-SEC-001/002/003/004/005 + REQ-MOD-IB-011 (multi-party round) as one stack.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RelayCore } from '@bsv-universal/relay';
import { OrderedSubscriber, channelSource } from '../src/index.ts';
import {
  Session,
  signEnvelope,
  encodeActionBody,
  encodeBeaconBody,
  envelopeToHex,
  envelopeFromHex,
  type EnvelopeFields,
} from '@bsv-universal/sdk';
import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset } from '@bsv-universal/engine';
import { keyPairFromPriv, partyId, commit, verifyBeaconRound, ZERO_BEACON, type BeaconRound, type KeyPair } from '@bsv-universal/crypto';
import { toHex, utf8 } from '@bsv-universal/protocol-types';

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};

function players(n: number) {
  return Array.from({ length: n }, (_, i) => {
    const kp = keyPairFromPriv(new Uint8Array(32).fill(i + 1));
    return { kp, id: toHex(partyId(kp.pub)) };
  });
}

function beaconRound(parts: { kp: KeyPair; id: string }[], nonce: number): BeaconRound {
  const ids = parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex')));
  const secrets = parts.map((p, i) => utf8(`${p.id}:${nonce}:${i}`));
  return {
    roundNo: 1,
    commits: ids.map((id, i) => ({ party: id, commitment: commit(secrets[i]!) })),
    reveals: ids.map((id, i) => ({ party: id, secret: secrets[i]! })),
    prevBeacon: ZERO_BEACON,
  };
}

test('two peers converge to identical state over the relay (full stack)', async () => {
  const parts = players(2);
  const eligible = parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex')));
  const initial = initInBetween({ gameId: 'ab', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 4, ruleset: RULESET });

  const core = new RelayCore();
  core.open('ab', 'cap');

  function mkSession() {
    return new Session<InBetweenState>({ module: M, initial, networkId: 'regtest', contractId: 'ab', protocolVersion: 1, eligible });
  }
  const sessions = [mkSession(), mkSession()];

  // each peer subscribes; on delivery it feeds the envelope to its own Session
  const subs = sessions.map(
    (s) =>
      new OrderedSubscriber(channelSource(core, 'ab', 'cap'), (hex) => {
        s.accept(envelopeFromHex(hex));
      }),
  );
  async function pumpAll() {
    for (const sub of subs) await sub.pump();
  }

  function fields(s: Session<InBetweenState>, kp: KeyPair, kind: EnvelopeFields['messageKind'], bodyHex: string): EnvelopeFields {
    return {
      networkId: 'regtest', moduleId: 'in-between', contractId: 'ab', protocolVersion: 1,
      messageKind: kind, seatId: toHex(partyId(kp.pub)), actorPubKeyHex: toHex(kp.pub),
      priorTranscriptHash: s.head, sequenceNo: s.seq, bodyHex,
    };
  }

  // Driver: the acting peer (per its OWN session view) publishes the next signed step.
  let guard = 0;
  while (!M.isComplete(sessions[0]!.state) && guard++ < 100) {
    const driver = sessions[0]!; // both views are identical; use peer 0 to decide what to publish
    const st = driver.state;
    const acting = parts[st.actingIdx]!;
    if (M.expectsRandomness(st)) {
      // find a beacon nonce that lands await-bet from the acting peer's current state
      let nonce = -1;
      for (let n = 0; n < 200; n++) {
        const vr = verifyBeaconRound(beaconRound(parts, n), eligible);
        if (!vr.ok) continue;
        const r = M.apply(st, { kind: 'randomness', seedHex: toHex(vr.seed) });
        if (r.ok && r.state.phase === 'await-bet') { nonce = n; break; }
      }
      assert.notEqual(nonce, -1);
      const env = signEnvelope(fields(driver, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, nonce))), acting.kp);
      const pub = core.publish('ab', 'cap', envelopeToHex(env));
      assert.equal(pub.ok, true);
    } else if (st.phase === 'await-bet') {
      const legal = M.getLegalActions(st);
      const bet = legal.find((a) => a.type === 'BET') as { party: string; max: bigint };
      const amount = bet.max >= RULESET.minBet ? bet.max : RULESET.minBet;
      const env = signEnvelope(fields(driver, acting.kp, 'action', encodeActionBody({ type: 'BET', amount })), acting.kp);
      const pub = core.publish('ab', 'cap', envelopeToHex(env));
      assert.equal(pub.ok, true);
    }
    await pumpAll();
    // both peers stay in lockstep after every delivery (REQ-SEC-004 → identical total order)
    assert.deepEqual(sessions[0]!.state, sessions[1]!.state);
    assert.equal(sessions[0]!.head, sessions[1]!.head);
  }

  assert.equal(M.isComplete(sessions[0]!.state), true);
  assert.deepEqual(sessions[0]!.state, sessions[1]!.state);
  // independent re-derivation matches the live state for both peers (REQ-ARCH-001)
  assert.deepEqual(sessions[0]!.rederive(), sessions[0]!.state);
  assert.deepEqual(sessions[1]!.rederive(), sessions[1]!.state);
  // value conserved end to end
  assert.equal(M.settle(sessions[0]!.state).conserved, true);
});
