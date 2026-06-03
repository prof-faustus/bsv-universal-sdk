import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Session,
  signEnvelope,
  encodeActionBody,
  encodeBeaconBody,
  type Envelope,
  type EnvelopeFields,
} from '../src/index.ts';
import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset } from '@bsv-universal/engine';
import { keyPairFromPriv, partyId, commit, verifyBeaconRound, signData, ZERO_BEACON, type BeaconRound, type KeyPair } from '@bsv-universal/crypto';
import { toHex, utf8, taggedHash, HASH_TAGS, canonicalStringify } from '@bsv-universal/protocol-types';

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

function beaconRound(parts: { kp: KeyPair; id: string }[], nonce: number, prev = ZERO_BEACON): BeaconRound {
  const ids = parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex')));
  const secrets = parts.map((p, i) => utf8(`${p.id}:${nonce}:${i}`));
  return {
    roundNo: 1,
    commits: ids.map((id, i) => ({ party: id, commitment: commit(secrets[i]!) })),
    reveals: ids.map((id, i) => ({ party: id, secret: secrets[i]! })),
    prevBeacon: prev,
  };
}

function newSession(parts: ReturnType<typeof players>) {
  const initial = initInBetween({ gameId: 'ab', parties: parts.map((p) => p.id), startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  return new Session<InBetweenState>({
    module: M,
    initial,
    networkId: 'regtest',
    contractId: 'ab',
    protocolVersion: 1,
    eligible: parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex'))),
  });
}

function fields(s: Session<InBetweenState>, kp: KeyPair, kind: EnvelopeFields['messageKind'], bodyHex: string): EnvelopeFields {
  return {
    networkId: 'regtest',
    moduleId: 'in-between',
    contractId: 'ab',
    protocolVersion: 1,
    messageKind: kind,
    seatId: toHex(partyId(kp.pub)),
    actorPubKeyHex: toHex(kp.pub),
    priorTranscriptHash: s.head,
    sequenceNo: s.seq,
    bodyHex,
  };
}

// Find a beacon nonce that drives the FIRST randomness step into await-bet.
function awaitBetNonce(parts: ReturnType<typeof players>, initial: InBetweenState): number {
  for (let n = 0; n < 200; n++) {
    const round = beaconRound(parts, n);
    const vr = verifyBeaconRound(round, parts.map((p) => Uint8Array.from(Buffer.from(p.id, 'hex'))));
    if (!vr.ok) continue;
    const r = M.apply(initial, { kind: 'randomness', seedHex: toHex(vr.seed) });
    if (r.ok && r.state.phase === 'await-bet') return n;
  }
  throw new Error('no await-bet nonce');
}

test('valid randomness + bet are accepted and state re-derives (REQ-SEC-001/002/004)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const n = awaitBetNonce(parts, s.state);
  const randEnv = signEnvelope(fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), acting.kp);
  let r = s.accept(randEnv);
  assert.equal(r.ok, true, r.ok ? '' : r.reason);
  assert.equal(s.state.phase, 'await-bet');
  assert.equal(s.seq, 1);

  const legal = M.getLegalActions(s.state);
  const bet = legal.find((a) => a.type === 'BET') as { party: string; max: bigint };
  const betEnv = signEnvelope(fields(s, acting.kp, 'action', encodeActionBody({ type: 'BET', amount: bet.max })), acting.kp);
  r = s.accept(betEnv);
  assert.equal(r.ok, true, r.ok ? '' : r.reason);
  assert.equal(s.seq, 2);
  // independent re-derivation from the recorded steps equals the live state
  assert.deepEqual(s.rederive(), s.state);
});

test('forged signature is DROPPED (REQ-SEC-001)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const n = awaitBetNonce(parts, s.state);
  const env = signEnvelope(fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), acting.kp);
  const forged: Envelope = { ...env, sigHex: '00'.repeat(70) };
  const r = s.accept(forged);
  assert.equal(r.ok, false);
  assert.equal(s.seq, 0); // state did not move
});

test('action by a non-acting seat is DROPPED (REQ-SEC-001 actor binding)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const other = parts[(s.state.actingIdx + 1) % parts.length]!;
  const n = awaitBetNonce(parts, s.state);
  s.accept(signEnvelope(fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), acting.kp));
  assert.equal(s.state.phase, 'await-bet');
  // the OTHER player signs a perfectly valid envelope for THEIR seat, but it isn't their turn
  const env = signEnvelope(fields(s, other.kp, 'action', encodeActionBody({ type: 'BET', amount: 1n })), other.kp);
  const r = s.accept(env);
  assert.equal(r.ok, false);
  assert.match(r.ok ? '' : r.reason, /non-acting|engine rejected/);
  assert.equal(s.seq, 1); // unchanged by the dropped move
});

test('impersonation (sign for a seat you do not own) is DROPPED', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const attacker = parts[(s.state.actingIdx + 1) % parts.length]!;
  const n = awaitBetNonce(parts, s.state);
  s.accept(signEnvelope(fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), acting.kp));
  // attacker tries to forge an envelope CLAIMING the acting seat but signs with its own key
  const claim = { ...fields(s, acting.kp, 'action', encodeActionBody({ type: 'BET', amount: 1n })) };
  // sign with attacker key but leave seatId/actorPubKey as the victim's → signEnvelope refuses; do it by hand
  const payload = taggedHash(HASH_TAGS.envelope, utf8(canonicalStringify(claim)));
  const env: Envelope = { ...claim, sigHex: toHex(signData(payload, attacker.kp)) };
  const r = s.accept(env);
  assert.equal(r.ok, false); // signature won't verify under the claimed victim pubkey
});

test('bad sequence number is DROPPED (REQ-SEC-004)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const n = awaitBetNonce(parts, s.state);
  const f = { ...fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), sequenceNo: 5 };
  const env = signEnvelope(f, acting.kp);
  const r = s.accept(env);
  assert.equal(r.ok, false);
  assert.match(r.ok ? '' : r.reason, /sequence/);
});

test('bad prior-transcript-hash is DROPPED (REQ-SEC-001 chaining)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  const n = awaitBetNonce(parts, s.state);
  const f = { ...fields(s, acting.kp, 'randomness', encodeBeaconBody(beaconRound(parts, n))), priorTranscriptHash: 'ab'.repeat(32) };
  const env = signEnvelope(f, acting.kp);
  const r = s.accept(env);
  assert.equal(r.ok, false);
  assert.match(r.ok ? '' : r.reason, /prior-transcript-hash/);
});

test('non-beacon / forged randomness is DROPPED (REQ-SEC-002/003 live path)', () => {
  const parts = players(2);
  const s = newSession(parts);
  const acting = parts[s.state.actingIdx]!;
  // a beacon round with a fake reveal from a non-seat — exactly the audit #3 exploit
  const base = beaconRound(parts, 0);
  const fake = keyPairFromPriv(new Uint8Array(32).fill(99));
  const tampered: BeaconRound = {
    ...base,
    reveals: [...base.reveals, { party: partyId(fake.pub), secret: utf8('chosen') }],
  };
  const env = signEnvelope(fields(s, acting.kp, 'randomness', encodeBeaconBody(tampered)), acting.kp);
  const r = s.accept(env);
  assert.equal(r.ok, false);
  assert.match(r.ok ? '' : r.reason, /beacon round invalid/);
  assert.equal(s.seq, 0);
});
