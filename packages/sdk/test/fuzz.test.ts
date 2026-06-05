// Fuzz battery (MS SDL / SANS): the envelope decoder and Session.accept are total on hostile input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Session, tryEnvelopeFromHex, type Envelope } from '../src/index.ts';
import { inBetweenModule as M, initInBetween, type InBetweenState, type Ruleset } from '@bsv-universal/engine';
import { keyPairFromPriv, partyId } from '@bsv-universal/crypto';
import { toHex } from '@bsv-universal/protocol-types';

const ITER = 5000;

const RULESET: Ruleset = {
  minBet: 1n, maxBet: 10n, ante: 5n, equalVisiblePenalty: 2n, postPenaltyMultiplier: 2,
  decisionTimeout: 30, recoveryTimeout: 300, minPlayers: 2, maxPlayers: 6,
};

function session() {
  const parts = [1, 2].map((i) => toHex(partyId(keyPairFromPriv(new Uint8Array(32).fill(i)).pub)));
  const initial = initInBetween({ gameId: 'ab', parties: parts, startingStack: 100n, roundsTotal: 3, ruleset: RULESET });
  return new Session<InBetweenState>({
    module: M, initial, networkId: 'regtest', contractId: 'ab', protocolVersion: 1,
    eligible: parts.map((p) => Uint8Array.from(Buffer.from(p, 'hex'))),
  });
}

test('tryEnvelopeFromHex is total over 5000 random hex blobs', () => {
  for (let i = 0; i < ITER; i++) {
    const hex = randomBytes(randomBytes(1)[0]! % 200).toString('hex');
    const r = tryEnvelopeFromHex(hex); // never throws
    assert.equal(typeof r.ok, 'boolean');
  }
  // also random NON-hex strings
  for (let i = 0; i < 1000; i++) {
    const s = randomBytes(20).toString('utf8');
    assert.doesNotThrow(() => tryEnvelopeFromHex(s));
  }
});

test('tryEnvelopeFromHex is total over structurally-random envelope JSON', () => {
  for (let i = 0; i < ITER; i++) {
    const obj: Record<string, unknown> = {
      networkId: ['main', 'test', 'regtest', 'evil', 42][randomBytes(1)[0]! % 5],
      moduleId: randomBytes(randomBytes(1)[0]! % 8).toString('hex'),
      contractId: randomBytes(randomBytes(1)[0]! % 8).toString('hex'),
      protocolVersion: randomBytes(4).readUInt32BE(0),
      messageKind: ['action', 'randomness', 'nope', 7][randomBytes(1)[0]! % 4],
      seatId: randomBytes(randomBytes(1)[0]! % 40).toString('hex'),
      actorPubKeyHex: randomBytes(randomBytes(1)[0]! % 70).toString('hex'),
      priorTranscriptHash: randomBytes(randomBytes(1)[0]! % 40).toString('hex'),
      sequenceNo: randomBytes(1)[0]! % 2 ? randomBytes(4).readUInt32BE(0) : -1,
      bodyHex: randomBytes(randomBytes(1)[0]! % 40).toString('hex'),
      sigHex: randomBytes(randomBytes(1)[0]! % 90).toString('hex'),
    };
    const hex = Buffer.from(JSON.stringify(obj), 'utf8').toString('hex');
    const r = tryEnvelopeFromHex(hex);
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('Session.accept is total over random well-typed envelopes (never throws, never advances on junk)', () => {
  const s = session();
  for (let i = 0; i < ITER; i++) {
    const env: Envelope = {
      networkId: 'regtest', moduleId: 'in-between', contractId: 'ab', protocolVersion: 1,
      messageKind: ['action', 'randomness'][randomBytes(1)[0]! % 2] as Envelope['messageKind'],
      seatId: randomBytes(33).toString('hex'),
      actorPubKeyHex: '04' + randomBytes(64).toString('hex'),
      priorTranscriptHash: s.head,
      sequenceNo: s.seq,
      bodyHex: randomBytes(randomBytes(1)[0]! % 60).toString('hex'),
      sigHex: randomBytes(70).toString('hex'),
    };
    const r = s.accept(env); // must never throw
    assert.equal(typeof r.ok, 'boolean');
  }
  // junk never advanced the accepted prefix
  assert.equal(s.seq, 0);
});
