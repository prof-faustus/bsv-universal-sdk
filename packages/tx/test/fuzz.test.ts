// Fuzz battery (MS SDL / SANS): tx verifiers are total on hostile input.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { verifyTxValue, verifyCovenantSpend, sighashChecker, covenantOutput, type Tx, type Covenant } from '../src/index.ts';
import { taggedHash, HASH_TAGS, utf8 } from '@bsv-universal/protocol-types';

const ITER = 4000;
const rbig = () => BigInt(randomBytes(4).readUInt32BE(0));
const txid32 = (n: number) => new Uint8Array(32).fill(n);

function randomTx(): Tx {
  const nIn = randomBytes(1)[0]! % 4;
  const nOut = randomBytes(1)[0]! % 4;
  return {
    version: randomBytes(4).readUInt32BE(0),
    inputs: Array.from({ length: nIn }, () => ({ outpoint: { txid: txid32(randomBytes(1)[0]!), vout: randomBytes(4).readUInt32BE(0) }, unlockingScript: new Uint8Array(randomBytes(randomBytes(1)[0]! % 30)), sequence: randomBytes(4).readUInt32BE(0) })),
    outputs: Array.from({ length: nOut }, () => ({ satoshis: rbig(), lockingScript: new Uint8Array(randomBytes(randomBytes(1)[0]! % 30)) })),
    lockTime: randomBytes(4).readUInt32BE(0),
  };
}

test('verifyTxValue is total over random txs/amounts/fees (never throws)', () => {
  for (let i = 0; i < ITER; i++) {
    const tx = randomTx();
    const prev = Array.from({ length: tx.inputs.length }, () => rbig());
    const r = verifyTxValue(tx, prev, rbig());
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('verifyCovenantSpend is total over random input (never throws)', () => {
  const prev: Covenant = { reserve: 1000n, rulesHash: taggedHash(HASH_TAGS.ruleset, utf8('r')) };
  const op = { txid: txid32(9), vout: 0 };
  for (let i = 0; i < ITER; i++) {
    const r = verifyCovenantSpend(prev, op, new Uint8Array(randomBytes(randomBytes(1)[0]! % 40)), randomTx(), new Uint8Array(randomBytes(20)), rbig());
    assert.equal(typeof r.ok, 'boolean');
  }
});

test('sighashChecker.check is total over random sig/pubkey (never throws)', () => {
  const prev = covenantOutput(1000n, taggedHash(HASH_TAGS.ruleset, utf8('r'))).lockingScript;
  const tx = randomTx();
  if (tx.inputs.length === 0) return;
  const checker = sighashChecker(tx, 0, prev, 1000n);
  for (let i = 0; i < ITER; i++) {
    const ok = checker.check(new Uint8Array(randomBytes(randomBytes(1)[0]! % 80)), new Uint8Array(randomBytes(randomBytes(1)[0]! % 70)));
    assert.equal(typeof ok, 'boolean');
  }
});
