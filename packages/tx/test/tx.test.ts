import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  serializeTx,
  txid,
  sighashChecker,
  verifyTxValue,
  p2pkhLocking,
  signP2PKH,
  covenantOutput,
  verifyCovenantSpend,
  verifyCovenantPayout,
  p2pkhLockingFromPkh,
  type Tx,
  type Covenant,
} from '../src/index.ts';
import { evalScript } from '@bsv-universal/script';
import { keyPairFromPriv, hash160 } from '@bsv-universal/crypto';
import { taggedHash, HASH_TAGS, utf8 } from '@bsv-universal/protocol-types';

const alice = keyPairFromPriv(new Uint8Array(32).fill(11));
const bob = keyPairFromPriv(new Uint8Array(32).fill(22));
const txid32 = (n: number) => new Uint8Array(32).fill(n);

function spendTx(unlocking: Uint8Array, outSats: bigint, outScript: Uint8Array): Tx {
  return {
    version: 1,
    inputs: [{ outpoint: { txid: txid32(1), vout: 0 }, unlockingScript: unlocking, sequence: 0xffffffff }],
    outputs: [{ satoshis: outSats, lockingScript: outScript }],
    lockTime: 0,
  };
}

test('serializeTx / txid are deterministic', () => {
  const tx = spendTx(new Uint8Array(0), 100n, p2pkhLocking(bob.pub));
  assert.deepEqual([...serializeTx(tx)], [...serializeTx(structuredClone(tx))]);
  assert.equal(txid(tx).length, 32);
});

test('REQ-SEC-007: P2PKH end-to-end — real sign then real script satisfaction', () => {
  const prevScript = p2pkhLocking(alice.pub);
  const prevAmount = 1000n;
  // unsigned tx (empty unlocking) → sign input 0 → attach unlocking
  const unsigned = spendTx(new Uint8Array(0), 1000n, p2pkhLocking(bob.pub));
  const unlocking = signP2PKH(unsigned, 0, prevScript, prevAmount, alice);
  const signed = spendTx(unlocking, 1000n, p2pkhLocking(bob.pub));
  const checker = sighashChecker(signed, 0, prevScript, prevAmount);
  const r = evalScript(unlocking, prevScript, checker);
  assert.equal(r.ok, true, r.ok ? '' : r.reason);
});

test('REQ-SEC-007: wrong key fails; tampering an output invalidates the signature (SIGHASH_ALL)', () => {
  const prevScript = p2pkhLocking(alice.pub);
  const prevAmount = 1000n;
  // signed by BOB but locked to ALICE → must fail
  const unsigned = spendTx(new Uint8Array(0), 1000n, p2pkhLocking(bob.pub));
  const wrong = signP2PKH(unsigned, 0, prevScript, prevAmount, bob);
  const tx1 = spendTx(wrong, 1000n, p2pkhLocking(bob.pub));
  assert.equal(evalScript(wrong, prevScript, sighashChecker(tx1, 0, prevScript, prevAmount)).ok, false);

  // correct signature, but the verifier checks it against a TAMPERED tx (different output amount)
  const good = signP2PKH(unsigned, 0, prevScript, prevAmount, alice);
  const tampered = spendTx(good, 999n /* changed */, p2pkhLocking(bob.pub));
  assert.equal(evalScript(good, prevScript, sighashChecker(tampered, 0, prevScript, prevAmount)).ok, false);
});

test('REQ-SEC-007: verifyTxValue conserves against real prev amounts + fee', () => {
  const tx = spendTx(new Uint8Array(0), 900n, p2pkhLocking(bob.pub));
  assert.equal(verifyTxValue(tx, [1000n], 100n).ok, true);
  assert.equal(verifyTxValue(tx, [1000n], 50n).ok, false); // 1000 != 900 + 50
  assert.equal(verifyTxValue(tx, [1000n, 1n], 100n).ok, false); // prevAmounts count mismatch
  assert.equal(verifyTxValue(tx, [-1n], 0n).ok, false); // negative prev
});

// ---- REQ-SEC-008 covenant binding
const rulesHash = taggedHash(HASH_TAGS.ruleset, utf8('rules-v1'));
const prev: Covenant = { reserve: 1000n, rulesHash };
const prevOutpoint = { txid: txid32(9), vout: 0 };
const prevScript = covenantOutput(prev.reserve, prev.rulesHash).lockingScript;
const recipientPkh = hash160(bob.pub);

function covenantSpend(amount: bigint, opts?: { outpoint?: typeof prevOutpoint }): Tx {
  return {
    version: 1,
    inputs: [{ outpoint: opts?.outpoint ?? prevOutpoint, unlockingScript: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [
      { satoshis: amount, lockingScript: p2pkhLockingFromPkh(recipientPkh) },
      covenantOutput(prev.reserve - amount, prev.rulesHash),
    ],
    lockTime: 0,
  };
}

test('REQ-SEC-008: valid covenant spend binds outpoint + prev script + rules hash + payout', () => {
  const tx = covenantSpend(300n);
  const r = verifyCovenantSpend(prev, prevOutpoint, prevScript, tx, recipientPkh, 300n);
  assert.equal(r.ok, true, r.ok ? '' : r.reason);
});

test('REQ-SEC-008: rejects spend of the WRONG outpoint', () => {
  const tx = covenantSpend(300n, { outpoint: { txid: txid32(8), vout: 0 } });
  const r = verifyCovenantSpend(prev, prevOutpoint, prevScript, tx, recipientPkh, 300n);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.reason, /outpoint/);
});

test('REQ-SEC-008: rejects a prevScript with a different rules hash', () => {
  const otherRules = taggedHash(HASH_TAGS.ruleset, utf8('rules-EVIL'));
  const wrongPrevScript = covenantOutput(prev.reserve, otherRules).lockingScript;
  const tx = covenantSpend(300n);
  const r = verifyCovenantSpend(prev, prevOutpoint, wrongPrevScript, tx, recipientPkh, 300n);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.reason, /covenant/);
});

test('REQ-SEC-008: rejects wrong payout amount / residual not re-locked', () => {
  // out0 pays a different amount than claimed
  const tx = covenantSpend(300n);
  assert.equal(verifyCovenantSpend(prev, prevOutpoint, prevScript, tx, recipientPkh, 301n).ok, false);
  // residual re-lock tampered
  const bad: Tx = { ...tx, outputs: [tx.outputs[0]!, covenantOutput(prev.reserve - 300n + 1n, prev.rulesHash)] };
  assert.equal(verifyCovenantPayout(prev, bad, recipientPkh, 300n).ok, false);
});
