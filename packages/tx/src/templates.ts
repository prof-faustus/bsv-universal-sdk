// @bsv-universal/tx — script templates: P2PKH + covenant, with the REQ-SEC-008 covenant-spend binding.
// No banned BTC artifacts (REQ-BAN): timing is tx-level (nLockTime/nSequence), covenant state is a
// locking-script data push (no data-carrier opcode).

import { concatBytes, bytesEqual } from '@bsv-universal/protocol-types';
import { hash160, signBitcoin, type KeyPair } from '@bsv-universal/crypto';
import { OP } from '@bsv-universal/script';
import { sighashPreimage, SIGHASH_ALL_FORKID } from './sighash.ts';
import { type Tx, type TxOutput, type Outpoint } from './tx.ts';

/** Minimal pushdata encoding for an item (direct push / PUSHDATA1 / PUSHDATA2). */
export function pushData(data: Uint8Array): Uint8Array {
  const n = data.length;
  if (n < OP.OP_PUSHDATA1) return concatBytes(new Uint8Array([n]), data);
  if (n <= 0xff) return concatBytes(new Uint8Array([OP.OP_PUSHDATA1, n]), data);
  if (n <= 0xffff) return concatBytes(new Uint8Array([OP.OP_PUSHDATA2, n & 0xff, (n >>> 8) & 0xff]), data);
  throw new Error('pushData too large for a template');
}

// ---- P2PKH -----------------------------------------------------------------------------------
/** Locking script for a 20-byte key hash: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG. */
export function p2pkhLockingFromPkh(pkh: Uint8Array): Uint8Array {
  if (pkh.length !== 20) throw new Error('pkh must be 20 bytes');
  return concatBytes(new Uint8Array([OP.OP_DUP, OP.OP_HASH160]), pushData(pkh), new Uint8Array([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]));
}
export function p2pkhLocking(pub65: Uint8Array): Uint8Array {
  return p2pkhLockingFromPkh(hash160(pub65));
}
export function p2pkhUnlocking(sigWithType: Uint8Array, pub65: Uint8Array): Uint8Array {
  return concatBytes(pushData(sigWithType), pushData(pub65));
}

/** Sign input `index` (P2PKH) and return its unlocking script (REQ-SEC-007 real signing). */
export function signP2PKH(tx: Tx, index: number, prevScript: Uint8Array, amount: bigint, kp: KeyPair): Uint8Array {
  const der = signBitcoin(sighashPreimage(tx, index, prevScript, amount), kp);
  const sigWithType = concatBytes(der, new Uint8Array([SIGHASH_ALL_FORKID]));
  return p2pkhUnlocking(sigWithType, kp.pub);
}

// ---- covenant (REQ-SEC-008) ------------------------------------------------------------------
export interface Covenant {
  readonly reserve: bigint;
  readonly rulesHash: Uint8Array; // 32 bytes
}
export type CovenantCheck = { readonly ok: true; readonly reason: string } | { readonly ok: false; readonly reason: string };

function reserveBytes(reserve: bigint): Uint8Array {
  if (reserve < 0n || reserve > 0xffffffffffffffffn) throw new Error('reserve out of range');
  const out = new Uint8Array(8);
  let v = reserve;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** The canonical covenant output for a (reserve, rulesHash): state carried as locking-script pushes. */
export function covenantOutput(reserve: bigint, rulesHash: Uint8Array): TxOutput {
  if (rulesHash.length !== 32) throw new Error('rulesHash must be 32 bytes');
  const lockingScript = concatBytes(
    pushData(rulesHash),
    new Uint8Array([OP.OP_DROP]),
    pushData(reserveBytes(reserve)),
    new Uint8Array([OP.OP_DROP, OP.OP_1]),
  );
  return { satoshis: reserve, lockingScript };
}

/** Payout predicate: out0 pays exactly `amount` to `recipientPkh`; out1 re-locks the residual. */
export function verifyCovenantPayout(prev: Covenant, tx: Tx, recipientPkh: Uint8Array, amount: bigint): CovenantCheck {
  if (recipientPkh.length !== 20) return { ok: false, reason: 'recipientPkh must be 20 bytes' };
  if (amount < 0n || amount > prev.reserve) return { ok: false, reason: 'amount out of [0, reserve]' };
  if (tx.outputs.length < 2) return { ok: false, reason: 'covenant spend needs payout + residual outputs' };
  const out0 = tx.outputs[0]!;
  const want0 = p2pkhLockingFromPkh(recipientPkh);
  if (out0.satoshis !== amount || !bytesEqual(out0.lockingScript, want0)) return { ok: false, reason: 'output 0 must pay exactly amount to recipient' };
  const out1 = tx.outputs[1]!;
  const want1 = covenantOutput(prev.reserve - amount, prev.rulesHash);
  if (out1.satoshis !== want1.satoshis || !bytesEqual(out1.lockingScript, want1.lockingScript)) return { ok: false, reason: 'output 1 must re-lock the residual to the same covenant' };
  return { ok: true, reason: 'covenant payout valid' };
}

/**
 * REQ-SEC-008: a FULL covenant-spend check that BINDS the predicate to the chain — not just to a
 * caller-supplied recipient/amount. VALID iff the tx actually spends the named covenant outpoint,
 * the spent prevout script IS this covenant's script for `prev.reserve`/`prev.rulesHash` (pinning
 * the rules hash + reserve to the real UTXO), AND the outputs satisfy the payout predicate.
 * `recipientPkh`/`amount` MUST be the canonical values the deterministic engine mandates for the
 * current state — the residual re-lock binds the rules hash, so a wrong-rules spend cannot validate.
 */
export function verifyCovenantSpend(
  prev: Covenant,
  prevOutpoint: Outpoint,
  prevScript: Uint8Array,
  tx: Tx,
  recipientPkh: Uint8Array,
  amount: bigint,
): CovenantCheck {
  const inp = tx.inputs[0];
  if (!inp || !bytesEqual(inp.outpoint.txid, prevOutpoint.txid) || inp.outpoint.vout !== prevOutpoint.vout) {
    return { ok: false, reason: 'tx does not spend the covenant outpoint' };
  }
  const expectedPrev = covenantOutput(prev.reserve, prev.rulesHash).lockingScript;
  if (!bytesEqual(prevScript, expectedPrev)) {
    return { ok: false, reason: 'spent prevout script is not this covenant (rules hash / reserve mismatch)' };
  }
  return verifyCovenantPayout(prev, tx, recipientPkh, amount);
}
