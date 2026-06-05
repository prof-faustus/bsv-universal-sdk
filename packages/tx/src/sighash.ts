// @bsv-universal/tx — BIP143/forkid sighash (BSV) + a SigChecker for the script interpreter.
//
// Only SIGHASH_ALL | FORKID (0x41) is supported here: every signature commits to ALL outputs, giving
// atomicity / anti-tamper (a changed output invalidates every signature) — the property ESTATES relies
// on. The checker computes the preimage from the tx context and ECDSA-verifies (REQ-SEC-007: real
// script satisfaction). It is TOTAL — a malformed sig/pubkey yields `false`, never a throw.

import { concatBytes } from '@bsv-universal/protocol-types';
import { verifyBitcoin } from '@bsv-universal/crypto';
import type { SigChecker } from '@bsv-universal/script';
import { sha256, hash256, u32le, u64le, varBytes, type Tx } from './tx.ts';

export const SIGHASH_ALL_FORKID = 0x41;

function hashPrevouts(tx: Tx): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const i of tx.inputs) parts.push(i.outpoint.txid, u32le(i.outpoint.vout));
  return hash256(concatBytes(...parts));
}
function hashSequence(tx: Tx): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const i of tx.inputs) parts.push(u32le(i.sequence));
  return hash256(concatBytes(...parts));
}
function hashOutputs(tx: Tx): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const o of tx.outputs) parts.push(u64le(o.satoshis), varBytes(o.lockingScript));
  return hash256(concatBytes(...parts));
}

/** The BIP143 sighash PREIMAGE for input `index` spending a prevout of `prevScript`/`amount`. */
export function sighashPreimage(tx: Tx, index: number, prevScript: Uint8Array, amount: bigint, hashType: number = SIGHASH_ALL_FORKID): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index >= tx.inputs.length) throw new Error('input index out of range');
  if (hashType !== SIGHASH_ALL_FORKID) throw new Error('only SIGHASH_ALL|FORKID is supported');
  const input = tx.inputs[index]!;
  return concatBytes(
    u32le(tx.version),
    hashPrevouts(tx),
    hashSequence(tx),
    input.outpoint.txid,
    u32le(input.outpoint.vout),
    varBytes(prevScript),
    u64le(amount),
    u32le(input.sequence),
    hashOutputs(tx),
    u32le(tx.lockTime),
    u32le(hashType >>> 0),
  );
}

/** sighash = double-SHA256(preimage). */
export function sighash(tx: Tx, index: number, prevScript: Uint8Array, amount: bigint): Uint8Array {
  return hash256(sighashPreimage(tx, index, prevScript, amount));
}

/**
 * A SigChecker bound to one spending context. Script signatures are DER ‖ hashType-byte; the checker
 * strips the trailing hashType, recomputes the preimage for it, and ECDSA-verifies. Total.
 */
export function sighashChecker(tx: Tx, index: number, prevScript: Uint8Array, amount: bigint): SigChecker {
  return {
    check(sig: Uint8Array, pubkey: Uint8Array): boolean {
      if (sig.length < 1) return false;
      const hashType = sig[sig.length - 1]!;
      if (hashType !== SIGHASH_ALL_FORKID) return false; // fail-closed on unsupported types
      const der = sig.slice(0, sig.length - 1);
      let preimage: Uint8Array;
      try {
        preimage = sighashPreimage(tx, index, prevScript, amount, hashType);
      } catch {
        return false;
      }
      return verifyBitcoin(preimage, der, pubkey);
    },
  };
}
