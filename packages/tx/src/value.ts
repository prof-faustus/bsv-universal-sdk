// @bsv-universal/tx — value conservation against REAL previous UTXO amounts (REQ-SEC-007).
// Mirrors ESTATES verifyTradeValue: conserve Σ prevAmounts == Σ outputs + fee, integer-checked.

import { MAX_IO, type Tx } from './tx.ts';

export type Check = { readonly ok: true; readonly reason: string } | { readonly ok: false; readonly reason: string };

export function verifyTxValue(tx: Tx, prevAmounts: readonly bigint[], fee: bigint): Check {
  if (prevAmounts.length !== tx.inputs.length) return { ok: false, reason: `prevAmounts (${prevAmounts.length}) must match inputs (${tx.inputs.length})` };
  if (tx.inputs.length > MAX_IO || tx.outputs.length > MAX_IO) return { ok: false, reason: 'too many inputs/outputs' };
  if (typeof fee !== 'bigint' || fee < 0n) return { ok: false, reason: 'fee must be a non-negative integer' };
  let totalIn = 0n;
  for (const v of prevAmounts) {
    if (typeof v !== 'bigint' || v < 0n) return { ok: false, reason: 'each prev UTXO amount must be a non-negative integer (real satoshis)' };
    totalIn += v;
  }
  let totalOut = 0n;
  for (const o of tx.outputs) {
    if (typeof o.satoshis !== 'bigint' || o.satoshis < 0n) return { ok: false, reason: 'output satoshis must be a non-negative integer' };
    totalOut += o.satoshis;
  }
  if (totalIn !== totalOut + fee) return { ok: false, reason: `value not conserved: ${totalIn} in != ${totalOut} out + ${fee} fee` };
  return { ok: true, reason: `value conserved against real UTXOs: ${totalIn} = ${totalOut} + ${fee}` };
}
