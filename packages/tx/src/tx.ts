// @bsv-universal/tx — real BSV transaction model (REQ-SEC-007): canonical serialization + txid.
// Integers are bigint/number with explicit range checks (no float; CWE-190 guarded). All structure
// is bounded (MAX_IO) so a hostile tx cannot exhaust resources.

import { createHash } from 'node:crypto';
import { concatBytes, u32be } from '@bsv-universal/protocol-types';

export const MAX_IO = 10_000; // bound inputs/outputs per tx (CWE-770)

export interface Outpoint {
  readonly txid: Uint8Array; // 32 bytes, internal byte order
  readonly vout: number; // uint32
}
export interface TxInput {
  readonly outpoint: Outpoint;
  readonly unlockingScript: Uint8Array;
  readonly sequence: number; // uint32 (REQ-TIME: relative-locktime carrier; no CSV opcode)
}
export interface TxOutput {
  readonly satoshis: bigint;
  readonly lockingScript: Uint8Array;
}
export interface Tx {
  readonly version: number; // uint32
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly lockTime: number; // uint32 (REQ-TIME: absolute-locktime carrier; no CLTV opcode)
}

function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`u32 out of range: ${n}`);
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}
function u64le(n: bigint): Uint8Array {
  if (typeof n !== 'bigint' || n < 0n || n > 0xffffffffffffffffn) throw new Error(`u64 out of range: ${n}`);
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Bitcoin CompactSize varint. */
export function varint(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new Error(`varint out of range: ${n}`);
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]);
  if (n <= 0xffffffff) return concatBytes(new Uint8Array([0xfe]), u32le(n));
  return concatBytes(new Uint8Array([0xff]), u64le(BigInt(n)));
}

function varBytes(b: Uint8Array): Uint8Array {
  return concatBytes(varint(b.length), b);
}

export const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());
export const hash256 = (b: Uint8Array): Uint8Array => sha256(sha256(b));

function checkBounds(tx: Tx): void {
  if (!Number.isInteger(tx.version) || tx.version < 0 || tx.version > 0xffffffff) throw new Error('bad version');
  if (!Number.isInteger(tx.lockTime) || tx.lockTime < 0 || tx.lockTime > 0xffffffff) throw new Error('bad lockTime');
  if (tx.inputs.length > MAX_IO || tx.outputs.length > MAX_IO) throw new Error('too many inputs/outputs');
}

/** Canonical transaction serialization. */
export function serializeTx(tx: Tx): Uint8Array {
  checkBounds(tx);
  const parts: Uint8Array[] = [u32le(tx.version), varint(tx.inputs.length)];
  for (const i of tx.inputs) {
    if (i.outpoint.txid.length !== 32) throw new Error('outpoint txid must be 32 bytes');
    parts.push(i.outpoint.txid, u32le(i.outpoint.vout), varBytes(i.unlockingScript), u32le(i.sequence));
  }
  parts.push(varint(tx.outputs.length));
  for (const o of tx.outputs) parts.push(u64le(o.satoshis), varBytes(o.lockingScript));
  parts.push(u32le(tx.lockTime));
  return concatBytes(...parts);
}

/** Transaction id = double-SHA256 of the canonical serialization (internal byte order). */
export function txid(tx: Tx): Uint8Array {
  return hash256(serializeTx(tx));
}

export { u32le, u64le, varBytes, u32be };
