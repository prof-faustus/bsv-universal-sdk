// @bsv-universal/script — bounded, total script parser (SANS: script bytes are hostile).
// Returns a typed rejection on any malformed/oversized script; never throws.

import { type Parsed } from '@bsv-universal/protocol-types';
import { OP, BANNED_OPCODES, type EvalLimits } from './opcodes.ts';

export type Op = { readonly kind: 'push'; readonly push: Uint8Array } | { readonly kind: 'op'; readonly code: number };

export function isPush(op: Op): op is { kind: 'push'; push: Uint8Array } {
  return op.kind === 'push';
}

/** Parse raw script bytes into ops. Bounded by limits; rejects banned opcodes at parse time. */
export function parseScript(bytes: Uint8Array, limits: EvalLimits): Parsed<Op[]> {
  if (!(bytes instanceof Uint8Array)) return { ok: false, reason: 'script must be bytes' };
  if (bytes.length > limits.maxScriptBytes) return { ok: false, reason: `script exceeds ${limits.maxScriptBytes} bytes` };
  const ops: Op[] = [];
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i]!;
    i += 1;
    if (b >= 0x01 && b <= 0x4b) {
      const r = take(bytes, i, b, limits);
      if (!r.ok) return r;
      ops.push({ kind: 'push', push: r.data });
      i = r.next;
    } else if (b === OP.OP_PUSHDATA1 || b === OP.OP_PUSHDATA2 || b === OP.OP_PUSHDATA4) {
      const szLen = b === OP.OP_PUSHDATA1 ? 1 : b === OP.OP_PUSHDATA2 ? 2 : 4;
      const len = readLE(bytes, i, szLen);
      if (len === null) return { ok: false, reason: 'truncated pushdata length' };
      i += szLen;
      const r = take(bytes, i, len, limits);
      if (!r.ok) return r;
      ops.push({ kind: 'push', push: r.data });
      i = r.next;
    } else {
      if (b in BANNED_OPCODES) return { ok: false, reason: `banned opcode ${BANNED_OPCODES[b]} (REQ-BAN)` };
      ops.push({ kind: 'op', code: b });
    }
    if (ops.length > limits.maxOps) return { ok: false, reason: 'too many ops' };
  }
  return { ok: true, value: ops };
}

function take(bytes: Uint8Array, start: number, len: number, limits: EvalLimits): { ok: true; data: Uint8Array; next: number } | { ok: false; reason: string } {
  if (len > limits.maxElement) return { ok: false, reason: `push of ${len} exceeds maxElement ${limits.maxElement}` };
  const end = start + len;
  if (end > bytes.length) return { ok: false, reason: 'truncated push payload' };
  return { ok: true, data: bytes.slice(start, end), next: end };
}

function readLE(bytes: Uint8Array, start: number, n: number): number | null {
  if (start + n > bytes.length) return null;
  let v = 0;
  for (let k = 0; k < n; k++) v += bytes[start + k]! * 2 ** (8 * k);
  return v;
}
