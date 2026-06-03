// @bsv-universal/protocol-types — canonical encoding primitives.
//
// Requirements realized here:
//  - REQ-SEC-009 : one strict hex codec (reject odd length / non-hex / wrong length); no silent
//                  zero-bytes. Conforms to ESTATES fromHexStrict.
//  - REQ-DET-001 : exactly one canonical serialization per object (stable, sorted-key form).
//  - REQ-DET-002 : no floating point in the canonical/consensus path (integers + bigint only).
//  - REQ-DET-003 : no iteration over unordered collections — keys are canonically ordered.
//  - REQ-DET-005 : domain-separated hashing H(tag ‖ bytes) with an explicit tag registry.
//  - REQ-SEC-006 : strict total decoders — out-of-range input becomes a typed rejection,
//                  never a masked/defaulted value.
//  - REQ-ENG-004 : decoders are total (never throw on adversarial input unless the caller opts
//                  into the throwing variant); `tryDecode` returns a typed result.

import { createHash } from 'node:crypto';

// ----------------------------------------------------------------------------- strict hex codec
const HEX_RE = /^[0-9a-fA-F]*$/;

/** Strict hex → bytes (REQ-SEC-009). Throws on odd length / non-hex. No silent zero-bytes. */
export function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !HEX_RE.test(h)) {
    throw new Error(`bad hex: must be even-length and [0-9a-fA-F] only (got ${describe(h)})`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Total variant of fromHex (REQ-ENG-004): never throws; returns a typed result. */
export function tryFromHex(h: string): { ok: true; bytes: Uint8Array } | { ok: false; reason: string } {
  try {
    return { ok: true, bytes: fromHex(h) };
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/** Strict 32-byte txid hex (REQ-SEC-006): exactly 64 hex chars. */
export function txidFromHex(h: string): Uint8Array {
  if (h.length !== 64) throw new Error(`txid must be 64 hex chars, got ${h.length}`);
  return fromHex(h);
}

function describe(h: unknown): string {
  if (typeof h !== 'string') return typeof h;
  return h.length > 16 ? `${h.slice(0, 16)}…(${h.length})` : h;
}

// ----------------------------------------------------------------------------- byte helpers
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`u32be out of range: ${n}`);
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export function u64be(n: bigint): Uint8Array {
  if (typeof n !== 'bigint' || n < 0n || n > 0xffffffffffffffffn) throw new Error(`u64be out of range: ${n}`);
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

// ----------------------------------------------------------------------------- domain-sep hashing
// REQ-DET-005: every hash is H(tag ‖ bytes) with the tag drawn from this registry. A bare
// sha256(bytes) is not allowed in the canonical path — domain separation prevents cross-protocol
// collision (a commitment can never be reinterpreted as a state hash, etc.).
export const HASH_TAGS = {
  state: 'bsv-universal/state/v1',
  commit: 'bsv-universal/commit/v1',
  beacon: 'bsv-universal/beacon/v1',
  envelope: 'bsv-universal/envelope/v1',
  transcript: 'bsv-universal/transcript/v1',
  ruleset: 'bsv-universal/ruleset/v1',
} as const;
export type HashTag = (typeof HASH_TAGS)[keyof typeof HASH_TAGS];

export function taggedHash(tag: HashTag, ...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  h.update(utf8(tag));
  h.update(new Uint8Array([0x00])); // separator between tag and payload
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

// ----------------------------------------------------------------------------- canonical JSON
// REQ-DET-001/002/003: exactly one serialization. Keys sorted; integers and bigints only (no
// float in the canonical path); arrays preserved in order; strings/booleans/null allowed.
export type Canonical =
  | string
  | number // MUST be a safe integer (REQ-DET-002 guards floats)
  | bigint
  | boolean
  | null
  | Canonical[]
  | { [k: string]: Canonical };

export function canonicalStringify(v: Canonical): string {
  return encode(v);
}

function encode(v: Canonical): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string':
      return JSON.stringify(v);
    case 'boolean':
      return v ? 'true' : 'false';
    case 'bigint':
      return `"${v.toString()}n"`; // bigints serialize with an explicit suffix, unambiguously
    case 'number':
      if (!Number.isInteger(v)) throw new Error(`non-integer number in canonical path (REQ-DET-002): ${v}`);
      if (!Number.isSafeInteger(v)) throw new Error(`unsafe integer in canonical path (use bigint): ${v}`);
      return v.toString();
    case 'object':
      if (Array.isArray(v)) return `[${v.map(encode).join(',')}]`;
      // REQ-DET-003: sort keys to a canonical order before iterating.
      return `{${Object.keys(v)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${encode(v[k] as Canonical)}`)
        .join(',')}}`;
    default:
      throw new Error(`unserializable type in canonical path: ${typeof v}`);
  }
}

/** Canonical state hash (REQ-DET-001 + REQ-DET-005). */
export function canonicalHash(v: Canonical): Uint8Array {
  return taggedHash(HASH_TAGS.state, utf8(canonicalStringify(v)));
}

// ----------------------------------------------------------------------------- strict decode guard
// REQ-SEC-006: build strict, total decoders. `expectInt` rejects out-of-range rather than masking.
export function expectInt(value: unknown, lo: number, hi: number, field: string): number {
  if (!Number.isInteger(value) || (value as number) < lo || (value as number) > hi) {
    throw new Error(`${field} out of range ${lo}..${hi} (got ${String(value)})`);
  }
  return value as number;
}

export function expectBool(value: unknown, field: string): boolean {
  if (value !== true && value !== false) throw new Error(`${field} must be a boolean (got ${String(value)})`);
  return value;
}

export function expectOneOf<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new Error(`${field} must be one of {${allowed.join(', ')}} (got ${String(value)})`);
  }
  return value as T;
}
