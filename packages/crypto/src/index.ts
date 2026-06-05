// @bsv-universal/crypto — verifiable randomness + player-key signatures. ISOMORPHIC (Node + browser)
// via audited @noble libraries; no node:crypto. Mirrors ESTATES' use of @noble/*.
//
// Requirements realized here:
//  - REQ-SEC-002 : randomness is beacon-derived from a commit→reveal round with REJECTION
//                  SAMPLING (no modulo bias) and prev-beacon chaining. No raw values.
//  - REQ-SEC-003 : verifyBeaconRound enforces one commitment per eligible seat, commit-precedes-
//                  reveal, secret-opens-commitment, no duplicate / non-seat reveal, ≥1 honest
//                  reveal; the outcome derives ONLY from the verified reveal set.
//  - REQ-SEC-001 : player keys — the player's OWN secp256k1 key signs moves (never a throwaway).
//  - REQ-COMMIT-001/002 : commitment binding + verification.

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { ripemd160 as nobleRipemd160 } from '@noble/hashes/ripemd160';
import {
  taggedHash,
  HASH_TAGS,
  concatBytes,
  u32be,
  bytesEqual,
  type HashTag,
} from '@bsv-universal/protocol-types';

function sha256(b: Uint8Array): Uint8Array {
  return nobleSha256(b);
}

/** Isomorphic CSPRNG bytes (Node + browser via WebCrypto). Bounded length. */
export function randomBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 1 << 20) throw new Error('randomBytes length out of range');
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Constant-time equality for fixed-length digests (CWE-208). */
function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

// ============================================================================ player keys (secp256k1)
// A player's identity IS their own long-lived key (REQ-SEC-001 / REQ-BAN-008): the same key
// authenticates the session, signs every move, and addresses chat. Public keys are carried
// uncompressed (65B) for crypto; `partyId` is the 33B compressed form used for addressing/ordering.
export interface KeyPair {
  readonly priv: Uint8Array; // 32 bytes
  readonly pub: Uint8Array; // 65 bytes, uncompressed 0x04||X||Y
}

function pubFromPriv(priv: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(priv, false); // uncompressed 65B; throws on invalid scalar
}

/** Generate a player master key (REQ-SEC-001). Long-lived; the player's sole signing authority. */
export function genKeyPair(): KeyPair {
  const priv = secp256k1.utils.randomPrivateKey(); // CSPRNG, always a valid scalar
  return { priv, pub: pubFromPriv(priv) };
}

export function keyPairFromPriv(priv: Uint8Array): KeyPair {
  if (priv.length !== 32) throw new Error('priv must be 32 bytes');
  return { priv, pub: pubFromPriv(priv) };
}

/** 33-byte compressed public key — the canonical party identifier (REQ-DET-003 ordering key). */
export function partyId(pub: Uint8Array): Uint8Array {
  if (pub.length !== 65 || pub[0] !== 0x04) throw new Error('pub must be uncompressed 65B');
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const prefix = (y[31]! & 1) === 0 ? 0x02 : 0x03;
  return concatBytes(new Uint8Array([prefix]), x);
}

/** Sign a payload with the player's own key (REQ-SEC-001). Returns a DER ECDSA signature (low-s). */
export function signData(payload: Uint8Array, kp: KeyPair): Uint8Array {
  return secp256k1.sign(sha256(payload), kp.priv).toDERRawBytes();
}

/** Verify a payload signature against a player public key (REQ-SEC-001). Total: never throws. */
export function verifyData(payload: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  try {
    return secp256k1.verify(secp256k1.Signature.fromDER(sig), sha256(payload), pub);
  } catch {
    return false;
  }
}

// ============================================================================ Bitcoin sighash sig
// A Bitcoin signature is ECDSA over the double-SHA256 of the preimage (the "sighash"). Public keys
// are 65-byte uncompressed (no point decompression needed).
/** Sign a transaction sighash preimage with the player's key (REQ-SEC-007). Returns a DER signature. */
export function signBitcoin(preimage: Uint8Array, kp: KeyPair): Uint8Array {
  return secp256k1.sign(sha256(sha256(preimage)), kp.priv).toDERRawBytes();
}

/** Verify a Bitcoin-sighash DER signature against a 65-byte uncompressed pubkey. Total: never throws. */
export function verifyBitcoin(preimage: Uint8Array, derSig: Uint8Array, pub: Uint8Array): boolean {
  try {
    if (pub.length !== 65 || pub[0] !== 0x04) return false;
    return secp256k1.verify(secp256k1.Signature.fromDER(derSig), sha256(sha256(preimage)), pub);
  } catch {
    return false;
  }
}

/** HASH160 = RIPEMD160(SHA256(x)) — the P2PKH key hash. */
export function hash160(b: Uint8Array): Uint8Array {
  return nobleRipemd160(sha256(b));
}

// ============================================================================ commit / reveal
/** Commitment to a secret (REQ-COMMIT-001): domain-separated so it can't be reread as a state hash. */
export function commit(secret: Uint8Array): Uint8Array {
  return taggedHash(HASH_TAGS.commit, secret);
}

/** Constant-time reveal check (REQ-COMMIT-002). */
export function verifyReveal(secret: Uint8Array, commitment: Uint8Array): boolean {
  const c = commit(secret);
  return ctEqual(c, commitment);
}

// ============================================================================ debiased draw (REQ-SEC-002)
// Rejection sampling: reject bytes in the biased tail so every residue class mod `modulus` is
// equally likely. This is the exact defect ESTATES' audit flagged (`% 6` over 256 is biased).
export function drawValue(seed: Uint8Array, label: number, modulus: number): number {
  if (!Number.isInteger(modulus) || modulus < 1 || modulus > 256) throw new Error('modulus must be 1..256');
  const limit = Math.floor(256 / modulus) * modulus; // largest multiple of modulus ≤ 256
  for (let counter = 0; counter < 1 << 24; counter++) {
    const block = taggedHash(HASH_TAGS.beacon, seed, u32be(label), u32be(counter));
    for (const b of block) {
      if (b < limit) return b % modulus;
    }
  }
  /* c8 ignore next */ throw new Error('drawValue: exhausted counter space (statistically impossible)');
}

// ============================================================================ beacon round
export interface PartyCommit {
  readonly party: Uint8Array; // 33B partyId
  readonly commitment: Uint8Array; // 32B
}
export interface PartyReveal {
  readonly party: Uint8Array; // 33B partyId
  readonly secret: Uint8Array;
}

export interface BeaconRound {
  readonly roundNo: number;
  readonly commits: readonly PartyCommit[];
  readonly reveals: readonly PartyReveal[];
  readonly prevBeacon: Uint8Array; // 32B; all-zero for the first round
}

export type RoundCheck =
  | { ok: true; seed: Uint8Array; honest: readonly PartyReveal[] }
  | { ok: false; reason: string };

function idHex(p: Uint8Array): string {
  let s = '';
  for (const x of p) s += x.toString(16).padStart(2, '0');
  return s;
}

/**
 * Verify a beacon round and derive its seed (REQ-SEC-002 + REQ-SEC-003). `eligible` is the set of
 * live seat partyIds permitted to participate this round. Enforces, in order:
 *   one commitment per eligible seat · no duplicate commitment · commitment only from eligible seat ·
 *   no duplicate reveal · reveal only from a seat that committed · secret opens its commitment ·
 *   ≥1 honest reveal (the unbiasable condition). The seed derives ONLY from the verified reveal set,
 *   ordered canonically by partyId (REQ-DET-003). Total: returns a typed result, never throws.
 */
/** Hard cap on participants in any beacon round — bounds all per-round work (CWE-770). */
export const MAX_PARTIES = 64;

export function verifyBeaconRound(round: BeaconRound, eligible: readonly Uint8Array[]): RoundCheck {
  // SANS: the round is hostile input. Reject structurally-invalid shapes BEFORE doing any work.
  if (round === null || typeof round !== 'object') return { ok: false, reason: 'round must be an object' };
  if (!Array.isArray(round.commits) || !Array.isArray(round.reveals)) return { ok: false, reason: 'commits/reveals must be arrays' };
  if (!Number.isInteger(round.roundNo) || round.roundNo < 0 || round.roundNo > 0xffffffff) return { ok: false, reason: 'roundNo out of range' };
  if (eligible.length === 0 || eligible.length > MAX_PARTIES) return { ok: false, reason: 'eligible set size out of bounds' };
  // CWE-770: bound the work — a hostile round cannot enumerate unboundedly.
  if (round.commits.length > MAX_PARTIES || round.reveals.length > MAX_PARTIES) return { ok: false, reason: 'too many commits/reveals' };

  const eligibleSet = new Set(eligible.map(idHex));

  // Commitments: one per eligible seat, no dup, only eligible.
  const commitMap = new Map<string, Uint8Array>();
  for (const c of round.commits) {
    const k = idHex(c.party);
    if (!eligibleSet.has(k)) return { ok: false, reason: `commitment from a non-eligible seat ${k}` };
    if (commitMap.has(k)) return { ok: false, reason: `duplicate commitment from seat ${k}` };
    if (c.commitment.length !== 32) return { ok: false, reason: `commitment from ${k} is not 32 bytes` };
    commitMap.set(k, c.commitment);
  }

  // Reveals: no dup, must have committed, must open the commitment.
  const seen = new Set<string>();
  const honest: PartyReveal[] = [];
  for (const rv of round.reveals) {
    const k = idHex(rv.party);
    if (seen.has(k)) return { ok: false, reason: `duplicate reveal from seat ${k}` };
    seen.add(k);
    const c = commitMap.get(k);
    if (!c) return { ok: false, reason: `reveal from seat ${k} with no prior commitment` };
    if (!verifyReveal(rv.secret, c)) return { ok: false, reason: `reveal from seat ${k} does not open its commitment` };
    honest.push(rv);
  }
  if (honest.length === 0) return { ok: false, reason: 'no honest reveal — beacon unbiasable condition fails' };
  if (round.prevBeacon.length !== 32) return { ok: false, reason: 'prevBeacon must be 32 bytes' };

  // Canonical order by partyId, then fold into the seed (REQ-DET-003 + REQ-DET-005).
  const ordered = [...honest].sort((a, b) => idHex(a.party).localeCompare(idHex(b.party)));
  const parts: Uint8Array[] = [u32be(round.roundNo), round.prevBeacon];
  for (const r of ordered) parts.push(r.party, r.secret);
  const seed = taggedHash(HASH_TAGS.beacon, ...parts);
  return { ok: true, seed, honest: ordered };
}

/** The new beacon value for chaining into the next round. */
export function beaconValue(seed: Uint8Array): Uint8Array {
  return taggedHash(HASH_TAGS.beacon, seed, u32be(0xffffffff));
}

export const ZERO_BEACON = new Uint8Array(32);

export { bytesEqual, type HashTag };
