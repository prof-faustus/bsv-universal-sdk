// @bsv-universal/sdk — authenticated protocol envelope (REQ-SEC-001).
//
// Every protocol message is a SIGNED envelope; relay ordering is never authentication. The signed
// payload binds network/module/contract/version/kind/seatId/actorPubKey/priorTranscriptHash/
// sequenceNo/body. The signer MUST be the player's own key, and its partyId MUST equal the seat it
// claims. Verification is TOTAL (returns a typed reject; a failing envelope is DROPPED, never applied).

import {
  canonicalStringify,
  taggedHash,
  HASH_TAGS,
  utf8,
  fromHex,
  toHex,
  tryFromHex,
  safeJsonParse,
  isObject,
  type Canonical,
  type Parsed,
} from '@bsv-universal/protocol-types';
import { signData, verifyData, partyId, type KeyPair } from '@bsv-universal/crypto';

export type MessageKind = 'start' | 'action' | 'leave' | 'commit' | 'reveal' | 'randomness';
const MESSAGE_KINDS: readonly MessageKind[] = ['start', 'action', 'leave', 'commit', 'reveal', 'randomness'];
const NETWORKS = ['main', 'test', 'regtest'] as const;

/** Hard caps on envelope structure (CWE-770). The relay's maxBody is the transport-level mirror. */
export const MAX_ENVELOPE_BYTES = 256 * 1024;
const MAX_ID_LEN = 128; // moduleId / contractId string length
const MAX_BODY_HEX = MAX_ENVELOPE_BYTES * 2;
const MAX_SIG_BYTES = 80; // DER secp256k1 sig is ≤ 72; allow slack

export interface EnvelopeFields {
  readonly networkId: 'main' | 'test' | 'regtest';
  readonly moduleId: string;
  readonly contractId: string; // gameId hex
  readonly protocolVersion: number;
  readonly messageKind: MessageKind;
  readonly seatId: string; // 33B partyId hex of the seat this message acts for
  readonly actorPubKeyHex: string; // 65B uncompressed hex — the player's own key
  readonly priorTranscriptHash: string; // hex of the accepted-prefix transcript head
  readonly sequenceNo: number; // strictly monotonic per contract
  readonly bodyHex: string; // canonical body bytes (kind-specific)
}

export interface Envelope extends EnvelopeFields {
  readonly sigHex: string;
}

/** Wire codec: an envelope travels the relay as opaque hex (the relay never interprets it). */
export function envelopeToHex(env: Envelope): string {
  return toHex(utf8(JSON.stringify(env)));
}

/**
 * TOTAL, validating decoder for envelopes arriving from the (hostile) relay (CWE-502/20/770).
 * Every field is type- and length-checked; it NEVER throws on adversarial input — a malformed,
 * oversized, or wrong-shaped message is a typed rejection. Use this at the network boundary.
 */
export function tryEnvelopeFromHex(hex: string): Parsed<Envelope> {
  if (typeof hex !== 'string' || hex.length > MAX_BODY_HEX) return { ok: false, reason: 'envelope hex too large or not a string' };
  const bytes = tryFromHex(hex);
  if (!bytes.ok) return { ok: false, reason: `envelope hex: ${bytes.reason}` };
  const parsed = safeJsonParse(new TextDecoder().decode(bytes.bytes), MAX_ENVELOPE_BYTES);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const o = parsed.value;
  if (!isObject(o)) return { ok: false, reason: 'envelope must be a JSON object' };

  const str = (v: unknown, max: number) => typeof v === 'string' && v.length <= max;
  const hexStr = (v: unknown, max: number) => typeof v === 'string' && v.length % 2 === 0 && v.length <= max && /^[0-9a-fA-F]*$/.test(v);

  if (!NETWORKS.includes(o.networkId as (typeof NETWORKS)[number])) return { ok: false, reason: 'bad networkId' };
  if (!str(o.moduleId, MAX_ID_LEN)) return { ok: false, reason: 'bad moduleId' };
  if (!str(o.contractId, MAX_ID_LEN)) return { ok: false, reason: 'bad contractId' };
  if (!Number.isInteger(o.protocolVersion) || (o.protocolVersion as number) < 0 || (o.protocolVersion as number) > 0xffff) return { ok: false, reason: 'bad protocolVersion' };
  if (!MESSAGE_KINDS.includes(o.messageKind as MessageKind)) return { ok: false, reason: 'bad messageKind' };
  if (!hexStr(o.seatId, 66)) return { ok: false, reason: 'bad seatId' }; // 33-byte partyId
  if (!hexStr(o.actorPubKeyHex, 130)) return { ok: false, reason: 'bad actorPubKeyHex' }; // 65-byte pub
  if (!hexStr(o.priorTranscriptHash, 64)) return { ok: false, reason: 'bad priorTranscriptHash' }; // 32-byte
  if (!Number.isInteger(o.sequenceNo) || (o.sequenceNo as number) < 0 || (o.sequenceNo as number) > Number.MAX_SAFE_INTEGER) return { ok: false, reason: 'bad sequenceNo' };
  if (!hexStr(o.bodyHex, MAX_BODY_HEX)) return { ok: false, reason: 'bad bodyHex' };
  if (!hexStr(o.sigHex, MAX_SIG_BYTES * 2)) return { ok: false, reason: 'bad sigHex' };

  return {
    ok: true,
    value: {
      networkId: o.networkId as Envelope['networkId'],
      moduleId: o.moduleId as string,
      contractId: o.contractId as string,
      protocolVersion: o.protocolVersion as number,
      messageKind: o.messageKind as MessageKind,
      seatId: o.seatId as string,
      actorPubKeyHex: o.actorPubKeyHex as string,
      priorTranscriptHash: o.priorTranscriptHash as string,
      sequenceNo: o.sequenceNo as number,
      bodyHex: o.bodyHex as string,
      sigHex: o.sigHex as string,
    },
  };
}

/** Throwing convenience wrapper for TRUSTED callers/tests only. Never use at a trust boundary. */
export function envelopeFromHex(hex: string): Envelope {
  const r = tryEnvelopeFromHex(hex);
  if (!r.ok) throw new Error(`envelopeFromHex: ${r.reason}`);
  return r.value;
}

function payloadBytes(f: EnvelopeFields): Uint8Array {
  // Canonicalize ONLY the signed field subset — never `sigHex` (which is absent at signing time
  // and present at verify time; including it would make every signature fail to verify).
  const signed: Canonical = {
    networkId: f.networkId,
    moduleId: f.moduleId,
    contractId: f.contractId,
    protocolVersion: f.protocolVersion,
    messageKind: f.messageKind,
    seatId: f.seatId,
    actorPubKeyHex: f.actorPubKeyHex,
    priorTranscriptHash: f.priorTranscriptHash,
    sequenceNo: f.sequenceNo,
    bodyHex: f.bodyHex,
  };
  return taggedHash(HASH_TAGS.envelope, utf8(canonicalStringify(signed)));
}

/** Sign an envelope with the player's OWN key (REQ-SEC-001). Verifies the key matches the seat. */
export function signEnvelope(fields: EnvelopeFields, kp: KeyPair): Envelope {
  const expectSeat = toHex(partyId(kp.pub));
  if (fields.seatId !== expectSeat) throw new Error('signing key partyId does not match seatId');
  if (fields.actorPubKeyHex !== toHex(kp.pub)) throw new Error('actorPubKeyHex does not match signing key');
  const sig = signData(payloadBytes(fields), kp);
  return { ...fields, sigHex: toHex(sig) };
}

/** Hash a transcript head forward by one accepted envelope (REQ-SEC-001 chaining). */
export function chainTranscript(priorHashHex: string, env: Envelope): string {
  const prior = priorHashHex.length === 0 ? new Uint8Array(32) : fromHex(priorHashHex);
  return toHex(taggedHash(HASH_TAGS.transcript, prior, payloadBytes(env)));
}

export interface VerifyContext {
  readonly networkId: EnvelopeFields['networkId'];
  readonly moduleId: string;
  readonly contractId: string;
  readonly protocolVersion: number;
  readonly headHash: string; // current accepted transcript head (hex; '' or 32 zero-bytes for genesis)
  readonly expectedSeq: number;
}

export type EnvelopeCheck = { readonly ok: true } | { readonly ok: false; readonly reason: string };

/** Verify an envelope against the session context. TOTAL — never throws; a failure means DROP. */
export function verifyEnvelope(env: Envelope, ctx: VerifyContext): EnvelopeCheck {
  try {
    if (env.networkId !== ctx.networkId) return { ok: false, reason: 'network mismatch' };
    if (env.moduleId !== ctx.moduleId) return { ok: false, reason: 'module mismatch' };
    if (env.contractId !== ctx.contractId) return { ok: false, reason: 'contract mismatch' };
    if (env.protocolVersion !== ctx.protocolVersion) return { ok: false, reason: 'protocol version mismatch' };
    if (env.sequenceNo !== ctx.expectedSeq) return { ok: false, reason: `sequence ${env.sequenceNo} != expected ${ctx.expectedSeq}` };

    const normHead = ctx.headHash.length === 0 ? toHex(new Uint8Array(32)) : ctx.headHash;
    const normPrior = env.priorTranscriptHash.length === 0 ? toHex(new Uint8Array(32)) : env.priorTranscriptHash;
    if (normPrior !== normHead) return { ok: false, reason: 'prior-transcript-hash does not match head (fork/replay)' };

    let actorPub: Uint8Array;
    try {
      actorPub = fromHex(env.actorPubKeyHex);
    } catch {
      return { ok: false, reason: 'bad actor pubkey hex' };
    }
    if (actorPub.length !== 65 || actorPub[0] !== 0x04) return { ok: false, reason: 'actor pubkey must be uncompressed 65B' };
    // actor-key binding: the signer's partyId MUST equal the seat it claims (REQ-SEC-001).
    if (toHex(partyId(actorPub)) !== env.seatId) return { ok: false, reason: 'actor key does not match seatId' };

    let sig: Uint8Array;
    try {
      sig = fromHex(env.sigHex);
    } catch {
      return { ok: false, reason: 'bad signature hex' };
    }
    if (!verifyData(payloadBytes(env), sig, actorPub)) return { ok: false, reason: 'signature does not verify (unsigned/forged)' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `envelope verify error: ${(e as Error).message}` };
  }
}
