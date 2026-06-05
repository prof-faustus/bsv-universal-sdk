// @bsv-universal/sdk — Session: the authenticated, ordered reduction of envelopes onto an engine.
//
// Ties together REQ-SEC-001 (every step from a verified signed envelope, sequence- and hash-chained),
// REQ-SEC-002/003 (randomness steps MUST carry a beacon round that verifies; the seed is DERIVED,
// never supplied), and REQ-SEC-004 (head/sequence advance ONLY on a fully accepted step, so the
// accepted prefix is a single total order). A rejected envelope is DROPPED — state does not move.

import {
  toHex,
  utf8,
  canonicalStringify,
  tryFromHex,
  safeJsonParse,
  isObject,
  expectArray,
  expectHex,
  expectBoundedHex,
  type Canonical,
  type Parsed,
} from '@bsv-universal/protocol-types';
import { verifyBeaconRound, MAX_PARTIES, type BeaconRound, type PartyCommit, type PartyReveal } from '@bsv-universal/crypto';
import { replay, type ContractModule, type Step } from '@bsv-universal/engine';
import { verifyEnvelope, chainTranscript, MAX_ENVELOPE_BYTES, type Envelope, type EnvelopeFields, type VerifyContext } from './envelope.ts';

export const GENESIS_HEAD = toHex(new Uint8Array(32));
const MAX_ACTION_TYPE_LEN = 32;
const MAX_SECRET_BYTES = 1024;

// ---- body codecs (strict, TOTAL — bodies are hostile input, CWE-502/20/770) ----------------
export function encodeActionBody(a: { type: string; amount?: bigint }): string {
  const obj: Canonical = a.amount === undefined ? { type: a.type } : { type: a.type, amount: a.amount.toString() };
  return toHex(utf8(canonicalStringify(obj)));
}

function decodeActionBody(bodyHex: string): Parsed<{ type: string; amount?: bigint }> {
  const bytes = tryFromHex(bodyHex);
  if (!bytes.ok) return { ok: false, reason: `action body hex: ${bytes.reason}` };
  const parsed = safeJsonParse(new TextDecoder().decode(bytes.bytes), MAX_ENVELOPE_BYTES);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const o = parsed.value;
  if (!isObject(o)) return { ok: false, reason: 'action body must be an object' };
  if (typeof o.type !== 'string' || o.type.length === 0 || o.type.length > MAX_ACTION_TYPE_LEN) return { ok: false, reason: 'bad action type' };
  if (o.amount === undefined) return { ok: true, value: { type: o.type } };
  if (typeof o.amount !== 'string' || !/^-?\d{1,20}$/.test(o.amount)) return { ok: false, reason: 'amount must be a bounded integer string' };
  return { ok: true, value: { type: o.type, amount: BigInt(o.amount) } };
}

export function encodeBeaconBody(round: BeaconRound): string {
  const obj: Canonical = {
    roundNo: round.roundNo,
    prevBeacon: toHex(round.prevBeacon),
    commits: round.commits.map((c) => ({ party: toHex(c.party), commitment: toHex(c.commitment) })),
    reveals: round.reveals.map((r) => ({ party: toHex(r.party), secret: toHex(r.secret) })),
  };
  return toHex(utf8(canonicalStringify(obj)));
}

function decodeBeaconBody(bodyHex: string): Parsed<BeaconRound> {
  const bytes = tryFromHex(bodyHex);
  if (!bytes.ok) return { ok: false, reason: `beacon body hex: ${bytes.reason}` };
  const parsed = safeJsonParse(new TextDecoder().decode(bytes.bytes), MAX_ENVELOPE_BYTES);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const o = parsed.value;
  if (!isObject(o)) return { ok: false, reason: 'beacon body must be an object' };
  if (!Number.isInteger(o.roundNo) || (o.roundNo as number) < 0 || (o.roundNo as number) > 0xffffffff) return { ok: false, reason: 'bad roundNo' };
  try {
    // expect* guards throw on any malformed/out-of-bound field; we catch → total (never throws out).
    const prevBeacon = expectHex(o.prevBeacon, 32, 'prevBeacon');
    const commitsRaw = expectArray(o.commits, MAX_PARTIES, 'commits');
    const revealsRaw = expectArray(o.reveals, MAX_PARTIES, 'reveals');
    const commits: PartyCommit[] = commitsRaw.map((c) => {
      if (!isObject(c)) throw new Error('commit must be an object');
      return { party: expectHex(c.party, 33, 'commit.party'), commitment: expectHex(c.commitment, 32, 'commit.commitment') };
    });
    const reveals: PartyReveal[] = revealsRaw.map((r) => {
      if (!isObject(r)) throw new Error('reveal must be an object');
      return { party: expectHex(r.party, 33, 'reveal.party'), secret: expectBoundedHex(r.secret, MAX_SECRET_BYTES, 'reveal.secret') };
    });
    return { ok: true, value: { roundNo: o.roundNo as number, prevBeacon, commits, reveals } };
  } catch (e) {
    return { ok: false, reason: `beacon body: ${(e as Error).message}` };
  }
}

// ---- session --------------------------------------------------------------------------------
export interface SessionConfig<S> {
  readonly module: ContractModule<S>;
  readonly initial: S;
  readonly networkId: EnvelopeFields['networkId'];
  readonly contractId: string;
  readonly protocolVersion: number;
  readonly eligible: readonly Uint8Array[]; // partyIds permitted in beacon rounds
}

export type AcceptResult<S> = { readonly ok: true; readonly state: S } | { readonly ok: false; readonly reason: string };

export class Session<S> {
  private _state: S;
  private _head: string = GENESIS_HEAD;
  private _seq = 0;
  private readonly steps: Step[] = [];
  private readonly cfg: SessionConfig<S>;
  constructor(cfg: SessionConfig<S>) {
    this.cfg = cfg;
    this._state = cfg.initial;
  }

  get state(): S {
    return this._state;
  }
  get head(): string {
    return this._head;
  }
  get seq(): number {
    return this._seq;
  }
  get transcript(): readonly Step[] {
    return this.steps;
  }

  private ctx(): VerifyContext {
    return {
      networkId: this.cfg.networkId,
      moduleId: this.cfg.module.id,
      contractId: this.cfg.contractId,
      protocolVersion: this.cfg.protocolVersion,
      headHash: this._head,
      expectedSeq: this._seq,
    };
  }

  /** Accept (or DROP) one signed envelope. State/head/seq advance only on full acceptance. */
  accept(env: Envelope): AcceptResult<S> {
    const v = verifyEnvelope(env, this.ctx());
    if (!v.ok) return v;

    let step: Step;
    if (env.messageKind === 'action') {
      const body = decodeActionBody(env.bodyHex);
      if (!body.ok) return { ok: false, reason: `bad action body: ${body.reason}` };
      step = { kind: 'action', action: { type: body.value.type, party: env.seatId, ...(body.value.amount !== undefined ? { amount: body.value.amount } : {}) } };
    } else if (env.messageKind === 'randomness') {
      // REQ-SEC-002/003: the seed is DERIVED from a verified beacon round — never supplied raw.
      const round = decodeBeaconBody(env.bodyHex);
      if (!round.ok) return { ok: false, reason: `bad beacon body: ${round.reason}` };
      const r = verifyBeaconRound(round.value, this.cfg.eligible);
      if (!r.ok) return { ok: false, reason: `beacon round invalid: ${r.reason}` };
      step = { kind: 'randomness', seedHex: toHex(r.seed) };
    } else {
      return { ok: false, reason: `unsupported message kind ${env.messageKind}` };
    }

    const applied = this.cfg.module.apply(this._state, step);
    if (!applied.ok) return { ok: false, reason: `engine rejected: ${applied.reason}` };

    // commit: advance the accepted prefix
    this._state = applied.state;
    this._head = chainTranscript(this._head, env);
    this._seq += 1;
    this.steps.push(step);
    return { ok: true, state: this._state };
  }

  /** Independent re-derivation of the accepted state from the recorded steps (REQ-ARCH-001). */
  rederive(): S {
    const r = replay(this.cfg.module, this.cfg.initial, this.steps);
    if (!r.ok) throw new Error(`rederive failed at step ${r.atStep}: ${r.reason}`);
    return r.state;
  }
}
