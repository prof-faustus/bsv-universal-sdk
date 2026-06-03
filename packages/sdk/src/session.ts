// @bsv-universal/sdk — Session: the authenticated, ordered reduction of envelopes onto an engine.
//
// Ties together REQ-SEC-001 (every step from a verified signed envelope, sequence- and hash-chained),
// REQ-SEC-002/003 (randomness steps MUST carry a beacon round that verifies; the seed is DERIVED,
// never supplied), and REQ-SEC-004 (head/sequence advance ONLY on a fully accepted step, so the
// accepted prefix is a single total order). A rejected envelope is DROPPED — state does not move.

import { fromHex, toHex, utf8, canonicalStringify, type Canonical } from '@bsv-universal/protocol-types';
import { verifyBeaconRound, type BeaconRound, type PartyCommit, type PartyReveal } from '@bsv-universal/crypto';
import { replay, type ContractModule, type Step } from '@bsv-universal/engine';
import { verifyEnvelope, chainTranscript, type Envelope, type EnvelopeFields, type VerifyContext } from './envelope.ts';

export const GENESIS_HEAD = toHex(new Uint8Array(32));

// ---- body codecs (strict) -------------------------------------------------------------------
export function encodeActionBody(a: { type: string; amount?: bigint }): string {
  const obj: Canonical = a.amount === undefined ? { type: a.type } : { type: a.type, amount: a.amount.toString() };
  return toHex(utf8(canonicalStringify(obj)));
}
function decodeActionBody(bodyHex: string): { type: string; amount?: bigint } {
  const obj = JSON.parse(new TextDecoder().decode(fromHex(bodyHex))) as { type?: unknown; amount?: unknown };
  if (typeof obj.type !== 'string') throw new Error('action body missing type');
  if (obj.amount === undefined) return { type: obj.type };
  if (typeof obj.amount !== 'string' || !/^-?\d+$/.test(obj.amount)) throw new Error('action body amount must be an integer string');
  return { type: obj.type, amount: BigInt(obj.amount) };
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
function decodeBeaconBody(bodyHex: string): BeaconRound {
  const o = JSON.parse(new TextDecoder().decode(fromHex(bodyHex))) as Record<string, unknown>;
  const commits = (o.commits as { party: string; commitment: string }[]).map<PartyCommit>((c) => ({
    party: fromHex(c.party),
    commitment: fromHex(c.commitment),
  }));
  const reveals = (o.reveals as { party: string; secret: string }[]).map<PartyReveal>((r) => ({
    party: fromHex(r.party),
    secret: fromHex(r.secret),
  }));
  return { roundNo: Number(o.roundNo), prevBeacon: fromHex(o.prevBeacon as string), commits, reveals };
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
    try {
      if (env.messageKind === 'action') {
        const body = decodeActionBody(env.bodyHex);
        step = { kind: 'action', action: { type: body.type, party: env.seatId, ...(body.amount !== undefined ? { amount: body.amount } : {}) } };
      } else if (env.messageKind === 'randomness') {
        // REQ-SEC-002/003: the seed is DERIVED from a verified beacon round — never supplied raw.
        const round = decodeBeaconBody(env.bodyHex);
        const r = verifyBeaconRound(round, this.cfg.eligible);
        if (!r.ok) return { ok: false, reason: `beacon round invalid: ${r.reason}` };
        step = { kind: 'randomness', seedHex: toHex(r.seed) };
      } else {
        return { ok: false, reason: `unsupported message kind ${env.messageKind}` };
      }
    } catch (e) {
      return { ok: false, reason: `bad body: ${(e as Error).message}` };
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
