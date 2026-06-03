// @bsv-universal/relay — RelayCore: hostile-by-default fan-out (REQ-SEC-004 / REQ-SEC-005).
//
// The relay is treated as hostile EVEN on localhost. It never interprets messages (canonical truth
// is the ordered replay through the engine, REQ-ARCH-001/003). Its only guarantees are:
//   - a SINGLE total order per channel = the server's append order (REQ-SEC-004). /history returns
//     the ordered prefix; clients re-read it and never reorder. There is no "insert behind seen".
//   - bounded memory + capability-gated access (REQ-SEC-005): max body, per-channel log cap, max
//     channels, capability token per channel, bounded history pagination.
//
// HTTP status codes mirror ESTATES: 413 (oversize body), 503 (a cap is reached), 401 (bad/absent
// capability), 404 (no such channel).

export interface RelayLimits {
  readonly maxBodyBytes: number; // per published message
  readonly maxLog: number; // messages retained per channel
  readonly maxChannels: number; // distinct channels
  readonly historyPageLimit: number; // max items returned by one history call
}

export const DEFAULT_LIMITS: RelayLimits = {
  maxBodyBytes: 256 * 1024,
  maxLog: 200_000,
  maxChannels: 10_000,
  historyPageLimit: 1_000,
};

export type RelayResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly status: number; readonly reason: string };

interface Channel {
  readonly token: string;
  readonly log: string[]; // message hex, in authoritative append order
}

const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

export class RelayCore {
  private readonly channels = new Map<string, Channel>();
  private readonly limits: RelayLimits;

  constructor(limits: Partial<RelayLimits> = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
  }

  /** Open a channel with a capability token (first caller sets it). Idempotent for the same token. */
  open(channel: string, token: string): RelayResult<{ created: boolean }> {
    if (!channel || !token) return { ok: false, status: 400, reason: 'channel and token required' };
    const existing = this.channels.get(channel);
    if (existing) {
      if (existing.token !== token) return { ok: false, status: 401, reason: 'capability token mismatch' };
      return { ok: true, value: { created: false } };
    }
    if (this.channels.size >= this.limits.maxChannels) return { ok: false, status: 503, reason: 'max channels reached' };
    this.channels.set(channel, { token, log: [] });
    return { ok: true, value: { created: true } };
  }

  private auth(channel: string, token: string): RelayResult<Channel> {
    const c = this.channels.get(channel);
    if (!c) return { ok: false, status: 404, reason: 'no such channel' };
    if (c.token !== token) return { ok: false, status: 401, reason: 'capability token mismatch' };
    return { ok: true, value: c };
  }

  /** Append one message (REQ-SEC-005 bounds enforced). Returns the assigned sequence number. */
  publish(channel: string, token: string, messageHex: string): RelayResult<{ seq: number }> {
    const a = this.auth(channel, token);
    if (!a.ok) return a;
    if (typeof messageHex !== 'string' || !HEX_RE.test(messageHex)) {
      return { ok: false, status: 400, reason: 'message must be even-length hex' };
    }
    if (Buffer.byteLength(messageHex, 'utf8') / 2 > this.limits.maxBodyBytes) {
      return { ok: false, status: 413, reason: 'message exceeds max body size' };
    }
    if (a.value.log.length >= this.limits.maxLog) {
      return { ok: false, status: 503, reason: 'channel log is full' };
    }
    a.value.log.push(messageHex);
    return { ok: true, value: { seq: a.value.log.length - 1 } };
  }

  /**
   * The authoritative ordered prefix from `from` (REQ-SEC-004). Bounded by historyPageLimit; the
   * caller pages by advancing `from`. `total` lets the caller know if more remains.
   */
  history(channel: string, token: string, from: number): RelayResult<{ items: readonly string[]; from: number; total: number }> {
    const a = this.auth(channel, token);
    if (!a.ok) return a;
    const start = Number.isInteger(from) && from > 0 ? from : 0;
    const items = a.value.log.slice(start, start + this.limits.historyPageLimit);
    return { ok: true, value: { items, from: start, total: a.value.log.length } };
  }

  channelCount(): number {
    return this.channels.size;
  }
}
