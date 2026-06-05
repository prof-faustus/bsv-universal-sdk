// @bsv-universal/net — OrderedSubscriber (REQ-SEC-004).
//
// The relay's append order is the single total order. This subscriber maintains a local accepted
// length and, on every pump (triggered by an SSE poke or a poll), reads the authoritative history
// FORWARD from that length and delivers each item in order. It never inserts a newly-discovered
// item behind an already-delivered one — a dropped poke only delays delivery, it cannot reorder.
// Two honest subscribers therefore converge to byte-identical delivery regardless of poke timing.

export interface HistorySource {
  /** The authoritative ordered prefix from `from` (paged). Sync or async. */
  history(from: number): Promise<{ items: readonly string[]; total: number }> | { items: readonly string[]; total: number };
}

export type OnMessage = (messageHex: string, seq: number) => void;

export class OrderedSubscriber {
  private len = 0;
  private pumping = false;
  private readonly source: HistorySource;
  private readonly onMessage: OnMessage;

  constructor(source: HistorySource, onMessage: OnMessage) {
    this.source = source;
    this.onMessage = onMessage;
  }

  /** Current accepted prefix length (number of delivered messages). */
  get delivered(): number {
    return this.len;
  }

  /**
   * Drain all available history in order. Re-entrant-safe: concurrent pumps coalesce. Pages until
   * caught up to `total`. Returns the number of messages delivered this call.
   */
  async pump(): Promise<number> {
    if (this.pumping) return 0; // coalesce — a later poke will pick up anything new
    this.pumping = true;
    let delivered = 0;
    try {
      // NASA P10 #2: bounded loop. Each iteration advances `len` by ≥1 (or breaks), so the loop
      // terminates in at most MAX_PAGES iterations; the cap is a fail-closed backstop against a
      // hostile/buggy source that never reports being caught up.
      const MAX_PAGES = 10_000_000;
      for (let page = 0; page < MAX_PAGES; page++) {
        const got = await this.source.history(this.len);
        if (!got || !Array.isArray(got.items) || typeof got.total !== 'number') break; // hostile source → stop safely
        if (got.items.length === 0) break; // caught up (or a misbehaving source) — never spin
        const before = this.len;
        for (const item of got.items) {
          this.onMessage(item, this.len);
          this.len += 1;
          delivered += 1;
        }
        if (this.len === before) break; // no forward progress — fail-closed
        if (this.len >= got.total) break;
      }
    } finally {
      this.pumping = false;
    }
    return delivered;
  }
}

/** Adapt a RelayCore-like object (with a token-scoped channel) into a HistorySource. */
export interface ChannelHistory {
  history(channel: string, token: string, from: number): { ok: true; value: { items: readonly string[]; total: number } } | { ok: false; status: number; reason: string };
}

export function channelSource(core: ChannelHistory, channel: string, token: string): HistorySource {
  return {
    history(from: number) {
      const r = core.history(channel, token, from);
      if (!r.ok) throw new Error(`history failed: ${r.status} ${r.reason}`);
      return { items: r.value.items, total: r.value.total };
    },
  };
}
