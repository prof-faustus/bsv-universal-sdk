// @bsv-universal/relay/server — a thin node:http wrapper over RelayCore.
//
// Hostile-by-default (REQ-SEC-005): bodies are size-capped at read time (not just after buffering),
// CORS is restricted (no `*`-with-all-headers in a shipped config), and every route requires the
// channel capability token. The wrapper adds no trust: it only marshals RelayCore results to HTTP.

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { RelayCore, DEFAULT_LIMITS, type RelayLimits } from './core.ts';

export interface HttpRelayOptions {
  readonly limits?: Partial<RelayLimits>;
  readonly allowedOrigin?: string; // explicit origin; defaults to 'null' (no wildcard)
}

function cors(origin: string): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST',
    'Access-Control-Allow-Headers': 'content-type,x-cap-token',
    'Content-Type': 'application/json',
  };
}

async function readBodyCapped(req: IncomingMessage, maxBytes: number): Promise<{ ok: true; text: string } | { ok: false }> {
  return await new Promise((resolve) => {
    let size = 0;
    const chunks: Buffer[] = [];
    let aborted = false;
    req.on('data', (c: Buffer) => {
      if (aborted) return;
      size += c.length;
      if (size > maxBytes) {
        // REQ-SEC-005: reject oversize at read time — stop buffering. Pause (don't destroy yet) so
        // the 413 response can be delivered; the caller destroys the request after responding.
        aborted = true;
        req.pause();
        resolve({ ok: false });
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!aborted) resolve({ ok: true, text: Buffer.concat(chunks).toString('utf8') });
    });
    req.on('error', () => {
      if (!aborted) resolve({ ok: false });
    });
  });
}

/** Create an HTTP relay server backed by a fresh RelayCore. */
export function createHttpRelay(opts: HttpRelayOptions = {}): { server: Server; core: RelayCore } {
  const core = new RelayCore(opts.limits ?? {});
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
  const origin = opts.allowedOrigin ?? 'null';
  const H = cors(origin);

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500, H);
      res.end(JSON.stringify({ reason: 'internal' }));
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, H);
      res.end();
      return;
    }
    const url = new URL(req.url ?? '/', 'http://relay');
    const token = req.headers['x-cap-token'];
    const tok = typeof token === 'string' ? token : '';
    const parts = url.pathname.split('/').filter(Boolean); // [verb, channel]
    const [verb, channel] = parts;

    if (req.method === 'POST' && verb === 'open' && channel) {
      const r = core.open(channel, tok);
      res.writeHead(r.ok ? 200 : r.status, H);
      res.end(JSON.stringify(r.ok ? r.value : { reason: r.reason }));
      return;
    }
    if (req.method === 'POST' && verb === 'publish' && channel) {
      const body = await readBodyCapped(req, limits.maxBodyBytes);
      if (!body.ok) {
        if (!res.headersSent) res.writeHead(413, H);
        res.end(JSON.stringify({ reason: 'message exceeds max body size' }));
        req.destroy(); // free the connection AFTER the 413 is queued (bounds memory under attack)
        return;
      }
      const r = core.publish(channel, tok, body.text.trim());
      res.writeHead(r.ok ? 200 : r.status, H);
      res.end(JSON.stringify(r.ok ? r.value : { reason: r.reason }));
      return;
    }
    if (req.method === 'GET' && verb === 'history' && channel) {
      const from = Number(url.searchParams.get('from') ?? '0');
      const r = core.history(channel, tok, from);
      res.writeHead(r.ok ? 200 : r.status, H);
      res.end(JSON.stringify(r.ok ? r.value : { reason: r.reason }));
      return;
    }
    res.writeHead(404, H);
    res.end(JSON.stringify({ reason: 'not found' }));
  }

  return { server, core };
}
