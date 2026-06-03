import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHttpRelay } from '../src/http.ts';
import type { AddressInfo } from 'node:net';

const M = (s: string) => Buffer.from(s, 'utf8').toString('hex');

async function withServer(opts: Parameters<typeof createHttpRelay>[0], fn: (base: string) => Promise<void>) {
  const { server } = createHttpRelay(opts);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

test('HTTP relay: open → publish → history round-trip over a real socket', async () => {
  await withServer({}, async (base) => {
    const hdr = { 'content-type': 'application/json', 'x-cap-token': 'cap' };
    let res = await fetch(`${base}/open/ch`, { method: 'POST', headers: hdr });
    assert.equal(res.status, 200);
    res = await fetch(`${base}/publish/ch`, { method: 'POST', headers: hdr, body: M('hello') });
    assert.equal(res.status, 200);
    res = await fetch(`${base}/publish/ch`, { method: 'POST', headers: hdr, body: M('world') });
    assert.equal(res.status, 200);
    res = await fetch(`${base}/history/ch?from=0`, { headers: hdr });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { items: string[]; total: number };
    assert.deepEqual(body.items, [M('hello'), M('world')]);
    assert.equal(body.total, 2);
  });
});

test('HTTP relay: oversize body rejected with 413; wrong token 401', async () => {
  await withServer({ limits: { maxBodyBytes: 4 } }, async (base) => {
    const hdr = { 'content-type': 'application/json', 'x-cap-token': 'cap' };
    await fetch(`${base}/open/ch`, { method: 'POST', headers: hdr });
    const big = await fetch(`${base}/publish/ch`, { method: 'POST', headers: hdr, body: M('toolong') });
    assert.equal(big.status, 413);
    const wrong = await fetch(`${base}/history/ch?from=0`, { headers: { 'x-cap-token': 'nope' } });
    assert.equal(wrong.status, 401);
  });
});
