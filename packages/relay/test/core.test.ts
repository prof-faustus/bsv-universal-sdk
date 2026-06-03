import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RelayCore } from '../src/index.ts';

const M = (s: string) => Buffer.from(s, 'utf8').toString('hex');

test('open is capability-gated and idempotent for the same token', () => {
  const r = new RelayCore();
  assert.equal(r.open('ch', 'tok').ok, true);
  const again = r.open('ch', 'tok');
  assert.equal(again.ok, true);
  const wrong = r.open('ch', 'other');
  assert.equal(wrong.ok, false);
  if (!wrong.ok) assert.equal(wrong.status, 401);
});

test('REQ-SEC-005: oversize message rejected with 413', () => {
  const r = new RelayCore({ maxBodyBytes: 4 });
  r.open('ch', 't');
  const ok = r.publish('ch', 't', M('abcd')); // 4 bytes
  assert.equal(ok.ok, true);
  const big = r.publish('ch', 't', M('abcde')); // 5 bytes
  assert.equal(big.ok, false);
  if (!big.ok) assert.equal(big.status, 413);
});

test('REQ-SEC-005: per-channel log cap rejected with 503', () => {
  const r = new RelayCore({ maxLog: 2 });
  r.open('ch', 't');
  assert.equal(r.publish('ch', 't', M('a')).ok, true);
  assert.equal(r.publish('ch', 't', M('b')).ok, true);
  const over = r.publish('ch', 't', M('c'));
  assert.equal(over.ok, false);
  if (!over.ok) assert.equal(over.status, 503);
});

test('REQ-SEC-005: max channels rejected with 503', () => {
  const r = new RelayCore({ maxChannels: 1 });
  assert.equal(r.open('a', 't').ok, true);
  const over = r.open('b', 't');
  assert.equal(over.ok, false);
  if (!over.ok) assert.equal(over.status, 503);
});

test('REQ-SEC-005: wrong token (401) and missing channel (404)', () => {
  const r = new RelayCore();
  r.open('ch', 'good');
  const bad = r.publish('ch', 'bad', M('x'));
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.equal(bad.status, 401);
  const missing = r.history('nope', 'good', 0);
  assert.equal(missing.ok, false);
  if (!missing.ok) assert.equal(missing.status, 404);
});

test('REQ-SEC-005: non-hex message rejected', () => {
  const r = new RelayCore();
  r.open('ch', 't');
  const bad = r.publish('ch', 't', 'zzzz');
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.equal(bad.status, 400);
});

test('REQ-SEC-004: /history returns the authoritative append order; paging by `from`', () => {
  const r = new RelayCore();
  r.open('ch', 't');
  r.publish('ch', 't', M('a'));
  r.publish('ch', 't', M('b'));
  r.publish('ch', 't', M('c'));
  const all = r.history('ch', 't', 0);
  assert.equal(all.ok, true);
  if (all.ok) {
    assert.deepEqual([...all.value.items], [M('a'), M('b'), M('c')]);
    assert.equal(all.value.total, 3);
  }
  const tail = r.history('ch', 't', 2);
  assert.equal(tail.ok, true);
  if (tail.ok) assert.deepEqual([...tail.value.items], [M('c')]);
});

test('REQ-SEC-004: history pagination is bounded by historyPageLimit', () => {
  const r = new RelayCore({ historyPageLimit: 2 });
  r.open('ch', 't');
  for (const s of ['a', 'b', 'c', 'd', 'e']) r.publish('ch', 't', M(s));
  const page = r.history('ch', 't', 0);
  assert.equal(page.ok, true);
  if (page.ok) {
    assert.equal(page.value.items.length, 2); // bounded
    assert.equal(page.value.total, 5); // but caller learns more remains
  }
});
