// Fuzz battery (MS SDL / SANS): RelayCore is total on hostile input and never exceeds its bounds.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { RelayCore } from '../src/index.ts';

const ITER = 5000;

test('publish/history/open are total over random hostile input (never throw)', () => {
  const core = new RelayCore({ maxBodyBytes: 1024, maxLog: 100, maxChannels: 50 });
  for (let i = 0; i < ITER; i++) {
    const channel = randomBytes(randomBytes(1)[0]! % 8).toString('hex');
    const token = randomBytes(randomBytes(1)[0]! % 8).toString('hex');
    const msg = randomBytes(1)[0]! % 2 ? randomBytes(randomBytes(1)[0]! % 200).toString('hex') : randomBytes(20).toString('utf8');
    assert.doesNotThrow(() => core.open(channel, token));
    const p = core.publish(channel, token, msg);
    assert.equal(typeof p.ok, 'boolean');
    const h = core.history(channel, token, randomBytes(4).readInt32BE(0));
    assert.equal(typeof h.ok, 'boolean');
  }
});

test('bounds are never exceeded under flooding (CWE-770)', () => {
  const core = new RelayCore({ maxBodyBytes: 8, maxLog: 5, maxChannels: 3 });
  core.open('c', 't');
  let accepted = 0;
  for (let i = 0; i < 1000; i++) {
    const r = core.publish('c', 't', randomBytes(4).toString('hex')); // 4 bytes ≤ cap
    if (r.ok) accepted++;
  }
  assert.equal(accepted, 5); // never retains more than maxLog
  const h = core.history('c', 't', 0);
  assert.equal(h.ok, true);
  if (h.ok) assert.ok(h.value.items.length <= 5);
  // channel cap holds
  assert.equal(core.open('c2', 't').ok, true);
  assert.equal(core.open('c3', 't').ok, true);
  const over = core.open('c4', 't');
  assert.equal(over.ok, false);
  assert.ok(core.channelCount() <= 3);
});
