import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RelayCore } from '@bsv-universal/relay';
import { OrderedSubscriber, channelSource } from '../src/index.ts';

const M = (s: string) => Buffer.from(s, 'utf8').toString('hex');

test('REQ-SEC-004: delivers in append order; a missed poke only delays, never reorders', async () => {
  const core = new RelayCore();
  core.open('ch', 't');
  const got: string[] = [];
  const sub = new OrderedSubscriber(channelSource(core, 'ch', 't'), (hex) => got.push(hex));

  core.publish('ch', 't', M('a'));
  core.publish('ch', 't', M('b'));
  await sub.pump(); // poke 1 — delivers a,b
  assert.deepEqual(got, [M('a'), M('b')]);

  // three messages arrive but the poke for the middle one is "dropped" (we just don't pump yet)
  core.publish('ch', 't', M('c'));
  core.publish('ch', 't', M('d'));
  core.publish('ch', 't', M('e'));
  await sub.pump(); // a single later poke catches up the whole prefix, in order
  assert.deepEqual(got, [M('a'), M('b'), M('c'), M('d'), M('e')]);
  assert.equal(sub.delivered, 5);
});

test('REQ-SEC-004: two subscribers converge to identical ordered delivery', async () => {
  const core = new RelayCore();
  core.open('ch', 't');
  const a: string[] = [];
  const b: string[] = [];
  const subA = new OrderedSubscriber(channelSource(core, 'ch', 't'), (h) => a.push(h));
  const subB = new OrderedSubscriber(channelSource(core, 'ch', 't'), (h) => b.push(h));

  for (const s of ['m0', 'm1', 'm2', 'm3']) core.publish('ch', 't', M(s));
  // A pumps eagerly twice, B pumps once at the end — different timing, same result
  await subA.pump();
  core.publish('ch', 't', M('m4'));
  await subA.pump();
  await subB.pump();
  assert.deepEqual(a, b);
  assert.deepEqual(a, ['m0', 'm1', 'm2', 'm3', 'm4'].map(M));
});

test('paged history is drained fully by pump (bounded pages, complete delivery)', async () => {
  const core = new RelayCore({ historyPageLimit: 2 });
  core.open('ch', 't');
  for (let i = 0; i < 7; i++) core.publish('ch', 't', M(`x${i}`));
  const got: string[] = [];
  const sub = new OrderedSubscriber(channelSource(core, 'ch', 't'), (h) => got.push(h));
  await sub.pump();
  assert.equal(got.length, 7);
  assert.deepEqual(got, Array.from({ length: 7 }, (_, i) => M(`x${i}`)));
});
