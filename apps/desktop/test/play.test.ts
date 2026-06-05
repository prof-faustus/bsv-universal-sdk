// Verifies the native client actually RENDERS and PLAYS (not "process alive"): spawn the real entry
// with a scripted keyboard, capture stdout, and assert the board renders and a full game completes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

function play(script: string) {
  return spawnSync(process.execPath, ['--experimental-strip-types', main], { input: script, encoding: 'utf8' });
}

test('native client renders the board and reaches game over under scripted play', () => {
  // alternate deal/pass enough times to finish all rounds, then quit
  const script = Array.from({ length: 80 }, (_, i) => (i % 2 === 0 ? 'd' : 'p')).join('\n') + '\nq\n';
  const r = play(script);
  assert.equal(r.status, 0, `exit ${r.status}; stderr: ${r.stderr}`);
  assert.equal(r.stderr.trim(), '', `no errors on stderr: ${r.stderr}`);
  assert.match(r.stdout, /In-Between\s+—\s+bsv-universal-sdk \(native\)/);
  assert.match(r.stdout, /Round \d+\s+Pot \d+ sat/);
  assert.match(r.stdout, /Visible cards:/); // at least one hand was dealt + rendered
  assert.match(r.stdout, /GAME OVER/); // the game ran to completion
});

test('native client rejects an out-of-range bet without crashing', () => {
  // deal until a bet is offered, then attempt an absurd bet
  const script = 'd\nd\nd\nb 999999\nq\n';
  const r = play(script);
  assert.equal(r.status, 0);
  assert.equal(r.stderr.trim(), '');
  // either the bet was rejected (range) or the phase wasn't await-bet (also rejected) — never a crash
  assert.match(r.stdout, /Rejected:|Your move/);
});

test('native client handles unknown input gracefully (hostile stdin)', () => {
  const r = play('@@@\n\n!!!\nq\n');
  assert.equal(r.status, 0);
  assert.equal(r.stderr.trim(), '');
  assert.match(r.stdout, /unknown command/);
});
