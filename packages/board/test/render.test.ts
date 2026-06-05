// Renders the rich board for real game states to PNG via native canvas, asserts non-trivial output,
// and writes previews to dist/ for visual inspection (what is verified is what ships in the browser).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCanvas } from '@napi-rs/canvas';
import { newGame, deal, pass, viewModel, type GameVM } from '@bsv-universal/practice';
import { drawBoard, BOARD_W, BOARD_H, type Ctx } from '../src/index.ts';

const distDir = fileURLToPath(new URL('../dist/', import.meta.url));
mkdirSync(distDir, { recursive: true });

function png(vm: GameVM): Buffer {
  const canvas = createCanvas(BOARD_W, BOARD_H);
  const ctx = canvas.getContext('2d');
  // native context is structurally a superset of Ctx (broader fillStyle union) — adapt at this boundary.
  drawBoard(ctx as unknown as Ctx, vm);
  return canvas.toBuffer('image/png');
}

function driveTo(predicate: (s: { phase: string }) => boolean, max = 80) {
  let s = newGame(2, 'cafe').state;
  let guard = 0;
  while (!predicate(s) && guard++ < max) {
    const next = viewModel(s).expectsDeal ? deal(s) : pass(s);
    if (!next.ok) break;
    s = next.state;
  }
  return s;
}

test('renders the deal (deck-commitment) board to a valid PNG', () => {
  const s = newGame(2, 'cafe').state;
  const buf = png(viewModel(s));
  assert.ok(buf.length > 2000, `png too small: ${buf.length}`);
  assert.equal(buf.subarray(1, 4).toString('latin1'), 'PNG'); // PNG signature
  writeFileSync(distDir + 'board-deal.png', buf);
});

test('renders the await-bet board (cards + pot + acting seat) to PNG', () => {
  const s = driveTo((x) => x.phase === 'await-bet');
  assert.equal(s.phase, 'await-bet');
  const buf = png(viewModel(s));
  assert.ok(buf.length > 3000);
  writeFileSync(distDir + 'board-bet.png', buf);
});

test('renders the game-over board to PNG', () => {
  const s = driveTo((x) => x.phase === 'complete');
  assert.equal(s.phase, 'complete');
  const buf = png(viewModel(s));
  assert.ok(buf.length > 2000);
  writeFileSync(distDir + 'board-over.png', buf);
});
