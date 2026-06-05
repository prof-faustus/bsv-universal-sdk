// @bsv-universal/board — rich graphical board renderer (Canvas 2D). ONE drawing routine used by
// both the web client (on-screen <canvas>) and the PNG verifier (native @napi-rs/canvas), so what is
// verified is exactly what ships. Pure: (ctx, view-model) → pixels. No DOM/Node specifics.

import type { GameVM } from '@bsv-universal/practice';

export const BOARD_W = 900;
export const BOARD_H = 560;

/** Structural subset of CanvasRenderingContext2D — satisfied by both browser and @napi-rs/canvas. */
export interface Ctx {
  fillStyle: string;
  strokeStyle: string;
  lineWidth: number;
  font: string;
  textAlign: string;
  textBaseline: string;
  fillRect(x: number, y: number, w: number, h: number): void;
  beginPath(): void;
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  quadraticCurveTo(cx: number, cy: number, x: number, y: number): void;
  arc(x: number, y: number, r: number, a0: number, a1: number): void;
  closePath(): void;
  fill(): void;
  stroke(): void;
  fillText(t: string, x: number, y: number): void;
  save(): void;
  restore(): void;
}

const FELT = '#0b6b3a';
const FELT_DARK = '#075a30';
const GOLD = '#e8c14a';
const INK = '#16202a';
const CARD = '#f7f4ea';
const BACK = '#1f3a8a';

function roundRect(ctx: Ctx, x: number, y: number, w: number, h: number, r: number): void {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

function drawCard(ctx: Ctx, x: number, y: number, w: number, h: number, label: string, faceUp: boolean): void {
  roundRect(ctx, x, y, w, h, 10);
  ctx.fillStyle = faceUp ? CARD : BACK;
  ctx.fill();
  ctx.lineWidth = 2;
  ctx.strokeStyle = faceUp ? '#caa' : '#0d245e';
  ctx.stroke();
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  if (faceUp) {
    ctx.fillStyle = INK;
    ctx.font = `bold ${Math.floor(h * 0.42)}px sans-serif`;
    ctx.fillText(label, x + w / 2, y + h / 2);
    ctx.font = `bold ${Math.floor(h * 0.16)}px sans-serif`;
    ctx.textAlign = 'left';
    ctx.fillText(label, x + 8, y + 16);
  } else {
    ctx.fillStyle = GOLD;
    ctx.font = `bold ${Math.floor(h * 0.5)}px sans-serif`;
    ctx.fillText('?', x + w / 2, y + h / 2);
  }
}

function drawChips(ctx: Ctx, cx: number, cy: number, pot: string): void {
  const colors = ['#c0392b', '#2980b9', '#27ae60'];
  for (let i = 0; i < 3; i++) {
    ctx.beginPath();
    ctx.arc(cx, cy - i * 6, 22, 0, Math.PI * 2);
    ctx.fillStyle = colors[i % colors.length]!;
    ctx.fill();
    ctx.lineWidth = 3;
    ctx.strokeStyle = '#fff';
    ctx.stroke();
  }
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 20px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${pot} sat`, cx, cy - 40);
}

function drawSeat(ctx: Ctx, x: number, y: number, w: number, h: number, name: string, balance: string, acting: boolean): void {
  roundRect(ctx, x, y, w, h, 12);
  ctx.fillStyle = acting ? 'rgba(232,193,74,0.22)' : 'rgba(0,0,0,0.28)';
  ctx.fill();
  ctx.lineWidth = acting ? 4 : 1.5;
  ctx.strokeStyle = acting ? GOLD : 'rgba(255,255,255,0.35)';
  ctx.stroke();
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 16px monospace';
  ctx.fillText(name, x + w / 2, y + 22);
  ctx.font = 'bold 22px sans-serif';
  ctx.fillStyle = GOLD;
  ctx.fillText(`${balance} sat`, x + w / 2, y + h - 24);
  if (acting) {
    ctx.font = 'bold 12px sans-serif';
    ctx.fillStyle = GOLD;
    ctx.fillText('● YOUR TURN', x + w / 2, y + h / 2);
  }
}

function footerText(vm: GameVM): string {
  if (vm.complete) return 'GAME OVER — start a new game';
  if (vm.expectsDeal) return 'Deal the cards (commit → reveal) to begin the round';
  const bet = vm.legalActions.find((a) => a.type === 'BET');
  if (bet && bet.min !== undefined) return `Your move: Bet ${bet.min}-${bet.max} sat, or Pass  (silence -> ${vm.timeoutOutcome})`;
  return '';
}

/** Render the whole board for a view-model. */
export function drawBoard(ctx: Ctx, vm: GameVM, width = BOARD_W, height = BOARD_H): void {
  // felt
  ctx.fillStyle = FELT_DARK;
  ctx.fillRect(0, 0, width, height);
  roundRect(ctx, 16, 16, width - 32, height - 32, 28);
  ctx.fillStyle = FELT;
  ctx.fill();
  ctx.lineWidth = 6;
  ctx.strokeStyle = GOLD;
  ctx.stroke();

  // title + header
  ctx.fillStyle = '#fff';
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  ctx.font = 'bold 26px sans-serif';
  ctx.fillText('In-Between', 40, 56);
  ctx.font = '15px sans-serif';
  ctx.fillStyle = 'rgba(255,255,255,0.85)';
  ctx.fillText('bsv-universal-sdk · you choose every action', 40, 78);
  ctx.textAlign = 'right';
  ctx.font = 'bold 16px monospace';
  ctx.fillStyle = '#fff';
  ctx.fillText(`Round ${vm.roundNo}   Phase ${vm.phase}`, width - 40, 56);

  // centre: cards + pot
  const cy = 200;
  const cw = 90;
  const ch = 130;
  const midX = width / 2;
  if (vm.visible) {
    drawCard(ctx, midX - cw * 1.7, cy, cw, ch, vm.visible[0], true);
    drawCard(ctx, midX - cw / 2, cy, cw, ch, '?', false);
    drawCard(ctx, midX + cw * 0.7, cy, cw, ch, vm.visible[1], true);
  } else {
    drawCard(ctx, midX - cw / 2, cy, cw, ch, '?', false);
  }
  drawChips(ctx, midX, cy + ch + 60, vm.pot);
  if (vm.lastOutcome) {
    ctx.textAlign = 'center';
    ctx.fillStyle = GOLD;
    ctx.font = 'bold 16px sans-serif';
    ctx.fillText(`last: ${vm.lastOutcome}`, midX, cy - 16);
  }

  // seats along the bottom
  const n = vm.players.length;
  const gap = 16;
  const sw = Math.min(180, (width - 80 - gap * (n - 1)) / n);
  const sh = 90;
  const totalW = sw * n + gap * (n - 1);
  let sx = (width - totalW) / 2;
  const sy = height - sh - 70;
  for (const p of vm.players) {
    drawSeat(ctx, sx, sy, sw, sh, p.short, p.balance, p.acting);
    sx += sw + gap;
  }

  // footer prompt
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 17px sans-serif';
  ctx.fillText(footerText(vm), width / 2, height - 36);
}
