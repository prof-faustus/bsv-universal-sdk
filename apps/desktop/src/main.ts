// Native console client for In-Between — the entry bundled into a single Windows .exe (Node SEA).
// Runs the REAL engine + crypto (no re-implementation, no divergence). Double-click → it renders the
// game and a human plays by typing. Menu-driven; nothing auto-plays (REQ-BAN-009 / REQ-CLIENT-001).

import { createInterface } from 'node:readline';
import { newGame, deal, bet, pass, type ApplyOutcome } from '@bsv-universal/practice';
import type { InBetweenState } from '@bsv-universal/engine';
import { render } from './render.ts';

let state: InBetweenState = newGame(2).state;

function show(message: string | null): void {
  process.stdout.write(render(state, message) + '\n');
}

function applyOutcome(o: ApplyOutcome): string | null {
  if (o.ok) {
    state = o.state;
    return null;
  }
  return `Rejected: ${o.reason}`;
}

function handle(raw: string): void {
  const line = raw.trim().toLowerCase();
  if (line === '') {
    show(null);
    return;
  }
  if (line === 'q' || line === 'quit') {
    process.stdout.write('Bye.\n');
    rl.close();
    return;
  }
  if (line === 'n' || line === 'new') {
    state = newGame(2).state;
    show('new game');
    return;
  }
  if (line === 'd' || line === 'deal') {
    show(applyOutcome(deal(state)));
    return;
  }
  if (line === 'p' || line === 'pass') {
    show(applyOutcome(pass(state)));
    return;
  }
  if (line === 'b' || line.startsWith('b ') || /^b\d+$/.test(line)) {
    const numStr = line.replace(/^b\s*/, '');
    if (!/^\d{1,18}$/.test(numStr)) {
      show('usage: b <whole-number-of-satoshis>');
      return;
    }
    show(applyOutcome(bet(state, BigInt(numStr))));
    return;
  }
  show(`unknown command "${line}" — use d, b <amt>, p, n, q`);
}

const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
process.stdout.write('Welcome to In-Between (native). Type commands and press Enter.\n\n');
show(null);
rl.on('line', handle);
rl.on('close', () => process.exit(0));
