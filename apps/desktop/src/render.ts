// Text renderer for the native console client. Pure: engine state → screen string (via the shared
// view-model). Enumerates the menu; never picks an action.

import { viewModel, type GameVM } from '@bsv-universal/practice';
import type { InBetweenState } from '@bsv-universal/engine';

export function render(state: InBetweenState, message: string | null): string {
  const vm: GameVM = viewModel(state);
  const lines: string[] = [];
  lines.push('==============================================');
  lines.push(' In-Between  —  bsv-universal-sdk (native)');
  lines.push('==============================================');
  lines.push(`Round ${vm.roundNo}    Pot ${vm.pot} sat    Phase ${vm.phase}`);
  lines.push('----------------------------------------------');
  for (const p of vm.players) {
    lines.push(`${p.acting ? ' -> ' : '    '}${p.short}   ${p.balance.padStart(5)} sat`);
  }
  lines.push('----------------------------------------------');
  if (vm.visible) lines.push(`Visible cards: ${vm.visible[0]} and ${vm.visible[1]}  (does the hidden third fall between?)`);
  if (vm.lastOutcome) lines.push(`Last outcome: ${vm.lastOutcome}`);

  if (vm.complete) {
    lines.push('*** GAME OVER ***   (n = new game, q = quit)');
  } else if (vm.expectsDeal) {
    lines.push('Your move:  d = deal cards (commit -> reveal)      (q = quit, n = new)');
  } else {
    const bet = vm.legalActions.find((a) => a.type === 'BET');
    const range = bet && bet.min !== undefined ? `${bet.min}-${bet.max}` : '?';
    lines.push(`Your move, seat ${vm.actingShort}:  b <amount> = bet (${range} sat),  p = pass`);
    lines.push(`(if you do nothing, the pre-declared outcome is: ${vm.timeoutOutcome})`);
  }
  if (message) lines.push(`>> ${message}`);
  lines.push('');
  return lines.join('\n');
}
