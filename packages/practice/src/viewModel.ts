// Pure view-model: maps engine state → exactly what a client shows. UI-framework-free, so it is unit-
// testable and shared by the web and native clients. Enumerates legal actions only — never selects
// one (REQ-CLIENT-001 / REQ-BAN-009).

import { inBetweenModule as M, type InBetweenState } from '@bsv-universal/engine';

export interface ActionVM {
  readonly type: string;
  readonly min?: string;
  readonly max?: string;
}
export interface PlayerVM {
  readonly id: string;
  readonly short: string;
  readonly balance: string;
  readonly acting: boolean;
}
export interface GameVM {
  readonly phase: InBetweenState['phase'];
  readonly roundNo: number;
  readonly pot: string;
  readonly complete: boolean;
  readonly players: readonly PlayerVM[];
  readonly actingShort: string | null;
  readonly visible: readonly [string, string] | null;
  readonly legalActions: readonly ActionVM[];
  readonly expectsDeal: boolean;
  readonly timeoutOutcome: string | null;
  readonly lastOutcome: string | null;
}

const RANKS = ['', 'A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
export function rankName(r: number): string {
  return RANKS[r] ?? String(r);
}
function short(id: string): string {
  return id.length >= 8 ? `${id.slice(0, 8)}…` : id;
}

export function viewModel(state: InBetweenState): GameVM {
  const acting = state.parties[state.actingIdx];
  const players: PlayerVM[] = state.parties.map((id) => {
    const entry = state.balances.find(([p]) => p === id);
    return { id, short: short(id), balance: (entry ? entry[1] : 0n).toString(), acting: id === acting };
  });
  const legalActions: ActionVM[] = M.getLegalActions(state).map((a) =>
    'min' in a ? { type: a.type, min: a.min.toString(), max: a.max.toString() } : { type: a.type },
  );
  const tb = M.timeoutBranch(state);
  return {
    phase: state.phase,
    roundNo: state.roundNo,
    pot: state.pot.toString(),
    complete: M.isComplete(state),
    players,
    actingShort: acting ? short(acting) : null,
    visible: state.visible ? [rankName(state.visible[0]), rankName(state.visible[1])] : null,
    legalActions,
    expectsDeal: M.expectsRandomness(state),
    timeoutOutcome: tb,
    lastOutcome: state.lastOutcome,
  };
}
