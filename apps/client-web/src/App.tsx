// Menu-driven in-between client (REQ-CLIENT-001/002 / REQ-BAN-009). Every action is a button the
// HUMAN clicks; nothing auto-plays or auto-advances; the silence/timeout outcome is shown explicitly.

import { useState } from 'react';
import { type InBetweenState } from '@bsv-universal/engine';
import { newGame, deal, bet, pass } from './game.ts';
import { viewModel } from './viewModel.ts';

export function App() {
  const [state, setState] = useState<InBetweenState>(() => newGame(2).state);
  const [error, setError] = useState<string | null>(null);
  const [amount, setAmount] = useState<string>('');

  const vm = viewModel(state);
  const betAction = vm.legalActions.find((a) => a.type === 'BET');

  function run(outcome: { ok: true; state: InBetweenState } | { ok: false; reason: string }): void {
    if (outcome.ok) {
      setState(outcome.state);
      setError(null);
    } else {
      setError(outcome.reason);
    }
  }

  function onBet(): void {
    if (!betAction || betAction.min === undefined) return;
    if (!/^\d{1,18}$/.test(amount)) {
      setError('enter a whole number of satoshis');
      return;
    }
    run(bet(state, BigInt(amount)));
    setAmount('');
  }

  return (
    <main className="app">
      <h1>In-Between — local practice</h1>
      <p className="sub">Universal BSV game engine. You choose every action; nothing plays itself.</p>

      <section className="status" aria-label="game status">
        <div>Round <b>{vm.roundNo}</b></div>
        <div>Phase <b data-testid="phase">{vm.phase}</b></div>
        <div>Pot <b data-testid="pot">{vm.pot}</b> sat</div>
      </section>

      <table className="seats">
        <thead>
          <tr><th>Seat</th><th>Balance (sat)</th><th>Turn</th></tr>
        </thead>
        <tbody>
          {vm.players.map((p) => (
            <tr key={p.id} className={p.acting ? 'acting' : ''}>
              <td>{p.short}</td>
              <td>{p.balance}</td>
              <td>{p.acting ? '→' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {vm.visible && (
        <p className="cards">Visible cards: <b>{vm.visible[0]}</b> and <b>{vm.visible[1]}</b> — bet whether the hidden third falls between them.</p>
      )}
      {vm.lastOutcome && <p className="outcome">Last: <b>{vm.lastOutcome}</b></p>}

      <section className="actions" aria-label="your actions">
        {vm.complete && <p data-testid="complete">Game over.</p>}

        {!vm.complete && vm.expectsDeal && (
          <button data-testid="deal" onClick={() => run(deal(state))}>
            Deal cards (commit → reveal)
          </button>
        )}

        {!vm.complete && betAction && betAction.min !== undefined && (
          <div className="bet">
            <p>
              Your move, seat <b>{vm.actingShort}</b>. If you do nothing, the pre-declared outcome is{' '}
              <b data-testid="timeout">{vm.timeoutOutcome}</b>.
            </p>
            <label>
              Bet ({betAction.min}–{betAction.max} sat):{' '}
              <input
                data-testid="amount"
                inputMode="numeric"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder={betAction.max}
              />
            </label>
            <button data-testid="bet" onClick={onBet}>Bet</button>
            <button data-testid="pass" onClick={() => run(pass(state))}>Pass</button>
          </div>
        )}
      </section>

      {error && <p className="error" data-testid="error" role="alert">Rejected: {error}</p>}

      <button className="reset" data-testid="reset" onClick={() => { setState(newGame(2).state); setError(null); }}>
        New game
      </button>
    </main>
  );
}
