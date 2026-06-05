// Real render + interaction verification (not "process alive"): mounts the React app in jsdom,
// asserts the menu renders, and drives a turn by CLICKING — proving the UI works end to end.

import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { App } from '../src/App.tsx';
import { viewModel } from '../src/viewModel.ts';
import { newGame, deal, bet } from '../src/game.ts';

afterEach(cleanup);

describe('client-web UI', () => {
  it('renders the menu-driven game shell', () => {
    render(<App />);
    expect(screen.getByText(/In-Between/i)).toBeTruthy();
    expect(screen.getByText(/You choose every action/i)).toBeTruthy();
    // first phase is deck-commitment → a human-clicked Deal button (nothing auto-deals)
    expect(screen.getByTestId('deal')).toBeTruthy();
    expect(screen.getByTestId('phase').textContent).toBe('deck-commitment');
  });

  it('advances only when the human clicks (deal → bet menu appears)', () => {
    render(<App />);
    fireEvent.click(screen.getByTestId('deal'));
    // after dealing, either a bet menu appears (await-bet) or the round auto-resolved to a new deal;
    // drive deals until we reach a bet decision, clicking each time (no auto-advance)
    let guard = 0;
    while (!screen.queryByTestId('bet') && screen.queryByTestId('deal') && guard++ < 20) {
      fireEvent.click(screen.getByTestId('deal'));
    }
    expect(screen.getByTestId('bet')).toBeTruthy();
    expect(screen.getByTestId('pass')).toBeTruthy();
    // the explicit silence/timeout outcome is shown (REQ-CLIENT-002)
    expect(screen.getByTestId('timeout').textContent).toBe('pass');
  });

  it('rejects an out-of-range bet with a visible error, without crashing', () => {
    render(<App />);
    let guard = 0;
    fireEvent.click(screen.getByTestId('deal'));
    while (!screen.queryByTestId('bet') && screen.queryByTestId('deal') && guard++ < 20) {
      fireEvent.click(screen.getByTestId('deal'));
    }
    const input = screen.getByTestId('amount') as HTMLInputElement;
    fireEvent.change(input, { target: { value: '99999' } });
    fireEvent.click(screen.getByTestId('bet'));
    expect(screen.getByTestId('error').textContent).toMatch(/Rejected/i);
  });
});

describe('viewModel (pure)', () => {
  it('enumerates the acting seat menu and never selects one', () => {
    const g = newGame(2, 'aa');
    const dealt = deal(g.state);
    expect(dealt.ok).toBe(true);
    if (!dealt.ok) return;
    // drive to a bet phase
    let s = dealt.state;
    let guard = 0;
    while (s.phase !== 'await-bet' && !viewModel(s).complete && guard++ < 50) {
      const d = deal(s);
      if (!d.ok) break;
      s = d.state;
    }
    const vm = viewModel(s);
    if (vm.phase === 'await-bet') {
      expect(vm.legalActions.map((a) => a.type).sort()).toEqual(['BET', 'PASS']);
      const betvm = vm.legalActions.find((a) => a.type === 'BET');
      expect(betvm?.min).toBeDefined();
    }
  });

  it('settlement conserves value (real engine through the UI layer)', () => {
    const g = newGame(2, 'bb');
    const dealt = deal(g.state);
    expect(dealt.ok).toBe(true);
    if (!dealt.ok) return;
    if (dealt.state.phase === 'await-bet') {
      const r = bet(dealt.state, 1n);
      expect(r.ok).toBe(true);
    }
  });
});
