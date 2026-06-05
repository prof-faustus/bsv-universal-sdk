// Rich graphical board: draws the shared canvas board into an on-screen <canvas>. Same drawBoard()
// routine that the PNG verifier uses, so the visual is verified pixel-for-pixel elsewhere.

import { useEffect, useRef } from 'react';
import { drawBoard, BOARD_W, BOARD_H, type Ctx } from '@bsv-universal/board';
import { viewModel } from '@bsv-universal/practice';
import type { InBetweenState } from '@bsv-universal/engine';

export function BoardCanvas({ state }: { state: InBetweenState }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return; // headless/jsdom returns null — the DOM controls remain the accessible fallback
    // browser context is structurally a superset of Ctx (broader fillStyle union) — adapt at this boundary.
    drawBoard(ctx as unknown as Ctx, viewModel(state), BOARD_W, BOARD_H);
  }, [state]);
  return (
    <canvas
      ref={ref}
      width={BOARD_W}
      height={BOARD_H}
      data-testid="board"
      style={{ width: '100%', height: 'auto', borderRadius: 12, display: 'block' }}
    />
  );
}
