// @bsv-universal/engine — replay (REQ-ENG-003/004).
// Folds each transcript step through the module's pure `apply`, rejecting any non-legal successor.
// TOTAL: returns a typed result and never throws on adversarial input.

import type { ContractModule, Step } from './module.ts';

export type ReplayResult<S> =
  | { readonly ok: true; readonly state: S; readonly steps: number }
  | { readonly ok: false; readonly reason: string; readonly atStep: number };

export function replay<S>(
  module: ContractModule<S>,
  initial: S,
  steps: readonly Step[],
): ReplayResult<S> {
  let state = initial;
  for (let i = 0; i < steps.length; i++) {
    let applied;
    try {
      applied = module.apply(state, steps[i]!);
    } catch (e) {
      // A module SHOULD be total; if it throws on adversarial input we still do not (REQ-ENG-004).
      return { ok: false, reason: `apply threw at step ${i}: ${(e as Error).message}`, atStep: i };
    }
    if (!applied.ok) return { ok: false, reason: applied.reason, atStep: i };
    state = applied.state;
  }
  return { ok: true, state, steps: steps.length };
}
