// @bsv-universal/engine — the ContractModule contract (REQ-ENG-001..008).
//
// A module is a PURE state machine: no I/O, no clock, no RNG-without-seed. Randomness enters only
// as a verified beacon seed (REQ-SEC-002). `getLegalActions` ENUMERATES the user's choices and
// never selects/ranks/recommends-then-executes one (REQ-BAN-009 / REQ-ENG-001): selection is the
// user's alone. Every timeout/abort outcome is an explicit, pre-declared branch (REQ-ENG-008).

/** A legal action offered to the user — a menu entry, never an auto-selected move. */
export type LegalAction =
  | { readonly type: string; readonly party: string } // discrete action by a party
  | { readonly type: string; readonly party: string; readonly min: bigint; readonly max: bigint }; // ranged

/** An applied step in the transcript. Randomness steps carry a verified beacon seed, never values. */
export type Step =
  | { readonly kind: 'action'; readonly action: ModuleAction }
  | { readonly kind: 'randomness'; readonly seedHex: string } // seed from a verified beacon round
  | { readonly kind: 'timeout'; readonly branch: string }; // an explicit pre-declared default branch

export interface ModuleAction {
  readonly type: string;
  readonly party: string; // 33B partyId hex — the actor; must match the signer (REQ-SEC-001)
  readonly amount?: bigint;
}

/** A typed rejection — `apply`/`replay` are TOTAL and never throw on adversarial input (REQ-ENG-004). */
export type Applied<S> = { readonly ok: true; readonly state: S } | { readonly ok: false; readonly reason: string };

export interface ContractModule<S> {
  readonly id: string;
  /** Pure transition. Total: returns next state or a typed rejection; never throws. */
  apply(state: S, step: Step): Applied<S>;
  /** Enumerated legal actions for the to-move party (and empty for others). Never selects one. */
  getLegalActions(state: S): readonly LegalAction[];
  /** Whether a beacon/randomness step is the expected next step in this phase. */
  expectsRandomness(state: S): boolean;
  /** The single pre-declared default branch if the to-move party is silent (REQ-ENG-008). */
  timeoutBranch(state: S): string | null;
  isComplete(state: S): boolean;
  /** Pure settlement; total value conserved against the locked pot (REQ-ENG-006). */
  settle(state: S): { readonly balances: Readonly<Record<string, string>>; readonly conserved: boolean };
}
