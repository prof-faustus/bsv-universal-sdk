# Module Spec — `in-between` (reference game)

**Status:** GROUNDED. This is the only game module specifiable from a verified source (`formal-architecture-v1.docx`). It is the reference instantiation of `ContractModule` and the regression anchor for the engine.

**Why this and not poker as the grounded reference:** the brief names poker as the reference game, but In-Between is used as the engine regression anchor because it is **open-information** — its correctness does not rest on the TEE, threshold-ECDSA, or in-script-EC dependencies that poker's private hands carry. The poker source (`bsvpoker_dlt_*`) has now been read and `poker-spec.md` is conformed (`SOURCE-CONFORMANCE.md` §8); In-Between remains the anchor so the engine has at least one module exercisable without those open per-module decisions. Recorded in `BUILD-STATUS.md`.

## 1. Game
In-Between (Acey-Deucey / Between the Sheets). Chosen in the verified architecture for its shallow state tree and single decisive betting action per round, while still exercising pot formation, deck commitment, card reveal, betting, timeout, settlement, and turn rotation.

## 2. State (informal; canonical encoding per protocol-types §4)
`{ gameId, rulesetHash, parties[], turnOrder[], roundNo, actingParty, pot, visibleCards[2], thirdCard?, commitments{entropy[], deck}, phase, deadlines{decision, recovery}, stateHash }`.

## 3. Phases / legal successors (verified architecture §2.4)
pot-formation → deck-commitment → visible-card-reveal (two cards) → bet (active party) | decision-timeout-default → third-card-reveal → win-settlement | loss-settlement | penalty (consecutive or equal visible cards) → turn-rotation → next round; global-recovery reachable from any stalled phase.

## 4. Requirements

- **REQ-MOD-IB-001** — `init` MUST fix ruleset (stake rules, min/max bet, win payout, loss contribution, consecutive-card penalty, equal-card penalty, decision timeout, recovery timeout, player-count bounds 2–6) and hash it; the hash binds every successor (REQ-COMMIT-003).
- **REQ-MOD-IB-002** — Deck order MUST be fixed before betting by combined entropy: each party commits entropy (REQ-COMMIT-001/002), all reveal, the combined seed derives the shuffle deterministically (REQ-DET-004). No party may choose the deck after seeing others' commitments (verified architecture §2.7).
- **REQ-MOD-IB-003** — Withheld entropy reveal after commitment MUST resolve by an **explicitly specified, user-pre-signed** outcome encoded as a timeout branch (REQ-BAN-009(b), REQ-ARCH-002): the `Ruleset` names exactly one outcome (e.g. timeout forfeiture / committed-fallback derivation / exclusion + penalty), every affected party pre-signs the corresponding timeout transaction at setup, and at expiry that pre-signed transaction is what settles — the engine selects nothing at runtime and there is no operator discretion (verified architecture §2.9).
- **REQ-MOD-IB-004** — The two visible cards MUST be revealed before the active party is prompted; the third card MUST be revealed only after the bet/timeout (verified architecture §2.4).
- **REQ-MOD-IB-005** — `getLegalActions` for the active party MUST return the bet range derived from pot + ruleset (REQ-BAN-006); for all others, empty until their turn.
- **REQ-MOD-IB-006** — The decision-timeout default MUST be **no bet / pass** (verified architecture §2.5.1: a forced wager would create asymmetric, exploitable risk). The default MUST be encoded as a timeout branch (§5), not chosen at expiry.
- **REQ-MOD-IB-007** — `settle` MUST compute win/loss/penalty purely from final state and conserve value against the locked pot (REQ-ENG-006); consecutive-visible and equal-visible penalties MUST be fixed amounts from the ruleset.
- **REQ-MOD-IB-008** — Fold/withdrawal (where applicable in multi-party variants) MUST surrender concealed objects without revealing them (verified architecture §2.12).
- **REQ-MOD-IB-009** — Turn rotation MUST be deterministic from `turnOrder` and `roundNo` (REQ-DET-003).
- **REQ-MOD-IB-010** — Negative battery MUST include: bet outside range, action by non-active party, third-card reveal before bet, stale bet after decision timeout, withheld entropy reveal, double bet for one round, settlement value-non-conservation attempt (REQ-TEST-002).
- **REQ-MOD-IB-011** — `in-between-e2e` MUST run a full multi-party round on the real interpreter with on-chain settlement and audit replay (REQ-TEST-007, REQ-TEST-011).
- **REQ-MOD-IB-012** — Reproducible vectors MUST cover: a deterministic deck from a fixed combined seed, each settlement class, and each penalty class; `pnpm reproduce` re-derives them (REQ-TEST-006).

## 5. Open items
- Multi-party concealed-hand variants beyond the open-information MVP require the concealment security analysis (REQ-SCOPE-003) and conform to the now-read shuffle/fair-play/provable-fairness sources (combined-key `Q=ΣP`, canonical scalar derivation, salted Merkle commitments; `SOURCE-CONFORMANCE.md` §5). Such variants MUST declare a fairness level (REQ-FAIR-001) and, for L5, the in-script-EC decision (REQ-FAIR-002).
