# Module Spec — `poker` (brief's reference game) — conformed (full read)

**Status:** conformed to the fully-read poker source `bsvpoker_dlt_v27_named`
("A Card-Shuffle NFT System on BSVM", C.S. Wright) and the shuffle / fair-play /
provable-fairness papers (`SOURCE-CONFORMANCE.md` §5, §8). The source composes
four inherited primitives — Burns-Wright EC set-shuffle (GB 2616862), the **BSVM**
execution environment, **Savanah-Wright threshold ECDSA** (patent **WO 2019/034951 A1**),
and **device-rooted TEEs** — plus two novel primitives (single-use
consensus-timestamped ECDH reveal token; recipient-only threshold decryption).
This spec encodes that design under the project hard rules: **CLTV converted to
transaction-level `nLockTime`**, commitments **OP_RETURN-free**, and the **TEE**
and **threshold-ECDSA** dependencies made explicit.

**Scope boundary (read carefully):** the source's *on-chain* scope is the card
mechanism — shuffle, deal, encrypted-NFT cards, reveal, and threshold-ECDSA
close-out. **Betting rounds and hand evaluation are OFF-CHAIN in the source**; the
pot is settled on BSV L1 only as a final spend to the winner (see
`REQ-MOD-POKER-006`). On-chain per-decision betting is a property of the universal
architecture (`REQ-ARCH-002`), not of the poker source — this spec does not
attribute it to the source.

Two dependencies remain open and are tracked, not assumed: the **Savanah-Wright
threshold-ECDSA paper (WO 2019/034951 A1) is not in the project files** (transitive
`DEPENDS-ON-SOURCE`), and any prior `bsv-poker` codebase is absent (`REQ-NODE-001..003`).

## 1. Grounded construction (from the source)

- **REQ-MOD-POKER-001 — state machines (grounded).** Deck and card state are
  covenant UTXO state-chains with **state in locking-script data-push fields
  (no `OP_RETURN`)**:
  - **Deck:** `Setup → Shuffling (N stages via commitStage) → Ready (finaliseOrder) → Playing`.
    Setup carries the `N` player public keys and the `N×D` per-card public-key
    matrix. Each stage-`p` UTXO is spent by player `p`, appending the 32-byte
    SHA-256 stage commitment `c_p = H(S_p‖α_p‖π_p)` (covering the stage state, the
    player's fresh scalar `α_p`, and permutation `π_p`) and incrementing the stage
    counter by one; sequential commit is enforced by the UTXO invariant. On-chain
    cost is `32N` bytes per game.
  - **Card:** `Minted → Drawn → Revealed → Discarded` (or `Drawn → Discarded` via
    `expire`). Each card is a single BSV UTXO locked by the combined key
    `Q_j = Σ_p P_{p,j}` (`REQ-COMMIT-005`); **selection of a card is the spend of
    that UTXO**.
  The brief and the poker source both cite the shuffle patent as **"GB 2616862 B"**
  (granted form); the project's uploaded shuffle copy is the **"A"** application
  publication. Whether the "B" grant is current is **not confirmed** from the
  documents — verify before relying on grant status.
- **REQ-MOD-POKER-002 — banned-construct conversions (grounded).** The source uses
  `OP_CHECKLOCKTIMEVERIFY` for the per-card reveal deadline and `expire` (pp 34-36).
  Under `REQ-BAN-002/003` this is converted to the **same `nLockTime` pattern the
  source already uses for its abort bundle (§9.4)**: a pre-signed forfeit/`expire`
  transaction with `nLockTime = h_ℓ + Δ` that any party may broadcast at/after the
  deadline; the cooperative reveal is an ordinary spend that races it. The
  draw-confirmation height `h_ℓ` is still **recorded as data** in the Drawn UTXO
  (it is the consensus-timestamp input to the reveal token, `REQ-MOD-POKER-007`) —
  only the CLTV *enforcement* is converted. The source's commitments are already
  `OP_RETURN`-free; if poker anchors via BSVM, BSVM's `OP_RETURN` batch-DA must be
  replaced (`SOURCE-CONFORMANCE.md` §2, §4).

## 2. Interface obligations

- **REQ-MOD-POKER-003** — Poker MUST implement `ContractModule` (§8) with
  byte-identical TS↔Go replay (`REQ-TEST-003`).
- **REQ-MOD-POKER-004 — settlement via threshold ECDSA (grounded).** The
  `Q_j`-locked card value is spent by **threshold ECDSA** per Savanah-Wright
  (WO 2019/034951 A1): each `v_{p,j}` is a Shamir share of `w_j = Σ_p v_{p,j}` on a
  degree-`(k−1)` polynomial (`k=N` for the `N`-of-`N` reveal), generated dealerlessly
  by joint random secret sharing; the ephemeral nonce `D_k` is jointly generated and
  shared; `r` is the `x`-coordinate (mod `n`) of `D_k·G` recovered by EC Lagrange
  interpolation; `s = D_k⁻¹(H(m)+r·w_j) mod n` is combined from partial signatures by
  Berlekamp-Welch decoding; **no party ever holds `w_j` or `D_k`**. JZSS zero-sum
  masking prevents cross-session aggregation from reconstructing `w_j`. The signed
  message `m` is the BSV sighash (version, outpoint, input script, output set,
  locktime), so the signature is single-use by the UTXO invariant. **The
  Savanah-Wright paper (WO 2019/034951 A1) is not in the project files** (transitive
  `DEPENDS-ON-SOURCE`); the conjunctive-multisig and additive-reconstruction modes
  of `REQ-TPL-009` do not depend on it. The `N`-of-`N` construction satisfies
  **REQ-BAN-008(b)**: every user's own share is required, so no subset can spend a
  user's card value without that user. Value handling is gated on `REQ-SCOPE-003`.
- **REQ-MOD-POKER-005 — fold-without-reveal (grounded).** Fold surrenders concealed
  cards without revealing them: unselected cards' combined keys remain committed and
  unopened, and no scalar leaves custody (shuffle Protocol A; verified architecture
  §2.12). Undealt cards stay `Minted` and are pruned to `Discarded` via the `expire`
  path past the hand-end deadline.
- **REQ-MOD-POKER-006 — betting & pot settlement (scope-corrected).** In the poker
  source, **betting rounds and hand evaluation are off-chain**: the winning hand is
  determined off-chain by standard hand-ranking, and the pot is settled on BSV L1 by
  spending a **pot-UTXO to the winner via a standard P2PKH output** within the
  covenant-advance batch. This module MUST therefore: (a) treat the on-chain artifacts
  as the card mechanism + the final pot spend, not per-bet transactions; (b) keep
  `settle` value-conserving — total payout equals the locked pot, side/split pots
  included (`REQ-ENG-006`) — noting that side-pot/split-pot *logic* is the engine's
  off-chain responsibility, **not** grounded in the poker source; (c) per
  **REQ-BAN-008(d)(e)**, the pot-UTXO MUST be locked so that release to the winner is
  authorised only by the participants' own keys (the funding/settlement construction
  of §5–§6), never by an operator holding the pot — any "operator" is fee/hosting
  infrastructure only, with no custody of or signing authority over the pot, and the
  timeout/abort distribution of a contested pot MUST be a path the participants
  pre-signed at funding. Where a deployment wants on-chain per-decision betting with
  cooperative + `nLockTime`-timeout branches, that is the universal architecture's
  model (`REQ-ARCH-002`, §5), declared as such and not attributed to the poker source.
- **REQ-MOD-POKER-007 — encrypted-NFT + single-use reveal (grounded, full detail).**
  A card is an **encrypted NFT** `(Q_j, P_{1,j}…P_{N,j}, E_j, c_j)`:
  `E_j = AEAD_{K(w_j)}(face_j)` with key `K(w_j) = HKDF-SHA256(w_j·G)` (RFC 5869),
  and `c_j = H(face_j‖r_j)` a **SHA-256** hash commitment (explicitly *not* Pedersen).
  `E_j` is fixed at mint and propagated unchanged: each covenant transition enforces
  `OP_EQUALVERIFY` byte-equality on the `E_j` slot; at `Drawn → Revealed` the script
  checks the opening `H(face_j‖r_j) = c_j`, and AEAD INT-CTXT rejects a tampered
  ciphertext. Reveal uses the **single-use ECDH token**: the recipient's TEE makes a
  one-shot `(e_r, E_r=e_r·G)`, posts `E_r` in the draw tx (private hand) or uses a
  deterministic hash-to-curve `E_r` of `(gid‖ℓ‖"public")` (community cards); each
  discloser's TEE computes `Z_{p,j,r}=v_{p,j}·E_r` and emits only
  `τ_p = HKDF(Z_{p,j,r}[x], "reveal"‖gid‖j‖ℓ‖h_ℓ‖E_r)` — `v_{p,j}` never leaves the
  TEE. The recipient re-derives `Z=e_r·P_{p,j}`, verifies each token, and derives
  `K_reveal = HKDF(τ_(1)‖…‖τ_(N), "aead-key"‖gid‖j)` to decrypt `E_j`. **Canonical
  token order** = lexicographic by 33-byte SEC-1 compressed long-term public key
  (defeats Dolev-Yao reordering); HKDF IKM is the **32-byte x-coordinate** of the
  shared secret; point-at-infinity excluded. The five properties MUST hold:
  single-use binding, no scalar disclosure, recipient-only decryption, time-anchor
  (`h_ℓ`), index-anchor (`ℓ`). Partial-token leakage (`<N` tokens) does not yield
  `K_reveal`; refusal to emit `τ_p` is a **liveness** failure resolved by the
  `expire` deadline + bond slashing. The source's optional `(t,N)` variant
  (`t<N`, trading collusion resistance for liveness) **MUST NOT** be used to spend
  or decrypt a single user's own value without that user (**REQ-BAN-008(b)**); it is
  admissible only for genuinely shared/table state every affected user authorised at
  setup, and the spend of any user-owned UTXO still requires that user's share.
  **Confidentiality DEPENDS ON TEE** — and per **REQ-BAN-008(a)** the TEE MUST be the
  **user's own device** (Secure Enclave / TrustZone / SGX on the user's hardware);
  no hosted, remote, or operator-run TEE may hold a user's share `v_{p,j}`
  (`REQ-FAIR-003`: confirm scope; Secure-Enclave **P-256 vs secp256k1** gap; the
  UI-layer screen-capture bound reduces, does not eliminate, leakage). The module
  MUST declare a **fairness level** (`REQ-FAIR-001`): private hands target **L5**
  (in-script-EC decision `REQ-FAIR-002`) or an explicit **L4 + external-sanction**
  justification. If TEE is out of scope, private-hand confidentiality is unsupported
  by the source — restrict to open-information play (use `in-between`) or re-derive
  confidentiality otherwise.
- **REQ-MOD-POKER-008** — "No regression": if a prior poker implementation exists in
  the absent `bsv-poker` repo, import its reproducible vectors and keep them passing
  (locate the repo first, `REQ-NODE-001`); plus negative + positive batteries and
  `poker-e2e` per §14, vectors per `REQ-TEST-006`. Negative battery MUST include:
  token replay across `(ℓ, h_ℓ, E_r)`, substituted `E_j` mid-protocol (must fail the
  covenant `OP_EQUALVERIFY`), face/opening mismatch at reveal, out-of-protocol spend
  of a `Q_j` UTXO, and a banned-opcode-bearing script.

## 3. Security model (grounded in the source's trust surface)

- **REQ-MOD-POKER-009 — declared trust surface.** The source is explicit that the
  protocol is non-custodial at reveal and dealerless, but **not "trustless"**: it
  rests on **ten enumerated assumptions** (source Table 5), each of which this module
  MUST carry in its `assumptions[]` (`REQ-BAN-007`) and surface for any value-bearing
  deployment: (1) DDH on secp256k1 (shuffle indistinguishability, encrypted-NFT
  confidentiality, reveal-token secrecy); (2) ECDSA EUF-CMA (selection integrity, no
  forged spends); (3) HKDF/AEAD/SHA-256 soundness (single-use binding,
  non-replayability, ciphertext integrity); (4) BSVM execution integrity; (5) BSV
  Nakamoto security (≤6-block reorgs); (6) device-TEE integrity (per-share
  confidentiality, honest RNG); (7) partial synchrony (liveness; bounded ≤ ~300 blocks
  by abort `nLockTime`); (8) NIST SP 800-90B-compliant TEE RNG (uniform scalar /
  permutation sampling — biased RNG degrades the indistinguishability bound by the
  min-entropy deficit); (9) correct off-chain protocol execution; (10) correct Rúnar
  compilation of the covenant predicates. This is the concrete content of the
  `REQ-SCOPE-003` gate for poker. Formal standalone proofs for the two novel
  primitives are in the source's Appendix §31 (single-use security,
  consensus-timestamp binding, recipient-only security) — cited, not re-proved here.
- **REQ-MOD-POKER-010 — dispute resolution (grounded, Section 10).** The on-chain
  stage commitments make four dispute classes adjudicable by replay, which this module
  MUST support: (1) a player lied at stage `p` — a challenger presents `S_{p-1}`, the
  claimed `S_p`, and `c_p`, and any verifier checks `H(S_p‖α_p‖π_p)=c_p` and that
  `S_p` is a valid re-encryption-and-permutation of `S_{p-1}`; (2) withheld disclosure
  — deadline-slash plus the **explicitly-specified, participant-pre-signed** silence
  outcome (REQ-BAN-009(b)): the default is named in the module spec and pre-signed by
  the affected participants at setup, and the engine selects nothing at runtime;
  (3) out-of-protocol spend of a `Q_j`
  UTXO — detectable by mempool monitoring (it requires a `v_{p,j}` to leak), freeze the
  game; (4) committed `S_p` disagrees with the off-chain trace — resolved by replay,
  since the off-chain protocol is deterministic given `(α_p, π_p)`. These are
  enforcement of the L4/L5 auditability the fairness level declares (`REQ-FAIR-001`).

## 4. Engine regression anchor
`in-between` (`in-between-spec.md`) remains the engine regression anchor: it is fully
grounded and open-information, so it exercises the engine without poker's per-module
open decisions (TEE scope `REQ-FAIR-003`, in-script-EC `REQ-FAIR-002`) and without the
threshold-ECDSA transitive dependency.
