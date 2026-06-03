# SOURCE-CONFORMANCE.md — `bsv-universal-sdk`

This document records the result of reading the project source documents and
conforming the spec's `DEPENDS-ON-SOURCE` requirements to what the sources
actually say. It is evidence-bearing: every disposition below is traceable to a
named document, section, and page read this session.

## 0. Correction to the prior verification ledger

The spec's §0 ledger recorded most project files as "image-only PDF, unread."
**That was wrong.** The files are not PDFs and are not image-only: each is a
**ZIP archive** (`file` reports "Zip archive data") containing, per page, a JPEG
render **and an extracted-text `.txt`**, plus a `manifest.json`. Every page's
`has_visual_content` flag is `false`, so the `.txt` is authoritative. All listed
sources were read in full or to the depth stated below. The earlier "zero text
layer" conclusion came from running PDF tools on non-PDF containers and is
retracted.

## 1. What each source actually is (read this session)

| Source | What it actually is | Read |
|---|---|---|
| `Anonymous_VerifiableSetShuffling_v14_1` | The Burns-Wright EC **set-shuffle** primitive. Protocol A (multi-party combined-key additive shuffle, settle by additive private-key reconstruction at `OP_CHECKSIG`) + Protocol B (in-script PRNG selection). | Full (9pp) |
| `Fair_Play_Transactions_8_1` | **Fair-play collateral transactions**: a UTXO bond whose redemption is gated by a script-verifiable consistency predicate over commitments vs reveals. 5-check locking script; griefing-aware collateral sizing. | Full (8pp) |
| `strict_provable_fairness_19_1` | **Strict-provable-fairness model**: the **L0–L5 fairness hierarchy**, single-oracle (ΠSO) and multi-party (ΠMP) constructions, 7-adversary analysis. | Full (9pp) |
| `bsvm_dlt_main_v30_named` (+ appendices, `bsvmwhitepaper_3`) | **BSVM = a validity-proven EVM Layer-2 on BSV** via covenant UTXO chains + STARK proofs (Oskarsson & Wright). **NOT an on-chain SQL engine.** Introduces/uses **Rúnar**, a BSV Script compiler. | Characterised (intro/background/bridge/covenant pages read; proof-pipeline/fee internals not relevant to this SDK) |
| `bsvpoker_dlt_v27_named` (+ appendix) | **A card-shuffle NFT poker system on BSVM**: composes Burns-Wright shuffle + BSVM + Savanah-Wright threshold ECDSA + **device-rooted TEEs**. Card = UTXO under combined key; selection = spend. | Architecture + state-machine + settlement/abort + banned-opcode pages read (full 64+63pp not exhaustively read) |
| `Database_Technical_Profiles`, `pra_fixedprobe_v08` | Not relied on; no requirement cites them. | Not read |

**`wallet_bonus_cassandra_schema.cql`** and **`formal-architecture-v1.docx`** were
already verified (read in full) in the prior session.

## 2. Hard-rule (ban) findings in the sources — and the faithful replacements

The ban scan covered every page of every source. Banned constructs appear in the
sources and must be replaced; none of the replacements changes the cryptographic
substance.

### 2.1 OP_RETURN (banned) — appears in:
- **Shuffle Protocol B** `Txcommit` carries `(R, σid)` in an `OP_RETURN` output
  (and the optional sequential-reveal variant publishes reveals in `OP_RETURN`).
- **BSVM** relies on **unbounded `OP_RETURN`** for data availability and for
  bridge deposits (deposit tx + `OP_RETURN` naming shard/L2-address).
- **Fair-play** has an *optional* public-mapping path "e.g. via `OP_RETURN`".

**Replacement (faithful):** carry every commitment as **locking-script data-push
constants** in a spendable output — exactly the mechanism the sources already use
for the rest of their constants (Protocol B hard-codes `h0…hm` and `P1…PD`/`R`
into the pot's locking script; poker carries `cp`, `cj`, state in "data-push
fields of the state-transition transaction"; BSVM covenant **state** is in the
locking script via `OP_PUSH_TX`). So `σid`/`R` move into the locking-script
constant block. The shuffle/provable-fairness/fair-play **hidden-commitment**
paths (`H(salt‖msg)`, salted Merkle roots) are already OP_RETURN-free. The only
genuinely OP_RETURN-dependent component is **BSVM's batch DA**, which must be
replaced with an OP_RETURN-free DA (e.g. push batch data / its commitment into
the covenant-chain locking script) if BSVM is used at all.

### 2.2 CLTV / CSV (banned) — appears in:
- **Poker** uses `OP_CHECKLOCKTIMEVERIFY` to enforce the per-card **reveal
  deadline** ("spend on or before `hℓ+Δ`") and the `expire` transition
  (pp 34-36, 46, 57).
- **BSVM** uses `OP_CHECKSEQUENCEVERIFY` for **bridge withdrawal timelocks**
  (tiered: 6/20/100 blocks by amount — main pp 26-27, whitepaper p6, supp pp 6,9).

**Replacement (faithful, and already used by the same sources):** all timing is
transaction-level `nLockTime` (absolute) + `nSequence` (relative).
- The **provable-fairness** and **fair-play** papers state this explicitly:
  recovery is "pre-signed recovery transactions whose validity depends on the
  transaction's locktime and sequence/finality fields … not as opcodes in the
  settlement script" and "not by a script-level time-lock opcode."
- The **poker** paper's own **abort bundle (§9.4)** already uses `nLockTime`
  (refund-abort and default-outcome-abort transactions time-locked to heights
  after the normal-path deadlines). The CLTV reveal-deadline is converted to the
  identical pattern: a pre-signed `expire`/forfeit transaction with
  `nLockTime = hℓ+Δ`; the cooperative reveal is an ordinary spend that races it.
  Same security (reveal-or-forfeit-by-deadline), no CLTV.
- The **BSVM** CSV tiers become `nLockTime`-bounded payout transactions per tier.

**Consequence:** the spec's §0.2 conflict (CLTV/CSV in `formal-architecture-v1.docx`)
is *reinforced*, not isolated: the source papers themselves use the banned
opcodes. Three independent sources nonetheless rely on transaction-level
`nLockTime`/`nSequence` for their actual timeout mechanisms, confirming the
project rule.

## 3. The Layer-4 "on-chain SQL" premise is FALSE (material correction)

The spec's §11 "Layer 4 — On-Chain SQL Binding" and the requirements
`REQ-SQL-001..006`, `REQ-TPL-008`, and `REQ-MOD-TEA-008` rest on a
memory-derived premise: a "`triple-entry-bsv-sql` / BSVM substrate that executes
SQL statements as on-chain journal entries." **No source supports this.**
- **"SQL" appears in zero documents.** "database" and "relational" appear in
  none. "triple-entry"/"double-entry" appear in none.
- **BSVM is an EVM Layer-2** (validity-proven, STARK, covenant UTXO chains). It
  executes EVM bytecode and proves it with a STARK; it does not execute SQL.
- **Rúnar** is a **BSV Script compiler** (TypeScript / Solidity-like / Move-style
  / Go / Rust → BSV Script), not a SQL engine.

**Disposition:** the on-chain-SQL abstraction is withdrawn. What the project
actually needs — an **append-only, UTXO-committed journal** for the
triple-entry-accounting module — is achievable with the commitment primitives
that *are* grounded (Merkle field tree, §6; covenant state-chain with state in
the locking script). The journal is a sequence of committed state-chain entries,
not SQL statements. `executeOnChainSQL` / `sqlJournalLocking` are reframed as
append-only journal-entry commitment. `REQ-SQL-001..006` are **BLOCKED as
written** (premise unsupported) and **re-scoped** to the journal-via-commitment
capability; `REQ-MOD-TEA-008` is reframed to the same.

## 4. What BSVM and Rúnar *are* good for here (grounded)

- **Rúnar** is directly useful: it already provides **determinism** (compilation
  is a pure function), **termination** (loops bounded, recursion forbidden), and
  **byte-identical cross-compiler conformance across TypeScript, Go, and Rust**.
  That is precisely the SDK's own TS↔Go determinism requirement (`REQ-DET-*`,
  `REQ-TEST-003`). The SDK SHOULD evaluate emitting its Script templates via
  Rúnar, or adopting its ANF conformance boundary, rather than hand-writing
  divergent TS/Go template emitters.
- **BSVM** is useful only in part: its **covenant state-UTXO-chain** pattern
  (`OP_PUSH_TX` introspection, state in the locking script) is ban-compatible and
  is the same pattern the poker paper uses for per-card state. Its **batch DA via
  `OP_RETURN`** and **bridge CSV** are banned and cannot be adopted as-is. Its
  **STARK-verification-in-Script** technique (hash + arithmetic only, no EC
  pairing) is a genuine option for discharging the L5 in-script-EC obligation
  (§5 below) by verifying an off-chain proof on-chain instead of doing EC point
  multiplication in Script.

## 5. Crypto-block conformance (discharges SCOPE-003, COMMIT-004/005, TPL-009, SDK-005)

**Combined key (all three crypto papers agree):** each item/card maps to a
combined public key `Q = Σ_p P_p` on secp256k1; the combined private key
`w = Σ_p s_p` is held by no single party. Selection of an item is the spend of
the UTXO locked to `Q`.

**Canonical scalar derivation (fair-play §III.C; the GB2616862 mechanism):**
shuffle key `P' = (x,y)` with `y² ≡ x³+7 (mod p)`; canonical `y = min(y, p−y)`;
scalar `s = x mod n`; reject `x ≥ n` and `s = 0`; domain-separated. This is the
patent primitive, confirmed in the source.

**Commitments (COMMIT-004) — grounded:** per-entry **salted, domain-separated
Merkle commitments with selective opening**:
- shuffle A8 leaf `H("round"‖σid‖p‖j‖π_p[j]‖b_{p,j}‖r_{p,j})`, mapping leaf
  `H("map"‖σid‖r_j‖j‖s_j‖Q_j)`, final leaf `H("final"‖σid‖r'_j‖j‖Q_j)`;
- provable-fairness leaf `H("SPF-leaf"‖i‖H(e_i)‖P_i‖H(π_i))`;
- fair-play hidden-mapping commitment `C_ij = H(P_ij‖d_j‖ρ_ij)`.
All domain tags are length-prefixed/fixed-width to prevent re-segmentation. This
**is** the spec's Merkle field tree; `COMMIT-004` is grounded. The SDK's
pay-to-contract tweak (`COMMIT-001`) remains a valid *additional* commitment
option but is **not** what the sources use; the sources use salted Merkle roots +
hash commitments carried in locking-script data-pushes.

**Shuffle algebra (COMMIT-005) — conformed:**
- **Protocol A** (Burns-Wright): additive blinding shuffle
  `Q^{(p)}_{π_p(j)} = Q^{(p-1)}_j + b_{p,j}·G`; settle by reconstructing
  `w^{(N)}_ℓ = Σ_p v_{p,Π⁻¹(ℓ)} + Σ_p b_{p,j_{p-1}} (mod n)` and signing
  `⟨Q^{(N)}_ℓ⟩ OP_CHECKSIG`. Additive (not multiplicative) so the post-shuffle
  key is reconstructible from held values. Selective-path disclosure via the A8
  Merkle openings.
- **Protocol B**: in-script PRNG selection — index
  `R̄ = int(H("select"‖σid‖X_0‖…‖X_m)) mod D` via `OP_SHA256/OP_CAT/OP_MOD`,
  key selected by `OP_ROLL`, verified by `OP_CHECKSIG`. **Its `OP_RETURN`
  commitment is replaced** per §2.1.

**Settlement (TPL-009) — three grounded options, ledger sees `OP_CHECKSIG`:**
1. **Additive reconstruction** (shuffle A): one designated party reconstructs `w`
   and signs. Requires **settlement-key containment** (fair-play §V.E:
   pre-signed settlement tx / covenant-bound destination / encrypted-share
   reveal) to prevent a settlement race — fixed before reveal.
2. **Conjunctive multisig** (provable-fairness eq 8):
   `Spend(Q) ⟺ ⋀_j CheckSig(P_j, σ_j)` — no reconstruction; `OP_CHECKSIG` only.
3. **Threshold ECDSA** (poker; Savanah-Wright [2019]): `N` parties jointly
   produce one ECDSA signature under `Q`; no individual holds `w`. **Note: the
   Savanah-Wright threshold-signing paper is NOT in the project files** — this is
   a transitive `DEPENDS-ON-SOURCE`.

No exotic locking opcode is required for any of the three; the ledger sees an
ordinary signature check.

**SDK MPC/crypto surface (SDK-005) — conformed:** secp256k1 point-add and
scalar-add mod n; canonical scalar derivation (above); domain-separated salted
Merkle trees with selective opening; commit-reveal entropy
`Y_i = H(X_i)`, `R = H(Σ X_i)`; Fisher-Yates **with rejection sampling**
(provable-fairness eq 7 — without it the permutation is biased); and the chosen
settlement primitive. Any value-bearing private-information module is gated by
`REQ-SCOPE-003`.

**SCOPE-003 security gate — now a concrete checklist (the sources' own stated
open obligations):** a value-bearing concealed-information module MUST address,
before handling value:
1. **Global shuffle-permutation soundness** across unopened entries — Phase-4
   verification does not establish it; requires full opening or a Neff-style
   ZK shuffle proof (shuffle §IV, §IX).
2. **Adaptive-adversary bias** — only the non-adaptive bound is proved
   (shuffle P4/Proposition 1).
3. A **complete game-based reduction for selective disclosure** (shuffle P5 —
   not given).
4. **Cross-session unlinkability / trackability** — explicitly open in both the
   shuffle and provable-fairness papers.
5. **Abort-conditioned bias** — deposits/collateral penalise but do **not**
   cryptographically prevent it; "conditional completion," not
   bias-freeness over the joint (settled, abort) distribution.
6. **Pre-commitment collusion** (fair-play §I) — needs simultaneous commit / MPC
   / blinding / shuffle proofs.
7. **Rejection sampling** actually implemented (else biased selection).
8. **Fairness level achieved** (§6 below): L5 target, or a justified L4 +
   external sanction.
9. **In-script-EC feasibility** for any L5 attestation on the target ledger
   (§7 below).
10. If the module relies on **TEE** for confidentiality (poker does), the **TEE
    decision** (§8 below) and the residual UI-layer bound.

## 6. Adopt the L0–L5 fairness hierarchy (new, grounded in provable-fairness)

- **L0** operator claim · **L1** outcome auditability · **L2** commitment
  auditability · **L3** recomputable randomness · **L4** recomputable transition
  (loose: deviation detectable, enforcement off-ledger) · **L5** strict
  enforceability (the settlement-critical transition predicate is evaluated
  **inside the locking script**, so the ledger rejects any `V=0` outcome).
- **Acceptance rule:** a value-bearing module states the fairness level it
  targets. Concealed-information / private-hand modules target **L5**, or
  document an explicit L4 + external-sanction justification. In-Between's
  open-information MVP can be specified at L4/L5 cheaply; poker's private hands
  require the L5 ECPS attestation (§7) or an explicit L4 declaration.

## 7. The L5 in-script EC obligation (new, decision required)

L5 strict enforcement of shuffle/attestation correctness, and the fair-play
5-check script, require **in-script EC scalar multiplication**
(`ECPS(P,w,Q)=1 ⟺ w·P=Q`; `s·G=P`; `w·P'∈E`). BSV Script post-Genesis has
big-integer arithmetic and removed size/number limits but **no single EC-point-
multiply opcode**. Three grounded options, decision per module:
1. **Implement the EC group law in Script** (feasible post-Genesis; costly;
   fair-play analyses ~50 opcodes per point-multiply plus an `O(M²)` permutation
   factor).
2. **Compile it via Rúnar** to BSV Script (determinism + conformance inherited).
3. **STARK-prove the attestation off-chain and verify the proof in Script**
   (BSVM technique — hash + arithmetic only, no EC pairing; carry the proof in
   the locking script, not `OP_RETURN`).
Without one of these, a concealed module is **L4 only** (off-chain attestation +
conjunctive/threshold `OP_CHECKSIG` settlement, which needs only `OP_CHECKSIG`).

## 8. TEE decision (new, decision required) — poker's confidentiality depends on it

The poker source makes **device-rooted TEEs** (Apple Secure Enclave, ARM
TrustZone, Intel SGX) load-bearing: private-key shares `v_{p,j}` live in the TEE,
the AEAD reveal consistency check runs inside the recipient's TEE, and pre-signed
abort signatures are stored in each TEE. Its confidentiality theorems assume TEE
integrity. The project rule is that **TEE status must be confirmed per project,
not assumed** (and is *permitted*, including for registry-authority roots). So:
- For a **private-hand** module (poker), confidentiality is **conditional on the
  TEE decision**. If TEE is in scope, state it as an explicit assumption with the
  vendor guarantees relied on and the UI-layer bound (screen-capture prevention
  reduces, does not eliminate, leakage — and note the Secure-Enclave **P-256 vs
  secp256k1** curve gap the poker paper flags).
- If TEE is **out of scope**, the private-hand confidentiality claim is not
  supported by these sources and the module must either re-derive confidentiality
  by other means or be restricted to **open-information** games (e.g. In-Between's
  MVP), which do not need it.

## 8.1 Poker full-read addendum (deck/card mechanism fully read)

The full read of the poker source (`SOURCE-CONFORMANCE.md` references below cite
the source's own sections) fixes the following details and one scope correction:

- **Threshold-ECDSA citation pinned:** the settlement protocol is Savanah-Wright
  patent **WO 2019/034951 A1** (dealerless JRSS shares of `w_j` on a degree-`(k−1)`
  polynomial, `k=N`; ephemeral nonce `D_k` shared; `r` via EC Lagrange
  interpolation; `s` via Berlekamp-Welch decoding; JZSS zero-sum masking blocks
  cross-session reconstruction; bound to the BSV sighash). Still **not in the
  project files** — transitive `DEPENDS-ON-SOURCE`.
- **Encrypted-NFT made exact:** `E_j = AEAD_{K(w_j)}(face_j)`,
  `K(w_j)=HKDF-SHA256(w_j·G)` (RFC 5869), `c_j = H(face_j‖r_j)` is a **SHA-256**
  hash commitment (explicitly *not* Pedersen). `E_j` is fixed at mint and held
  byte-immutable across covenant transitions by `OP_EQUALVERIFY`; opening
  `H(face_j‖r_j)=c_j` is checked at `Drawn→Revealed`; AEAD INT-CTXT rejects
  tampering. Reveal token `τ_p = HKDF(Z_{p,j,r}[x], "reveal"‖gid‖j‖ℓ‖h_ℓ‖E_r)`,
  `Z_{p,j,r}=v_{p,j}·E_r`; recipient aggregates
  `K_reveal = HKDF(τ_(1)‖…‖τ_(N), "aead-key"‖gid‖j)`; canonical token order is
  lexicographic by 33-byte SEC-1 compressed public key; HKDF IKM is the 32-byte
  `x`-coordinate; five properties (single-use binding, no scalar disclosure,
  recipient-only decryption, time-anchor, index-anchor). Public (community) cards
  use a deterministic hash-to-curve `E_r` of `(gid‖ℓ‖"public")` and reveal on a
  published channel.
- **SCOPE CORRECTION — betting/hand-ranking is OFF-CHAIN in the source.** "The
  winning hand is determined off-chain by standard Texas Hold'em hand-ranking; the
  pot is settled on BSV L1 by spending a pot-UTXO to the winner's public key via a
  standard P2PKH output." The poker source's on-chain scope is the **card
  mechanism + final pot spend** — it specifies no on-chain betting tree, blinds, or
  side-pot logic. The prior `poker-spec.md` `REQ-MOD-POKER-006` implied on-chain
  per-decision betting; that is the **universal architecture's** model
  (`REQ-ARCH-002`), not the poker source, and is no longer attributed to it. Value
  conservation in `settle` (`REQ-ENG-006`) still applies; side-pot/split-pot logic
  is the engine's off-chain responsibility.
- **Trust surface (10 assumptions, source Table 5)** is now a first-class module
  requirement (`REQ-MOD-POKER-009`): DDH, ECDSA EUF-CMA, HKDF/AEAD/SHA-256, BSVM
  execution integrity, BSV Nakamoto security (≤6-block reorgs), device-TEE
  integrity, partial synchrony (liveness ≤ ~300 blocks by abort `nLockTime`), NIST
  SP 800-90B TEE RNG, correct off-chain execution, correct Rúnar compilation. The
  source is explicit the protocol is non-custodial-at-reveal and dealerless but
  **not "trustless."** Formal proofs of the two novel primitives are in the
  source's Appendix §31 (cited, not re-proved).
- **Dispute resolution (source §10)** is a first-class requirement
  (`REQ-MOD-POKER-010`): four replayable classes (stage-`p` lie, withheld
  disclosure, out-of-protocol `Q_j` spend, trace mismatch), all adjudicable against
  the on-chain stage commitments `c_p = H(S_p‖α_p‖π_p)`.
- **Result:** poker grew 8→10 requirements; module total 41→43; pack grand total
  148→150.

## 9. Per-requirement disposition (updates `traceability.txt`)

| REQ | Prior | New | Basis |
|---|---|---|---|
| `REQ-SCOPE-003` | DEPENDS-ON-SOURCE | **OPEN** (gate fully specified, §5 checklist) | shuffle/fair-play/provable-fairness |
| `REQ-COMMIT-004` | OPEN (note) | **OPEN, grounded** | A8 / SPF-leaf / fair-play `C_ij` |
| `REQ-COMMIT-005` | DEPENDS-ON-SOURCE | **OPEN, conformed** (+OP_RETURN replacement) | shuffle Protocols A/B |
| `REQ-TPL-009` | DEPENDS-ON-SOURCE | **OPEN, conformed** (3 settlement options) | shuffle/provable-fairness/poker |
| `REQ-SDK-005` | DEPENDS-ON-SOURCE | **OPEN, conformed** | crypto block |
| `REQ-TPL-008` | DEPENDS-ON-SOURCE | **BLOCKED→re-scoped** (no SQL; journal-via-commitment) | §3 |
| `REQ-SQL-001..006` | DEPENDS-ON-SOURCE | **BLOCKED→re-scoped** (no SQL substrate exists) | §3 |
| `REQ-MOD-TEA-008` | DEPENDS-ON-SOURCE | **OPEN, reframed** (append-only Merkle-committed journal, no SQL) | §3 + `.cql` |
| `REQ-MOD-POKER-001..010` | DEPENDS-ON-SOURCE (was 001..008) | **OPEN, conformed** (+CLTV→nLockTime; +TEE decision; +threshold-ECDSA transitive dep WO 2019/034951 A1; +betting/hand-ranking off-chain scope correction; +009 trust surface; +010 dispute resolution) | poker paper (full read), §8.1 |
| `REQ-NODE-001..003` | DEPENDS-ON-SOURCE | **DEPENDS-ON-SOURCE (unchanged)** | codebase still absent |
| `REQ-TIME-004` | DEPENDS-ON-VERIFICATION | **DEPENDS-ON-VERIFICATION (unchanged)** | sources use *absolute* `nLockTime` for actual timeouts; relative `nSequence` enforcement on BSV/Teranode still unverified |

**New obligations introduced by the read (tracked, not padded):**
- L0–L5 fairness-level declaration per value-bearing module (§6).
- L5 in-script-EC decision per concealed module (§7).
- TEE decision per private-hand module (§8).
- Transitive `DEPENDS-ON-SOURCE`: **Savanah-Wright threshold ECDSA (patent
  WO 2019/034951 A1)** is referenced by poker but not in the project files.
- BSVM batch-DA `OP_RETURN` must be replaced if BSVM is used (§2.1, §4).

## 10. Hard rule added: non-custodial; user in total control (this is a wallet)

A binding project rule was added at automatic-reject severity: **the end user is
the sole custodian of their own keys and the sole authority required to move their
own value; the wallet, SDK, engine, relay, indexer, SPV service, node binding, any
operator, and any hosted TEE hold no user keys, sign nothing, and choose nothing on
the user's behalf.** This is `REQ-BAN-008` (clauses a–g), enforced by `REQ-BUILD-002`
plus a no-spend-without-the-user test battery.

Two requirements I had conformed from the source documents violated it and were
fixed:
- **`REQ-TPL-009` mode (a)** (additive reconstruction — one party reconstructs `w`
  and can then spend alone) is now permitted only under containment that provably
  binds the reconstructed key to a single, user-pre-signed settlement transaction;
  the non-custodial modes (conjunctive multisig; `N`-of-`N` threshold ECDSA with the
  user as a required share) are preferred for user value. Any `(t,N)` with `t<N`
  MUST NOT move a single user's own value without that user.
- **Poker `REQ-MOD-POKER-007` `(t,N)` variant** (subset completes a reveal) MUST NOT
  apply to a user's own card/value; and the **TEE MUST be the user's own device** —
  no hosted/operator-run TEE may hold a user's share.

Also conformed: `REQ-SDK-002` (builders emit unsigned templates only; SDK never
holds keys, never auto-signs/broadcasts/selects), `REQ-ARCH-005` (elevated to point
at the hard rule), poker `REQ-MOD-POKER-006` (the pot is never operator-custodied;
contested-pot distribution is a participant-pre-signed path), and the operator role
throughout is reduced to fee/hosting infrastructure with no custody or signing
authority. The poker source's operator-flavoured framing (operator fee absorption,
"commercial gaming operators") is **infrastructure-only** under this rule and confers
no custody.

Counts: `REQ-BAN-008` added → core 107→108, pack grand total 150→151.

## 10.1 Hard rule added: user chooses every action (gameplay control)

A second binding rule was added at automatic-reject severity, extending total
user control from custody into gameplay: **`REQ-BAN-009`** — no assistant/engine-
selected gameplay choices; no defaults unless explicitly specified and
user-pre-signed; everything user-facing is menu-driven; a person chooses every
action; bots are test-only and never a default participant; funding and defunding
remain user-controlled; real (acceptance) testing requires a real person; and
**failure to allow selection is itself a failure**.

Distinction made explicit (not a contradiction with `REQ-ARCH-002`): a
timeout/abort branch is legitimate **only** as the affected user's own,
explicitly-specified, pre-signed fallback for *that user's* non-response — never
as the engine selecting a move for a present user, and never as an implicit or
convention-inherited default. The engine advances an actionable state only on the
user's signed action or on the elapse of the deadline that triggers the user's own
pre-signed timeout transaction.

Conformed by this rule:
- `REQ-ARCH-002` (timeout branch reframed as the user's pre-signed silence-fallback),
  `REQ-ENG-001` (`getLegalActions` enumerates; never selects), `REQ-ENG-008`
  (no implicit default; every non-response outcome explicitly specified +
  user-pre-signed), `REQ-SDK-002` (unsigned templates; no auto-select/broadcast),
  `REQ-CLIENT-001/002` (menu-driven; no auto-confirm; the stated silence-outcome is
  the user's pre-signed fallback), `REQ-BUILD-002` (scanner extended).
- New: `REQ-TEST-012` (human-in-the-loop acceptance — a bot run may not be reported
  as user-acceptance) and `REQ-TEST-013` (automated actors confined to a test-only
  `test-actors` package, unbuildable into production).
- Module outcomes reframed from engine-applied to explicitly-specified +
  user-pre-signed: in-between `REQ-MOD-IB-003` (withheld-reveal outcome) — note
  `REQ-MOD-IB-006` was already correct (no-bet/pass, encoded as a timeout branch,
  "not chosen at expiry") — and poker `REQ-MOD-POKER-010` dispute class (2)
  (withheld-disclosure outcome).

Counts: `REQ-BAN-009` + `REQ-TEST-012` + `REQ-TEST-013` added → core 108→111,
pack grand total 151→154.

*End of SOURCE-CONFORMANCE.md.*
