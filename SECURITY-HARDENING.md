# SECURITY-HARDENING.md — `bsv-universal-sdk`

**Purpose.** This document binds the lessons of the **ESTATES repository audit** into the
`bsv-universal-sdk` build *before any code is written*. ESTATES is a sibling project
(`D:\claude\Monopoly\estates`) whose deterministic core was sound but whose **live multiplayer,
audit, dice, relay, and transaction paths did not enforce the security claims of its README**.
The audit verdict — *"acceptable as a deterministic prototype; NOT acceptable as a dealerless,
adversarial, fully-auditable, real-value game"* — is exactly the outcome this project must **not**
reproduce. We want secure and robust by construction.

This file is governed by **REQ-TRACE-003** (counts here, in `traceability.txt`, and in
`BUILD-STATUS.md §1` must agree) and is the authoritative SECTION source for the **`REQ-SEC-*`**
block (spec cross-reference §20). It adds **10 requirements**, raising the index to **164 total**
(core 121 + module 43).

The governing principle: **the audit's "Required fix" for each finding becomes a normative,
testable requirement here — not a code review we hope to remember later.** Each `REQ-SEC-*` cites
(a) the ESTATES finding it forecloses, (b) the ESTATES *positive* pattern we adopt, (c) the
existing `bsv-universal-sdk` requirements it sharpens, and (d) its enforcement + test obligation.

---

## 1. Cross-walk — every audit finding to a closing requirement

Severity is the ESTATES audit's. "Existing coverage" is what the spec already says; "Verdict"
states whether that was sufficient. Every row resolves to an explicit requirement.

| # | ESTATES finding (severity) | Existing `bsv-universal-sdk` coverage | Verdict | Closes with |
|---|---|---|---|---|
| 1 | Game actions **unauthenticated / forgeable** by any relay peer (CRITICAL) | `REQ-BAN-008` (sole signing authority), `REQ-ENG-001` ("selection … signed by user"), `REQ-NET-001` ("peer auth, action propagation") | **PARTIAL** — principle stated, but no normative *signed-message schema* binding actor, prior-transcript hash, and sequence | **REQ-SEC-001** |
| 2 | Live client uses **biased local dice**, bypasses the beacon (CRITICAL) | `REQ-COMMIT-004/005` (commit-reveal), `REQ-FAIR-*`, `REQ-ENG-001` (RNG only via seed) | **PARTIAL** — commit-reveal specified, but no explicit *ban on raw client randomness on the action surface* and no *rejection-sampling / no-modulo-bias* mandate | **REQ-SEC-002** |
| 3 | Audit transcript **does not verify commitments**, participant set, or timeouts (CRITICAL) | `REQ-ENG-003` (replay folds through validation), `REQ-TEST-002` (withheld-reveal negative) | **PARTIAL** — replay validates *transitions*, but no requirement that the verifier check commitment-precedes-reveal, one-per-eligible-seat, no non-seat reveal, timeout-default evidence | **REQ-SEC-003** |
| 4 | HTTP relay **ordered replay wrong after packet loss** (HIGH) | `REQ-DET-007` (canonical conflict ordering), `REQ-ARCH-001` (state = deriveState(transcript)) | **PARTIAL** — canonical *content* order defined, but no *transport-level* total-order guarantee (sequence numbers + gap buffering) | **REQ-SEC-004** |
| 5 | Relay **trivially memory-DoSable and unauthenticated** (HIGH) | none explicit (`REQ-NET-003` = "non-custodial infra" only) | **GAP** | **REQ-SEC-005** |
| 6 | On-chain NFT/state encoding **lacks range & canonical validation** (HIGH) | `REQ-DET-001` (one canonical serialization), `REQ-TEST-002` (out-of-bounds negative) | **PARTIAL** — canonical *encode* implied, but no requirement that *decode reject* every non-canonical / out-of-range byte | **REQ-SEC-006** |
| 7 | Trade tx model **is not a real BSV transaction verifier** (HIGH) | `REQ-SDK-002` (unsigned builders), `REQ-TPL-*` | **PARTIAL** — builders specified, but no requirement to use the *real BSV SDK tx model* and verify prevout value/script/fee/change before real value | **REQ-SEC-007** |
| 8 | Covenant predicate **insufficient as standalone bank-enforcement proof** (MEDIUM) | `REQ-TPL-004` (full spend branches), `REQ-TPL-009` (MPC locking) | **PARTIAL** — branch shapes specified, but no requirement to *bind* the predicate to the spent outpoint, prior script, rules-hash, and the canonical action | **REQ-SEC-008** |
| 9 | **Unsafe hex parsing** in multiple verifier paths (MEDIUM) | `REQ-TEST-005` (fuzz; replay never throws), `REQ-ENG-004` (total replay) | **PARTIAL** — fuzz target exists, but no *single strict codec* mandate rejecting odd-length / non-hex / wrong-length | **REQ-SEC-009** |
| 10 | Root CI **does not build the web client or Tauri** package, nor adversarial protocol tests (MEDIUM) | `REQ-BUILD-007` (no green-by-omission), `REQ-CLIENT-003/004` (web/desktop exist) | **PARTIAL** — "no green by omission" stated, but CI scope does not *explicitly* include app builds + an adversarial-protocol battery | **REQ-SEC-010** |

**Net:** 0 findings are left to "we'll catch it in review." 1 was a true gap (#5); the other 9
were principles without teeth — now each has a normative requirement, an enforcement point, and a
named test obligation.

---

## 1A. Reference implementations — ESTATES' verified, CI-green fixes (conformance targets)

ESTATES did not merely receive this audit; it **remediated all 10 findings in code and shipped them
CI-green** (28 packages, `tools/ci.ts` = bans → typecheck → tests → web build). Each fix below was
**confirmed present in source** (file:symbol verified, not claimed). For `bsv-universal-sdk`, these
are the **reference implementations** the corresponding `REQ-SEC-*` MUST conform to — i.e., build it
the way ESTATES' tested code already does it, generalized to the universal engine. This is the
concrete meaning of "apply ESTATES' requirements when building."

| REQ-SEC | ESTATES reference (file · symbol) — verified present | Mechanism to reproduce |
|---|---|---|
| 001 | `packages/sidecar/src/index.ts` · `GamePeer.movePayload` / `signData` / verify at apply; key from `channel.identityFrom(playerPriv)` / `@estates/keys genMaster` | Sign every move with the **player's OWN** key (not a throwaway) over `{k:'…-move-v1', gameId, turnIndex, actor, action}`; the same key does the IP-to-IP handshake + chat address; `seatKeys` map binds a peer to its own seat; unsigned/forged/wrong-actor → dropped |
| 002 | `packages/beacon/src/index.ts` · `drawDie` (rejection-sample, reject byte ≥252) + sidecar verify | ROLL dice come from a commit→reveal beacon round, `prev_beacon`-chained; verifier returns `null` if `result.dice ≠ supplied dice`; `policy()` emits no dice |
| 003 | `packages/audit/src/index.ts` · `audit()` | Per entry: one commit per live seat; reject duplicate commit/reveal; reject non-live/non-seat reveal; each reveal opens its commit (`verifyReveal`); ≥1 honest reveal; dice only from verified set |
| 004 | `packages/chat/src/relay.ts` · ordered subscribe | `/history` append order is the SINGLE authority; SSE is only a poke to re-poll; never append a live frame into local order |
| 005 | `packages/chat/src/server.ts` · `MAX_BODY` / `MAX_LOG` / `MAX_CHANNELS` | Bounds 256 KB body / 200 K msgs-per-channel / 10 K channels; HTTP 413 on oversize, 503 on cap; `req.destroy()` on overflow |
| 006 | `packages/onchain/src/index.ts` · `validateTitleState` | Direct range checks that THROW (no `& 0xff`): kind ∈ set, gameTag 32 B, propertyId 0..39, groupId 0..255, buildLevel 0..5, mortgaged boolean, REPRIEVE canonical, vout uint32 |
| 007 | `packages/trade/src/index.ts` · `verifyTradeValue(tx, prevAmounts, fee)` | Conserve against REAL prev-UTXO sats: `Σ prevAmounts === Σ outputs + fee`, integer-validated; not claimed amounts |
| 008 | `packages/bank/src/covenant.ts` · `verifyCovenantSpend` | Bind to spent outpoint (`input[0] === prevOutpoint`) + prior covenant script (`=== covenantOutput(reserve, rulesHash).script`) + rules hash, THEN payout predicate |
| 009 | `fromHex`/`fromHexStrict` across sidecar/audit/trade/onchain/net/chat | `h.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(h)` else throw; no `parseInt`-without-validation, no silent zero-bytes |
| 010 | `tools/ci.ts` · step 4 `web client build` | `pnpm --filter @estates/client-web build` is part of CI; app not silently excluded |

Where the Game Engine differs from ESTATES (multi-module, TS↔Go differential, real BSV Script
interpreter), the requirement **generalizes** the reference: e.g. REQ-SEC-001's envelope adds
`networkId/moduleId/contractId/protocolVersion/priorTranscriptHash/sequenceNo` beyond ESTATES'
move payload, and REQ-SEC-007 additionally mandates full script-satisfaction in the real interpreter
(`REQ-TEST-001`), which ESTATES brackets as its production path. The reference proves the approach
is real and testable; the `REQ-SEC-*` text is the binding form for this project.

---

## 2. The `REQ-SEC-*` requirements (normative)

Each requirement is OPEN (nothing is built). Severity **AUTOMATIC-REJECT** means a violation fails
`pnpm ci` and may not be merged, in the same manner as the `REQ-BAN-*` family.

### REQ-SEC-001 — Authenticated protocol: every message signed, actor-bound, chained
**Severity: AUTOMATIC-REJECT. Closes finding #1.**

Every protocol message (session/join, seat-claim, start, action, leave, commit, reveal, settlement)
MUST be a **signed envelope**; relay ordering is **never** treated as authentication. The signed
payload MUST bind, at minimum:

```
{ networkId, moduleId, contractId, protocolVersion, messageKind,
  seatId, actorPubKey, priorTranscriptHash, sequenceNo | blockRef, body }
```

The signing key MUST be the **player's own long-lived non-custodial key** — the *same* identity that
authenticates the IP-to-IP session handshake and addresses encrypted (Bitmessage-style) chat — and
**never a software-generated throwaway seat key**. One key per player: it authenticates the channel,
signs every move, and derives the chat address. This binds finding #1 to `REQ-BAN-008` (the user is
the sole custodian of the key that authorizes their actions). A seat is occupied by registering that
player public key; "the seat key" everywhere below means *that* key.

Acceptance rules the replay/`deriveState` path MUST enforce (a message failing any rule is **dropped**,
never applied):
- An **action** is accepted only if signed by the **player key registered to the seat that is legally
  to-move** in the current derived state.
- A **host/start** action is accepted only if signed by the **registered host key**.
- A **leave** is accepted only if signed by the **leaving seat's** key.
- `priorTranscriptHash` MUST equal the hash of the accepted transcript prefix; a mismatch is a
  fork/replay attempt and is rejected.
- `sequenceNo` MUST be strictly monotonic per channel; gaps are handled by REQ-SEC-004, not by
  reordering.

**ESTATES pattern adopted:** ESTATES' `bank` M-of-N verifier counts *distinct registered seat keys*
whose `SIGHASH_ALL` signature verifies and rejects duplicate/non-seat signers — the same
*actor-key-binding* discipline, lifted to every table message.
**Sharpens:** `REQ-BAN-008`, `REQ-ENG-001`, `REQ-NET-001`.
**Enforcement:** `packages/sdk/src/net/**` envelope verifier; `replay` rejects unsigned/mis-actored
messages. **Test:** `REQ-TEST-002` (forged-actor negative — publish `{type:BUY}` / `{type:ROLL}`
from a non-active, non-seat, and wrong-seat key and assert each is dropped), `REQ-TEST-012`.

### REQ-SEC-002 — No raw client randomness on the action surface; beacon-only, debiased
**Severity: AUTOMATIC-REJECT. Closes finding #2.**

No user- or client-supplied random outcome (dice, shuffle, draw, coin) may appear on the live action
surface. A random outcome MUST be **derived** from a commit→reveal transcript:
1. commitments from every eligible live seat first,
2. reveals second,
3. deterministic outcome derivation third (`H(reveals_ordered_by_seat ‖ turnIndex ‖ priorBeacon)`),
chaining the prior beacon and binding the turn index. The derivation MUST use **rejection sampling**
(no modulo reduction of a non-multiple range — the exact ESTATES `% 6` bias). The signed randomness
action carries the commitment set, reveal set, timeout evidence for missing reveals, prior beacon,
and turn index — **never** a bare outcome value. The engine MUST reject a randomness action whose
outcome is not reproducible from its transcript.

**ESTATES pattern adopted:** ESTATES' `beacon` already does this correctly (rejection sampling,
`SHA256(reveals_ordered ‖ turn ‖ prev)`, timeout-drop of committed non-revealers, unbiasable if ≥1
honest seat commits before any reveal). The audit's defect was that the *live client did not use it*.
This requirement forecloses that divergence at the type level: there is no action carrying a raw value.
**Sharpens:** `REQ-COMMIT-004/005`, `REQ-FAIR-001`, `REQ-ENG-001`.
**Enforcement:** randomness action type carries no outcome field; `packages/engine/**` derives and
verifies. **Test:** `REQ-TEST-002` (publish a chosen-dice action → rejected), `REQ-TEST-004`
(uniformity / no-modulo-bias property), `REQ-TEST-007` (e2e via beacon only).

### REQ-SEC-003 — Audit verifies commitments, participant eligibility, and timeout defaults
**Severity: AUTOMATIC-REJECT. Closes finding #3.**

The audit/`replay` verifier for any randomness or sealed-bid entry MUST verify, not merely recompute:

```
exactly one commitment per eligible live seat
commitment precedes reveal (ordering proven, not assumed)
each revealed secret hashes to its prior commitment
no duplicate seat reveal
no reveal from a non-seat / bankrupt / ineligible seat
every dropped reveal carries timeout / default-branch evidence
the outcome is derived ONLY from the canonical valid reveal set
```

Recomputing that the outcome matches the supplied reveals is **insufficient** (the precise ESTATES
hole: a producer could insert a fake/duplicate reveal and pick the result). The verifier MUST consume
the commitment set; an entry that omits commitments is rejected, not trusted.

**ESTATES pattern adopted:** ESTATES *had* an `honestReveals()` helper that checks secrets against
commitments but the audit path didn't call it because commitments were absent from the transcript.
Here, commitments are a **required** field of the audited entry, and the verifier MUST run the check.
**Sharpens:** `REQ-ENG-003`, `REQ-ENG-004` (total, never throws).
**Enforcement:** `packages/engine/src/replay`, transcript schema. **Test:** `REQ-TEST-002`
(fake-reveal-from-fake-seat, duplicate-seat-reveal, commitment-absent, reveal-before-commit — each
rejected), `REQ-TEST-005` (fuzz).

### REQ-SEC-004 — Transport total-order: sequence numbers + gap buffering, no late insertion
**Severity: AUTOMATIC-REJECT. Closes finding #4.**

The transcript-sync path MUST guarantee a single total order across all peers even under SSE/live
frame loss + polling backfill. It MUST NOT append a "newly discovered" earlier item *behind*
already-seen later items. Either (a) rebuild from the full canonical `/history` each reconcile, or
(b) assign **server/channel sequence numbers** and **buffer gaps** until missing prior sequence
numbers arrive. Two honest peers MUST converge to byte-identical derived state regardless of frame
timing.

**ESTATES pattern adopted:** ESTATES' `net.PeerSession` already checks the sequence number and waits
on gaps/replays — the audit's `subscribeOrdered()` bug was a *different* code path that appended out
of order. This requirement makes the gap-buffering discipline the *only* sanctioned path.
**Sharpens:** `REQ-DET-007`, `REQ-ARCH-001`.
**Enforcement:** `packages/sdk/src/net/**` ordered subscriber. **Test:** `REQ-TEST-009`
(drop live frame *n*, deliver *n+1* then backfill *n*; assert identical final state on two clients).

### REQ-SEC-005 — Relay treated as hostile: bounded, authenticated, paginated
**Severity: AUTOMATIC-REJECT. Closes finding #5 (true gap).**

The relay (even bound to localhost) is hostile infrastructure and MUST enforce:
maximum body size, maximum per-channel log length, per-channel capability tokens, signed messages
(REQ-SEC-001), rate limiting, channel expiry, and **bounded, paginated** history responses (never
"return the entire log as one text response"). CORS MUST NOT be `*`-with-all-headers in any
shipped configuration. Memory MUST be bounded by construction; an unauthenticated POST MUST NOT be
able to grow relay memory without limit or force clients to process an unbounded history.

**ESTATES pattern adopted:** ESTATES' README already names the relay "untrusted"; this requirement
gives that claim teeth that the audit found missing.
**Sharpens / fixes:** `REQ-NET-003`. **Enforcement:** `services/relay/**`. **Test:** `REQ-TEST-009`
(oversized body, log-cap overflow, missing-capability, history-pagination, rate-limit — each
rejected/bounded).

### REQ-SEC-006 — Canonical decode: reject every out-of-range / non-canonical on-chain object
**Severity: AUTOMATIC-REJECT. Closes finding #6.**

Decoding any on-chain object (NFT/title/registry/journal state) MUST **reject**, not mask, every
value outside its canonical domain. Masking with `& 0xff` or silently treating non-canonical bytes
as a default is forbidden. The decoder MUST enforce the object's full validity predicate (kind ∈
declared set; ids within declared board/registry bounds; level within declared range; boolean bytes
∈ {0,1}; genesis txid strict 64-hex; vout a safe uint32; fixed-length layout). A malformed or
adversarial object decodes to a **typed rejection**, never an "impossible game state."

**ESTATES pattern adopted:** ESTATES' fixed `STATE_LEN` layout is good; the audit's complaint was
that `decodeTitleState()` accepted any byte. This requirement mandates strict, total decoding.
**Sharpens:** `REQ-DET-001`, `REQ-ENG-004`. **Enforcement:** `packages/protocol-types/**` decoders.
**Test:** `REQ-TEST-002` (out-of-bounds id/level, non-canonical boolean, bad-length genesis →
rejected), `REQ-TEST-005` (fuzz the decoder; never throws, always typed result).

### REQ-SEC-007 — Real BSV transaction model with full prevout/value/fee verification
**Severity: AUTOMATIC-REJECT before any real-value path. Closes finding #7.**

Value-bearing transactions MUST use the **real BSV SDK transaction model** end to end — real
serialization, real sighash semantics — and MUST verify previous transactions, output indices,
locking scripts, satoshi values, script satisfaction, fee, and change. A bespoke `Tx`/`TxInput`/
preimage that omits previous-output amount and locking script (the ESTATES trade layer) MUST NOT be
presented as production enforcement. `valueConserved`-style checks over requested-vs-output amounts
are insufficient without verifying the **previous** UTXO satoshis and fee/change. Any layer not yet
on the real model MUST be labelled a co-signing *model*, never "production transaction enforcement,"
and is fenced out of real-value use.

**ESTATES pattern adopted:** ESTATES' wallet broadcast guard (explicit mainnet confirmation) is kept;
the model trade layer is replaced, not shipped.
**Sharpens:** `REQ-SDK-002`, `REQ-TPL-*`. **Enforcement:** `packages/sdk/**` builders/verifiers on
the BSV SDK. **Test:** `REQ-TEST-001` (real interpreter), `REQ-TEST-002` (value-non-conservation,
wrong-prevout-amount, missing-fee → rejected).

### REQ-SEC-008 — Covenant predicate bound to outpoint, prior script, rules-hash, and action
**Severity: AUTOMATIC-REJECT for bank/covenant enforcement. Closes finding #8.**

A covenant/bank-payout predicate MUST bind, via sighash-preimage introspection, to: the **actual
spent outpoint** (it is the covenant UTXO), the **prior covenant locking script**, the **rules
hash**, the **state transition**, and a **canonical action proof** — so that recipient and amount are
*derived from canonical game state*, not supplied by the caller. A pure "output 0 pays X, output 1
re-locks residual" predicate is acceptable **only** as a unit-test oracle, never as the full
enforcement story.

**ESTATES pattern adopted:** ESTATES' own file comments acknowledge production enforcement needs
sighash-preimage introspection and schedule the covenant upgrade; this requirement makes that the
shipping bar for value-bearing covenants and matches `REQ-TPL-009` MPC-locking discipline.
**Sharpens:** `REQ-TPL-004`, `REQ-TPL-009`. **Enforcement:** `packages/script-templates-ts/**`.
**Test:** `REQ-TEST-001` (real interpreter: wrong-outpoint, wrong-prior-script, recipient-not-derived
→ rejected).

### REQ-SEC-009 — One strict hex/bytes codec everywhere; no lenient parsing
**Severity: AUTOMATIC-REJECT. Closes finding #9.**

All hex/byte parsing in verifier, audit, net, relay, and transaction paths MUST go through a
**single strict codec** that rejects odd length, empty-where-not-allowed, non-hex characters
(`/^(?:[0-9a-fA-F]{2})+$/`), and unexpected decoded length. Ad-hoc `parseInt`/`length/2`
allocation that turns malformed input into zero-like bytes is banned. Decoding adversarial input
yields a typed rejection; it never silently succeeds (supports `REQ-ENG-004`: `replay` never throws).

**Sharpens:** `REQ-TEST-005`, `REQ-ENG-004`. **Enforcement:** `packages/protocol-types/**` codec;
`check:bans` may flag ad-hoc hex parsing outside the codec. **Test:** `REQ-TEST-005` (fuzz:
odd-length, non-hex, over/under-length → typed reject, no throw).

### REQ-SEC-010 — CI builds the apps and runs an adversarial-protocol battery
**Severity: AUTOMATIC-REJECT. Closes finding #10.**

`pnpm ci` MUST build **every shippable app** — `client-web` (`vite build`) and the desktop/Tauri
config — and MUST run an **adversarial-protocol test battery** (the negative cases for REQ-SEC-001..009:
forged actor, chosen dice, fake reveal, out-of-order frame, relay DoS, non-canonical decode,
value-non-conservation, covenant misbinding, malformed hex). A requirement with no test, or an app
excluded from the build path, is a **failing `trace`**, not a pass (no green-by-omission). The root
`tsconfig`/CI scope MUST NOT silently exclude `apps/*`.

**ESTATES pattern adopted:** ESTATES' exact gap — root CI ran bans+typecheck+package tests but
excluded `apps/client-web`, so "vite build green" was unenforced. Fixed here at the CI-contract level.
**Sharpens:** `REQ-BUILD-007`, `REQ-CLIENT-003/004`. **Enforcement:** `tooling/ci/**`, root CI script.
**Test:** the CI pipeline itself (`REQ-TEST-009`/`REQ-TEST-011` adversarial + build gates).

---

## 3. Index impact (REQ-TRACE-003)

| | before | after |
|---|---|---|
| core REQs | 111 | **121** |
| module REQs | 43 | 43 |
| **TOTAL** | **154** | **164** |
| OPEN | 147 | **157** |

The 10 `REQ-SEC-*` rows are OPEN (nothing built). `traceability.txt` STATUS TALLY and
`BUILD-STATUS.md §1` are updated to match in the same change. `pnpm trace` MUST treat divergence
between these three as a defect.

---

## 4. What ESTATES got right (carried forward, not re-litigated)

The audit's positive observations are adopted as the baseline, not re-derived: a pure deterministic
engine with no I/O, clock, or RNG (matches `REQ-ENG-001`); rejection-sampling beacon (REQ-SEC-002);
an explicit mainnet broadcast guard (kept under `REQ-SEC-007`); and a static ban scanner for
OP_RETURN / CLTV / CSV / branded strings (matches `REQ-BAN-001..005`). The `REQ-SEC-*` block exists
precisely because those good foundations did **not**, by themselves, cure the unauthenticated live
protocol, the non-beacon live dice, and the incomplete audit proof. This project builds the live,
audit, dice, relay, and transaction paths to the same standard as the core from day one.

---

*End of SECURITY-HARDENING.md. Counts are authoritative against `traceability.txt` and
`BUILD-STATUS.md §1`; update all three in the same change (REQ-TRACE-003).*
