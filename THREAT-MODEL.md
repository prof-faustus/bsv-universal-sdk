# THREAT-MODEL.md — `bsv-universal-sdk`

Microsoft-SDL threat model. **Assumption: a funded adversary is actively trying to break this** —
steal value, forge moves, bias randomness, fork state, exhaust resources, or crash a peer. Security
controls are listed against each threat with the requirement and the code that enforces it. This is a
living document, updated in the same change as the code (REQ-BAN-007: no hidden assumptions).

## 1. Assets
- **A1 — User funds / value** (satoshis, NFTs). The user is the sole custodian and sole signer
  (REQ-BAN-008). Nothing may strand, duplicate, or transfer value without the user's own signature.
- **A2 — Game integrity** (the canonical transcript and derived state). Every honest peer must
  converge on one identical total order (REQ-ARCH-001).
- **A3 — Randomness fairness** (unbiasable dice/shuffle).
- **A4 — Liveness** (a peer must not be crashable or wedgeable by hostile input).

## 2. Trust boundaries
- **TB1 — the relay / network.** Treated as **hostile even on localhost** (`packages/relay`,
  `packages/net`): it may reorder, censor, replay, flood, or inject arbitrary bytes. It is opaque
  fan-out and never authoritative.
- **TB2 — other players.** Semi-trusted: may try to act out of turn, impersonate, double-spend a
  move, bias randomness, or withhold a reveal.
- **TB3 — decoded bytes** (envelopes, bodies, beacon rounds, hex). Every byte from TB1/TB2/file is
  HOSTILE until validated (SANS). Decoders are total and bounded.

## 3. Threats → mitigations (STRIDE)

| # | Threat | STRIDE | Mitigation (requirement · code) | Test |
|---|---|---|---|---|
| T1 | Forge/replay another seat's move | Spoofing/Tampering | Every message a signed envelope bound to the player's own key; actor partyId must equal the to-move seat; relay order is not auth (REQ-SEC-001 · `sdk/envelope.ts`, `session.ts`) | `sdk/test/session.test.ts` |
| T2 | Submit chosen dice / bypass the beacon | Tampering | No action carries a raw outcome; randomness enters only as a beacon round the session verifies; debiased by rejection sampling (REQ-SEC-002 · `crypto`, `session.ts`) | `sdk`, `crypto` tests |
| T3 | Insert fake/duplicate/non-seat reveal to steer the result | Tampering | `verifyBeaconRound` enforces one-commit-per-seat, commit-precedes-reveal, secret-opens-commit, ≥1 honest reveal (REQ-SEC-003 · `crypto/index.ts`) | `crypto/test/beacon.test.ts` |
| T4 | Reorder state after packet loss → divergent forks | Tampering | Relay `/history` append order is the single authority; `OrderedSubscriber` never inserts behind delivered items; prior-transcript-hash chains the prefix (REQ-SEC-004 · `net`, `sdk/envelope.ts`) | `net/test/ordered.test.ts`, `e2e.test.ts` |
| T5 | Memory-DoS / channel poisoning on the relay | DoS | Capability tokens; max body / log / channels; bounded history pagination; oversize rejected at read time; 413/503/401/404 (REQ-SEC-005 · `relay/core.ts`, `http.ts`) | `relay/test/{core,http,fuzz}.test.ts` |
| T6 | Crash a peer with malformed network bytes | DoS | All boundary decoders are TOTAL and bounded — typed rejection, never an uncaught throw; `safeJsonParse` + strict field guards; `tryEnvelopeFromHex` validates every field/length (CWE-502/20/770 · `protocol-types`, `sdk`) | `*/test/fuzz.test.ts` (~30k iterations) |
| T7 | Stack exhaustion via deeply nested input | DoS | `canonicalStringify` fails closed at `MAX_CANON_DEPTH`; arrays bounded by `MAX_PARTIES` (CWE-674/770) | `protocol-types/test/fuzz.test.ts` |
| T8 | Strand or duplicate value in settlement | Tampering/EoP | Pure `settle` conserves total value against the locked pot every step; integer/bigint only, no float (REQ-ENG-006, REQ-MOD-IB-007 · `engine/in-between.ts`) | `engine/test/*` (conservation asserted per step + fuzz) |
| T9 | Software auto-acts / chooses for the user | EoP | `getLegalActions` only enumerates; engine never selects; no implicit default; silence resolves only via a pre-declared timeout branch (REQ-BAN-009, REQ-ENG-001/008) | `engine/test/in-between.test.ts` |
| T10 | Timing side-channel on secret comparison | Info disclosure | `verifyReveal` uses `timingSafeEqual`; signature verify via `node:crypto` (CWE-208) | `crypto` tests |
| T11 | Banned BTC constructs reintroduced | Tampering | `check:bans` (OP_RETURN/CLTV/CSV/BTC-only) + SAST gate in CI (REQ-BAN-001..005) | `pnpm ci` |

## 4. Engineering controls (defect classes impossible by construction)
- **Bounded everything** (NASA P10 #2): every loop has a provable bound or a fail-closed cap
  (`drawValue`, `genKeyPair`, `pump`, `verifyBeaconRound`, relay caps).
- **No recursion without a depth bound** (NASA P10 #1): canonical encoder is depth-capped.
- **Total parsers** (SANS): `tryFromHex`, `safeJsonParse`, `tryEnvelopeFromHex`, body/beacon decoders,
  `verifyBeaconRound`, `verifyData`, `replay`, `apply` all return typed results and never throw on
  hostile input — proven by the fuzz battery.
- **Fail-closed** defaults; least privilege (capability tokens); constant-time secret compare.
- **SAST gate** (`tooling/sast`) forbids `JSON.parse` outside the safe wrapper, `as any`, type/lint
  suppressions, unbounded loops, and `Math.random` in production code — enforced every `pnpm ci`.
- **Zero suppressions**, strict TypeScript at max settings, zero external runtime deps.

## 5. Residual risks / not-yet-built (honest)
- Real BSV-Script interpreter + covenant binding (REQ-SEC-007/008) — until built, value-bearing
  on-chain settlement is out of scope; the model layers are labelled as such, never shipped as
  production enforcement.
- TS↔Go differential corpus (REQ-TEST-003) — second-implementation cross-check pending.
- DAST/network fuzzing of the live HTTP relay beyond unit/property fuzz.
- Eclipse/peer-reputation hardening of discovery (noted in spec §gaps).

*Updated with the code it describes (REQ-TRACE-003).*
