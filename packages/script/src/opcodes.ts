// @bsv-universal/script — opcode table + the REQ-TPL-003 whitelist.
//
// Only the whitelisted opcodes exist for this engine. The BTC artifacts (the 0x6a data-carrier and
// the 0xb1/0xb2 timelock opcodes) are explicitly listed as BANNED and rejected at parse AND eval time
// (REQ-BAN-001..003 enforced at the interpreter level, not only by the static scanner).

export const OP = {
  OP_0: 0x00,
  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51,
  OP_16: 0x60,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_DEPTH: 0x74,
  OP_SWAP: 0x7c,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHAN: 0xa0,
  OP_SHA256: 0xa8,
  OP_HASH160: 0xa9,
  OP_HASH256: 0xaa,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKMULTISIGVERIFY: 0xaf,
} as const;

// Explicitly BANNED opcodes (BTC artifacts). Present so the interpreter can name them in rejections.
export const BANNED_OPCODES: Readonly<Record<number, string>> = {
  0x6a: 'OP_RETURN', /* ban-ok: name for runtime rejection (REQ-BAN-001) */
  0xb1: 'OP_CHECKLOCKTIMEVERIFY', /* ban-ok: name for runtime rejection (REQ-BAN-002) */
  0xb2: 'OP_CHECKSEQUENCEVERIFY', /* ban-ok: name for runtime rejection (REQ-BAN-003) */
};

// REQ-TPL-003 whitelist: signature, hash, branching, numeric/stack. Pushdata + small ints are
// always permitted (handled separately). Anything not here is rejected — fail-closed.
export const WHITELISTED_OPCODES: ReadonlySet<number> = new Set<number>([
  OP.OP_1NEGATE,
  OP.OP_IF, OP.OP_NOTIF, OP.OP_ELSE, OP.OP_ENDIF, OP.OP_VERIFY,
  OP.OP_TOALTSTACK, OP.OP_FROMALTSTACK,
  OP.OP_DROP, OP.OP_DUP, OP.OP_DEPTH, OP.OP_SWAP,
  OP.OP_EQUAL, OP.OP_EQUALVERIFY,
  OP.OP_ADD, OP.OP_SUB, OP.OP_LESSTHAN, OP.OP_GREATERTHAN,
  OP.OP_SHA256, OP.OP_HASH160, OP.OP_HASH256,
  OP.OP_CHECKSIG, OP.OP_CHECKSIGVERIFY, OP.OP_CHECKMULTISIG, OP.OP_CHECKMULTISIGVERIFY,
]);

/** True for small-integer opcodes OP_1..OP_16 (which push 1..16). */
export function isSmallInt(code: number): boolean {
  return code >= OP.OP_1 && code <= OP.OP_16;
}
export function smallIntValue(code: number): number {
  return code - (OP.OP_1 - 1); // OP_1 → 1 … OP_16 → 16
}

/** Consensus-style bounds (BSV). Fail-closed defaults; all eval work is bounded by these. */
export interface EvalLimits {
  readonly maxScriptBytes: number;
  readonly maxOps: number;
  readonly maxStack: number;
  readonly maxElement: number; // max bytes per stack element
  readonly maxNumBytes: number; // max bytes interpreted as a CScriptNum
}
export const DEFAULT_LIMITS: EvalLimits = {
  maxScriptBytes: 10_000,
  maxOps: 20_000,
  maxStack: 1_000,
  maxElement: 520,
  maxNumBytes: 4,
};
