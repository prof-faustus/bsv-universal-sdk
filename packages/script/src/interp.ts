// @bsv-universal/script — bounded, total Script interpreter.
//
// Mission-critical: every script is hostile. The interpreter is TOTAL (typed rejection, never throws),
// BOUNDED (script bytes, op count, stack depth, element size, number width), FAIL-CLOSED (only the
// REQ-TPL-003 whitelist executes; banned opcodes are rejected at runtime — REQ-BAN-001..003), and the
// unlocking script is enforced push-only (attack-surface reduction). `OP_CHECKSIG` defers to an
// injected `SigChecker` so the tx layer provides real sighash+ECDSA (REQ-SEC-007 script satisfaction).

import { createHash } from 'node:crypto';
import { OP, WHITELISTED_OPCODES, BANNED_OPCODES, isSmallInt, smallIntValue, DEFAULT_LIMITS, type EvalLimits } from './opcodes.ts';
import { parseScript, type Op } from './parse.ts';

export type EvalResult = { readonly ok: true } | { readonly ok: false; readonly reason: string };

/** Verifies a signature over the spending context for an (sig, pubkey) pair (REQ-SEC-007). */
export interface SigChecker {
  check(sig: Uint8Array, pubkey: Uint8Array): boolean;
}

const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const ripemd160 = (b: Uint8Array) => new Uint8Array(createHash('ripemd160').update(b).digest());

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function castToBool(v: Uint8Array): boolean {
  for (let i = 0; i < v.length; i++) {
    if (v[i] !== 0) {
      // negative zero (only the sign bit set on the last byte) is false
      if (i === v.length - 1 && v[i] === 0x80) return false;
      return true;
    }
  }
  return false;
}

// CScriptNum: little-endian, sign-magnitude, minimally encoded, bounded width.
function decodeNum(v: Uint8Array, maxBytes: number): { ok: true; n: bigint } | { ok: false; reason: string } {
  if (v.length > maxBytes) return { ok: false, reason: 'number too long' };
  if (v.length === 0) return { ok: true, n: 0n };
  // minimal encoding check
  if ((v[v.length - 1]! & 0x7f) === 0 && (v.length <= 1 || (v[v.length - 2]! & 0x80) === 0)) {
    return { ok: false, reason: 'non-minimally-encoded number' };
  }
  let result = 0n;
  for (let i = 0; i < v.length; i++) result |= BigInt(v[i]!) << BigInt(8 * i);
  const neg = (v[v.length - 1]! & 0x80) !== 0;
  if (neg) result &= ~(0x80n << BigInt(8 * (v.length - 1)));
  return { ok: true, n: neg ? -result : result };
}

function encodeNum(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  const neg = n < 0n;
  let abs = neg ? -n : n;
  const out: number[] = [];
  while (abs > 0n) {
    out.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  if ((out[out.length - 1]! & 0x80) !== 0) out.push(neg ? 0x80 : 0x00);
  else if (neg) out[out.length - 1]! |= 0x80;
  return Uint8Array.from(out);
}

interface Vm {
  readonly stack: Uint8Array[];
  readonly alt: Uint8Array[];
  readonly vfExec: boolean[];
  opCount: number;
  readonly limits: EvalLimits;
  readonly checker: SigChecker;
}

/** Evaluate unlocking ‖ locking. Returns ok iff the script is satisfied (single truthy top). */
export function evalScript(unlocking: Uint8Array, locking: Uint8Array, checker: SigChecker, limits: EvalLimits = DEFAULT_LIMITS): EvalResult {
  const u = parseScript(unlocking, limits);
  if (!u.ok) return { ok: false, reason: `unlocking: ${u.reason}` };
  // SANS attack-surface reduction: unlocking scripts MUST be push-only. Per Bitcoin, the small-int
  // opcodes (OP_0, OP_1NEGATE, OP_1..OP_16) are push operations and are permitted.
  for (const op of u.value) if (!isPushOnly(op)) return { ok: false, reason: 'unlocking script must be push-only' };
  const l = parseScript(locking, limits);
  if (!l.ok) return { ok: false, reason: `locking: ${l.reason}` };

  const vm: Vm = { stack: [], alt: [], vfExec: [], opCount: 0, limits, checker };
  // Unlocking ops are already validated push-only; run them through the normal step so that the
  // small-int opcodes (OP_0/OP_1NEGATE/OP_1..OP_16) push their values correctly.
  for (const op of u.value) {
    const r = step(vm, op);
    if (!r.ok) return r;
  }
  for (const op of l.value) {
    const r = step(vm, op);
    if (!r.ok) return r;
  }
  if (vm.vfExec.length !== 0) return { ok: false, reason: 'unbalanced conditional (missing ENDIF)' };
  if (vm.stack.length === 0) return { ok: false, reason: 'empty stack at end' };
  if (!castToBool(vm.stack[vm.stack.length - 1]!)) return { ok: false, reason: 'top of stack is false' };
  return { ok: true };
}

/** True for ops permitted in a push-only (unlocking) script: data pushes and small-int opcodes. */
function isPushOnly(op: Op): boolean {
  if (op.kind === 'push') return true;
  return op.code === OP.OP_0 || op.code === OP.OP_1NEGATE || isSmallInt(op.code);
}

function executing(vm: Vm): boolean {
  for (const f of vm.vfExec) if (!f) return false;
  return true;
}

function stepPush(vm: Vm, op: Op): EvalResult {
  if (op.kind !== 'push') return { ok: false, reason: 'expected push' };
  if (op.push.length > vm.limits.maxElement) return { ok: false, reason: 'push exceeds maxElement' };
  vm.stack.push(op.push);
  if (vm.stack.length + vm.alt.length > vm.limits.maxStack) return { ok: false, reason: 'stack overflow' };
  return { ok: true };
}

function step(vm: Vm, op: Op): EvalResult {
  const fExec = executing(vm);
  // pushes
  if (op.kind === 'push') return fExec ? stepPush(vm, op) : { ok: true };

  const code = op.code;
  // control flow must be processed even when not executing
  if (code === OP.OP_IF || code === OP.OP_NOTIF) return doIf(vm, code, fExec);
  if (code === OP.OP_ELSE) return doElse(vm);
  if (code === OP.OP_ENDIF) return doEndif(vm);
  if (!fExec) return { ok: true }; // skip the rest while in a false branch

  if (code in BANNED_OPCODES) return { ok: false, reason: `banned opcode ${BANNED_OPCODES[code]} at runtime (REQ-BAN)` };
  if (code === OP.OP_0) {
    vm.stack.push(new Uint8Array(0));
    return capStack(vm);
  }
  if (code === OP.OP_1NEGATE) {
    vm.stack.push(encodeNum(-1n));
    return capStack(vm);
  }
  if (isSmallInt(code)) {
    vm.stack.push(encodeNum(BigInt(smallIntValue(code))));
    return capStack(vm);
  }
  if (!WHITELISTED_OPCODES.has(code)) return { ok: false, reason: `opcode 0x${code.toString(16)} not in whitelist (REQ-TPL-003)` };

  vm.opCount += 1;
  if (vm.opCount > vm.limits.maxOps) return { ok: false, reason: 'op count exceeded' };
  return dispatch(vm, code);
}

function capStack(vm: Vm): EvalResult {
  return vm.stack.length + vm.alt.length > vm.limits.maxStack ? { ok: false, reason: 'stack overflow' } : { ok: true };
}
function pop(vm: Vm): Uint8Array | null {
  return vm.stack.pop() ?? null;
}

function doIf(vm: Vm, code: number, fExec: boolean): EvalResult {
  let value = false;
  if (fExec) {
    const v = pop(vm);
    if (v === null) return { ok: false, reason: 'IF: empty stack' };
    value = castToBool(v);
    if (code === OP.OP_NOTIF) value = !value;
  }
  vm.vfExec.push(value);
  return { ok: true };
}
function doElse(vm: Vm): EvalResult {
  if (vm.vfExec.length === 0) return { ok: false, reason: 'ELSE without IF' };
  vm.vfExec[vm.vfExec.length - 1] = !vm.vfExec[vm.vfExec.length - 1];
  return { ok: true };
}
function doEndif(vm: Vm): EvalResult {
  if (vm.vfExec.length === 0) return { ok: false, reason: 'ENDIF without IF' };
  vm.vfExec.pop();
  return { ok: true };
}

function dispatch(vm: Vm, code: number): EvalResult {
  switch (code) {
    case OP.OP_DROP:
      return pop(vm) === null ? { ok: false, reason: 'DROP: empty' } : { ok: true };
    case OP.OP_DUP: {
      const a = vm.stack[vm.stack.length - 1];
      if (a === undefined) return { ok: false, reason: 'DUP: empty' };
      vm.stack.push(a);
      return capStack(vm);
    }
    case OP.OP_DEPTH:
      vm.stack.push(encodeNum(BigInt(vm.stack.length)));
      return capStack(vm);
    case OP.OP_SWAP: {
      const n = vm.stack.length;
      if (n < 2) return { ok: false, reason: 'SWAP: <2' };
      const t = vm.stack[n - 1]!;
      vm.stack[n - 1] = vm.stack[n - 2]!;
      vm.stack[n - 2] = t;
      return { ok: true };
    }
    case OP.OP_TOALTSTACK: {
      const v = pop(vm);
      if (v === null) return { ok: false, reason: 'TOALTSTACK: empty' };
      vm.alt.push(v);
      return { ok: true };
    }
    case OP.OP_FROMALTSTACK: {
      const v = vm.alt.pop();
      if (v === undefined) return { ok: false, reason: 'FROMALTSTACK: empty' };
      vm.stack.push(v);
      return capStack(vm);
    }
    case OP.OP_EQUAL:
    case OP.OP_EQUALVERIFY: {
      const b = pop(vm);
      const a = pop(vm);
      if (a === null || b === null) return { ok: false, reason: 'EQUAL: <2' };
      const eq = eqBytes(a, b);
      if (code === OP.OP_EQUALVERIFY) return eq ? { ok: true } : { ok: false, reason: 'EQUALVERIFY failed' };
      vm.stack.push(eq ? encodeNum(1n) : new Uint8Array(0));
      return { ok: true };
    }
    case OP.OP_VERIFY: {
      const v = pop(vm);
      if (v === null) return { ok: false, reason: 'VERIFY: empty' };
      return castToBool(v) ? { ok: true } : { ok: false, reason: 'VERIFY failed' };
    }
    case OP.OP_ADD:
    case OP.OP_SUB:
    case OP.OP_LESSTHAN:
    case OP.OP_GREATERTHAN:
      return binNum(vm, code);
    case OP.OP_SHA256:
      return hashOp(vm, sha256);
    case OP.OP_HASH160:
      return hashOp(vm, (b) => ripemd160(sha256(b)));
    case OP.OP_HASH256:
      return hashOp(vm, (b) => sha256(sha256(b)));
    case OP.OP_CHECKSIG:
    case OP.OP_CHECKSIGVERIFY:
      return checkSig(vm, code === OP.OP_CHECKSIGVERIFY);
    case OP.OP_CHECKMULTISIG:
    case OP.OP_CHECKMULTISIGVERIFY:
      return checkMultisig(vm, code === OP.OP_CHECKMULTISIGVERIFY);
    /* node:coverage ignore next 2 */
    default:
      return { ok: false, reason: `unhandled whitelisted opcode 0x${code.toString(16)}` };
  }
}

function binNum(vm: Vm, code: number): EvalResult {
  const b = pop(vm);
  const a = pop(vm);
  if (a === null || b === null) return { ok: false, reason: 'numeric: <2' };
  const na = decodeNum(a, vm.limits.maxNumBytes);
  const nb = decodeNum(b, vm.limits.maxNumBytes);
  if (!na.ok) return na;
  if (!nb.ok) return nb;
  let r: bigint;
  if (code === OP.OP_ADD) r = na.n + nb.n;
  else if (code === OP.OP_SUB) r = na.n - nb.n;
  else if (code === OP.OP_LESSTHAN) r = na.n < nb.n ? 1n : 0n;
  else r = na.n > nb.n ? 1n : 0n;
  vm.stack.push(encodeNum(r));
  return capStack(vm);
}

function hashOp(vm: Vm, h: (b: Uint8Array) => Uint8Array): EvalResult {
  const v = pop(vm);
  if (v === null) return { ok: false, reason: 'hash: empty' };
  vm.stack.push(h(v));
  return capStack(vm);
}

function checkSig(vm: Vm, verify: boolean): EvalResult {
  const pub = pop(vm);
  const sig = pop(vm);
  if (pub === null || sig === null) return { ok: false, reason: 'CHECKSIG: <2' };
  const ok = sig.length > 0 && vm.checker.check(sig, pub);
  if (verify) return ok ? { ok: true } : { ok: false, reason: 'CHECKSIGVERIFY failed' };
  vm.stack.push(ok ? encodeNum(1n) : new Uint8Array(0));
  return { ok: true };
}

function checkMultisig(vm: Vm, verify: boolean): EvalResult {
  const nKey = popCount(vm, 'pubkey count');
  if (!nKey.ok) return nKey;
  const keys: Uint8Array[] = [];
  for (let i = 0; i < nKey.n; i++) {
    const k = pop(vm);
    if (k === null) return { ok: false, reason: 'CHECKMULTISIG: missing pubkey' };
    keys.push(k);
  }
  const nSig = popCount(vm, 'sig count');
  if (!nSig.ok) return nSig;
  if (nSig.n > nKey.n) return { ok: false, reason: 'more sigs than keys' };
  const sigs: Uint8Array[] = [];
  for (let i = 0; i < nSig.n; i++) {
    const s = pop(vm);
    if (s === null) return { ok: false, reason: 'CHECKMULTISIG: missing sig' };
    sigs.push(s);
  }
  if (pop(vm) === null) return { ok: false, reason: 'CHECKMULTISIG: missing dummy' }; // Satoshi off-by-one
  // sigs and keys must match in order (each sig consumes keys left-to-right)
  let ki = 0;
  let matched = 0;
  for (const sig of sigs) {
    while (ki < keys.length && !vm.checker.check(sig, keys[ki]!)) ki++;
    if (ki < keys.length) {
      matched++;
      ki++;
    }
  }
  const ok = matched === sigs.length;
  if (verify) return ok ? { ok: true } : { ok: false, reason: 'CHECKMULTISIGVERIFY failed' };
  vm.stack.push(ok ? encodeNum(1n) : new Uint8Array(0));
  return capStack(vm);
}

function popCount(vm: Vm, what: string): { ok: true; n: number } | { ok: false; reason: string } {
  const v = pop(vm);
  if (v === null) return { ok: false, reason: `${what}: empty` };
  const d = decodeNum(v, vm.limits.maxNumBytes);
  if (!d.ok) return d;
  if (d.n < 0n || d.n > 20n) return { ok: false, reason: `${what} out of range 0..20` };
  return { ok: true, n: Number(d.n) };
}

export { encodeNum, decodeNum, castToBool };
