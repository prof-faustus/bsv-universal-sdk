// Branch-completion battery for the Script interpreter (REQ-TEST-010). Exercises every opcode and
// every error branch — including OP_CHECKMULTISIG, which the prior suites did not cover.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evalScript, parseScript, DEFAULT_LIMITS, OP, type SigChecker } from '../src/index.ts';

const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const rmd = (b: Uint8Array) => new Uint8Array(createHash('ripemd160').update(b).digest());

const ACCEPT: SigChecker = { check: () => true };
const REJECT: SigChecker = { check: () => false };
// stub: a sig matches a pubkey iff their first bytes are equal
const FIRSTBYTE: SigChecker = { check: (s, p) => s.length > 0 && p.length > 0 && s[0] === p[0] };
const B = (...n: number[]) => new Uint8Array(n);
const push = (d: number[]) => [d.length, ...d];

test('stack ops: DEPTH, SWAP, TOALTSTACK/FROMALTSTACK, DROP', () => {
  assert.equal(evalScript(B(...push([1]), ...push([2])), B(OP.OP_DEPTH, OP.OP_1 + 1, OP.OP_EQUAL), ACCEPT).ok, true); // depth==2
  assert.equal(evalScript(B(...push([0xaa]), ...push([0xbb])), B(OP.OP_SWAP, ...push([0xaa]), OP.OP_EQUAL), ACCEPT).ok, true);
  assert.equal(evalScript(B(...push([0x05])), B(OP.OP_TOALTSTACK, OP.OP_FROMALTSTACK, ...push([0x05]), OP.OP_EQUAL), ACCEPT).ok, true);
  assert.equal(evalScript(B(...push([1]), ...push([2])), B(OP.OP_DROP, ...push([1]), OP.OP_EQUAL), ACCEPT).ok, true);
});

test('stack underflows fail closed', () => {
  for (const code of [OP.OP_SWAP, OP.OP_TOALTSTACK, OP.OP_FROMALTSTACK, OP.OP_VERIFY, OP.OP_ADD]) {
    assert.equal(evalScript(B(), B(code), ACCEPT).ok, false);
  }
  assert.equal(evalScript(B(...push([1])), B(OP.OP_ADD), ACCEPT).ok, false); // ADD with one operand
});

test('numeric: SUB, LESSTHAN, GREATERTHAN, 1NEGATE; non-minimal & too-long rejected', () => {
  assert.equal(evalScript(B(), B(OP.OP_1 + 2, OP.OP_1, OP.OP_SUB, OP.OP_1 + 1, OP.OP_EQUAL), ACCEPT).ok, true); // 3-1==2
  assert.equal(evalScript(B(), B(OP.OP_1, OP.OP_1 + 1, OP.OP_LESSTHAN), ACCEPT).ok, true); // 1<2
  assert.equal(evalScript(B(), B(OP.OP_1 + 1, OP.OP_1, OP.OP_GREATERTHAN), ACCEPT).ok, true); // 2>1
  assert.equal(evalScript(B(), B(OP.OP_1NEGATE, OP.OP_1NEGATE, OP.OP_EQUAL), ACCEPT).ok, true);
  // non-minimal number (0x00) as operand → reject
  assert.equal(evalScript(B(...push([0x00])), B(...push([0x01]), OP.OP_ADD), ACCEPT).ok, false);
  // number too long (5 bytes > maxNumBytes 4)
  assert.equal(evalScript(B(...push([1, 2, 3, 4, 5])), B(...push([1]), OP.OP_ADD), ACCEPT).ok, false);
});

test('branch: NOTIF, nested IF, ELSE/ENDIF errors', () => {
  assert.equal(evalScript(B(OP.OP_0), B(OP.OP_NOTIF, OP.OP_1, OP.OP_ENDIF), ACCEPT).ok, true); // NOTIF on false → run
  assert.equal(evalScript(B(OP.OP_1), B(OP.OP_IF, OP.OP_1, OP.OP_IF, OP.OP_1, OP.OP_ENDIF, OP.OP_ENDIF), ACCEPT).ok, true); // nested
  assert.equal(evalScript(B(), B(OP.OP_ELSE), ACCEPT).ok, false); // ELSE without IF
  assert.equal(evalScript(B(), B(OP.OP_IF), ACCEPT).ok, false); // IF empty stack
});

test('VERIFY and EQUALVERIFY failure branches', () => {
  assert.equal(evalScript(B(OP.OP_0), B(OP.OP_VERIFY, OP.OP_1), ACCEPT).ok, false); // VERIFY false
  assert.equal(evalScript(B(...push([1])), B(...push([2]), OP.OP_EQUALVERIFY, OP.OP_1), ACCEPT).ok, false); // EQUALVERIFY fail
});

test('CHECKSIGVERIFY both branches', () => {
  assert.equal(evalScript(B(...push([1]), ...push([1])), B(OP.OP_CHECKSIGVERIFY, OP.OP_1), ACCEPT).ok, true);
  assert.equal(evalScript(B(...push([1]), ...push([1])), B(OP.OP_CHECKSIGVERIFY, OP.OP_1), REJECT).ok, false);
});

test('CHECKMULTISIG: 2-of-3 pass, fail, and VERIFY variant', () => {
  const pub1 = push([0x01, 0xaa]);
  const pub2 = push([0x02, 0xbb]);
  const pub3 = push([0x03, 0xcc]);
  const sig1 = push([0x01, 0x11]);
  const sig2 = push([0x02, 0x22]);
  const dummy = push([0x00]);
  // stack (bottom→top): dummy, sig1, sig2, m=2, pub1,pub2,pub3, n=3, CHECKMULTISIG
  const u = B(...dummy, ...sig1, ...sig2);
  const lOk = B(OP.OP_1 + 1, ...pub1, ...pub2, ...pub3, OP.OP_1 + 2, OP.OP_CHECKMULTISIG);
  assert.equal(evalScript(u, lOk, FIRSTBYTE).ok, true);
  // sigs that match no pubkey → fail
  const badU = B(...dummy, ...push([0x09, 0x11]), ...push([0x08, 0x22]));
  assert.equal(evalScript(badU, lOk, FIRSTBYTE).ok, false);
  // VERIFY variant success
  const lVfy = B(OP.OP_1 + 1, ...pub1, ...pub2, ...pub3, OP.OP_1 + 2, OP.OP_CHECKMULTISIGVERIFY, OP.OP_1);
  assert.equal(evalScript(u, lVfy, FIRSTBYTE).ok, true);
});

test('CHECKMULTISIG malformed: too many sigs, out-of-range counts, underflow', () => {
  // nSig=2 but nKey=1 → "more sigs than keys". Stack bottom→top: dummy, sig1, sig2, 2, pub1, 1
  const l = B(OP.OP_1 + 1, ...push([0x01]), OP.OP_1, OP.OP_CHECKMULTISIG);
  const u = B(...push([0x00]), ...push([0x01]), ...push([0x02]));
  assert.equal(evalScript(u, l, FIRSTBYTE).ok, false);
  // count out of range (push 21) → reject
  assert.equal(evalScript(B(), B(...push([21]), OP.OP_CHECKMULTISIG), FIRSTBYTE).ok, false);
  // empty stack → reject
  assert.equal(evalScript(B(), B(OP.OP_CHECKMULTISIG), FIRSTBYTE).ok, false);
});

test('hash ops: SHA256, HASH160, HASH256 compute correctly; empty-stack rejected', () => {
  const data = [0xde, 0xad];
  const d = new Uint8Array(data);
  assert.equal(evalScript(B(...push(data)), B(OP.OP_SHA256, ...push([...sha(d)]), OP.OP_EQUAL), ACCEPT).ok, true);
  assert.equal(evalScript(B(...push(data)), B(OP.OP_HASH160, ...push([...rmd(sha(d))]), OP.OP_EQUAL), ACCEPT).ok, true);
  assert.equal(evalScript(B(...push(data)), B(OP.OP_HASH256, ...push([...sha(sha(d))]), OP.OP_EQUAL), ACCEPT).ok, true);
  assert.equal(evalScript(B(), B(OP.OP_SHA256), ACCEPT).ok, false); // empty
});

test('parse rejects non-bytes input (defensive guard)', () => {
  const r = parseScript('not-bytes' as unknown as Uint8Array, DEFAULT_LIMITS);
  assert.equal(r.ok, false);
});

test('parse: PUSHDATA1/PUSHDATA2 and their truncations', () => {
  assert.equal(parseScript(B(OP.OP_PUSHDATA1, 0x02, 0xaa, 0xbb), DEFAULT_LIMITS).ok, true);
  assert.equal(parseScript(B(OP.OP_PUSHDATA1, 0x02, 0xaa), DEFAULT_LIMITS).ok, false); // truncated payload
  assert.equal(parseScript(B(OP.OP_PUSHDATA1), DEFAULT_LIMITS).ok, false); // truncated length
  assert.equal(parseScript(B(OP.OP_PUSHDATA2, 0x01), DEFAULT_LIMITS).ok, false); // truncated len bytes
});

test('limits: too many ops and stack overflow fail closed', () => {
  const many = new Uint8Array(Array.from({ length: 30000 }, () => OP.OP_1));
  // 30000 small-int pushes → stack overflow before op-count, but either way must reject (not crash)
  assert.equal(evalScript(B(), many, ACCEPT).ok, false);
});
