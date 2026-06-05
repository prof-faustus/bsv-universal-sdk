// Generates the VALUE-LAYER differential corpus (REQ-TEST-003 extended): script-eval results, txids,
// sighashes, value-conservation checks, and covenant-spend checks — all computed by the TS
// implementation. The Go implementation must reproduce every one byte-for-byte / boolean-for-boolean.
// OP_CHECKSIG uses a deterministic stub checker shared with the Go side (interpreter logic, not crypto).

import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';
import { evalScript, OP, type SigChecker } from '@bsv-universal/script';
import {
  serializeTx, txid, sighash, verifyTxValue, p2pkhLockingFromPkh, covenantOutput, verifyCovenantSpend,
  type Tx,
} from '@bsv-universal/tx';
import { toHex } from '@bsv-universal/protocol-types';
import { genKeyPair, partyId, commit as commitSecret, verifyBeaconRound, ZERO_BEACON, signData, verifyData, signBitcoin, verifyBitcoin, type BeaconRound } from '@bsv-universal/crypto';

// shared stub checker: accept iff non-empty sig & pub and sig[0] === pub[0]
const STUB: SigChecker = { check: (sig, pub) => sig.length > 0 && pub.length > 0 && sig[0] === pub[0] };
function stubName(): string { return 'sig0==pub0'; }

const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const ripemd = (b: Uint8Array) => new Uint8Array(createHash('ripemd160').update(b).digest());
const B = (...n: number[]) => new Uint8Array(n);
const push = (d: number[]) => [d.length, ...d];
const cat = (...a: number[][]) => new Uint8Array(a.flat());

// ---- script vectors -------------------------------------------------------------------------
interface ScriptVec { u: string; l: string; ok: boolean }
const scriptVecs: ScriptVec[] = [];
function sv(u: Uint8Array, l: Uint8Array) {
  const r = evalScript(u, l, STUB);
  scriptVecs.push({ u: toHex(u), l: toHex(l), ok: r.ok });
}
{
  const data = [0xde, 0xad, 0xbe, 0xef];
  sv(B(...push(data)), B(...push(data), OP.OP_EQUAL)); // equal → true
  sv(B(...push([0x01])), B(...push([0x02]), OP.OP_EQUAL)); // unequal → false
  sv(B(), B(OP.OP_1, OP.OP_1, OP.OP_ADD, OP.OP_1 + 1, OP.OP_EQUAL)); // 1+1==2 → true
  sv(B(OP.OP_1), B(OP.OP_IF, OP.OP_1, OP.OP_ELSE, OP.OP_0, OP.OP_ENDIF)); // branch true
  sv(B(OP.OP_0), B(OP.OP_IF, OP.OP_1, OP.OP_ELSE, OP.OP_0, OP.OP_ENDIF)); // branch false
  sv(B(...push(data)), cat(push(data), [OP.OP_SHA256], push([...sha(B(...data))]), [OP.OP_EQUAL])); // sha256 parity
  sv(B(...push(data)), cat(push(data), [OP.OP_HASH256], push([...sha(sha(B(...data)))]), [OP.OP_EQUAL])); // hash256
  sv(B(...push(data)), cat(push(data), [OP.OP_HASH160], push([...ripemd(sha(B(...data)))]), [OP.OP_EQUAL])); // hash160 → tests Go RIPEMD160
  sv(B(...push([0x07, 0xff]), ...push([0x07, 0x01])), B(OP.OP_CHECKSIG)); // stub: sig0==pub0 (07==07) → true
  sv(B(...push([0x07, 0xff]), ...push([0x09, 0x01])), B(OP.OP_CHECKSIG)); // stub: 07!=09 → false
  sv(B(...push([0x01])), B(0x6a)); // 0x6a data-carrier byte → parse-reject → false
  sv(B(...push([0x01])), B(0xa6)); // non-whitelisted opcode → false
  sv(B(OP.OP_DUP), B(OP.OP_1)); // unlocking not push-only → false
  sv(B(), B()); // empty → false
  sv(B(), B(OP.OP_DUP)); // DUP underflow → false
  sv(B(OP.OP_1), B(OP.OP_IF, OP.OP_1)); // missing ENDIF → false
}

// ---- tx helpers -----------------------------------------------------------------------------
function txJson(tx: Tx) {
  return {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({ txid: toHex(i.outpoint.txid), vout: i.outpoint.vout, unlockingScript: toHex(i.unlockingScript), sequence: i.sequence })),
    outputs: tx.outputs.map((o) => ({ satoshis: o.satoshis.toString(), lockingScript: toHex(o.lockingScript) })),
    lockTime: tx.lockTime,
  };
}
function mkTx(seed: number): Tx {
  const nIn = 1 + (seed % 3);
  const nOut = 1 + ((seed >> 2) % 3);
  return {
    version: 1 + (seed % 2),
    inputs: Array.from({ length: nIn }, () => ({ outpoint: { txid: new Uint8Array(randomBytes(32)), vout: randomBytes(1)[0]! }, unlockingScript: new Uint8Array(randomBytes(randomBytes(1)[0]! % 20)), sequence: 0xffffffff })),
    outputs: Array.from({ length: nOut }, () => ({ satoshis: BigInt(100 + (randomBytes(2).readUInt16BE(0))), lockingScript: new Uint8Array(randomBytes(1 + randomBytes(1)[0]! % 24)) })),
    lockTime: 0,
  };
}

// ---- txid + sighash vectors -----------------------------------------------------------------
const txidVecs: { tx: ReturnType<typeof txJson>; txid: string }[] = [];
const sighashVecs: { tx: ReturnType<typeof txJson>; index: number; prevScript: string; amount: string; sighash: string }[] = [];
for (let s = 0; s < 30; s++) {
  const tx = mkTx(s);
  txidVecs.push({ tx: txJson(tx), txid: toHex(txid(tx)) });
  const prevScript = s % 2 === 0 ? p2pkhLockingFromPkh(new Uint8Array(randomBytes(20))) : covenantOutput(BigInt(1000 + s), sha(B(s))).lockingScript;
  const amount = BigInt(500 + s * 7);
  sighashVecs.push({ tx: txJson(tx), index: 0, prevScript: toHex(prevScript), amount: amount.toString(), sighash: toHex(sighash(tx, 0, prevScript, amount)) });
}

// ---- value-conservation vectors -------------------------------------------------------------
const valueVecs: { tx: ReturnType<typeof txJson>; prevAmounts: string[]; fee: string; ok: boolean }[] = [];
for (let s = 0; s < 20; s++) {
  const tx = mkTx(s + 100);
  const outSum = tx.outputs.reduce((a, o) => a + o.satoshis, 0n);
  const fee = BigInt(s);
  // half the time make it conserve exactly, half the time not
  const conserve = s % 2 === 0;
  const prevAmounts = tx.inputs.map((_, i) => (i === 0 ? (conserve ? outSum + fee : outSum + fee + 1n) : 0n));
  const r = verifyTxValue(tx, prevAmounts, fee);
  valueVecs.push({ tx: txJson(tx), prevAmounts: prevAmounts.map((x) => x.toString()), fee: fee.toString(), ok: r.ok });
}

// ---- covenant vectors -----------------------------------------------------------------------
const covVecs: { reserve: string; rulesHash: string; prevTxid: string; prevVout: number; prevScript: string; tx: ReturnType<typeof txJson>; recipientPkh: string; amount: string; ok: boolean }[] = [];
for (let s = 0; s < 16; s++) {
  const reserve = BigInt(1000 + s * 13);
  const rulesHash = sha(B(s, 0xaa));
  const prevOutpoint = { txid: new Uint8Array(randomBytes(32)), vout: 0 };
  const prevScript = covenantOutput(reserve, rulesHash).lockingScript;
  const recipientPkh = new Uint8Array(randomBytes(20));
  const amount = BigInt(100 + s);
  // build a spend; introduce defects for some indices
  let tx: Tx = {
    version: 1,
    inputs: [{ outpoint: prevOutpoint, unlockingScript: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [
      { satoshis: amount, lockingScript: p2pkhLockingFromPkh(recipientPkh) },
      covenantOutput(reserve - amount, rulesHash),
    ],
    lockTime: 0,
  };
  let usePrevScript = prevScript;
  let useOutpoint = prevOutpoint;
  if (s % 4 === 1) useOutpoint = { txid: new Uint8Array(randomBytes(32)), vout: 0 }; // wrong outpoint
  if (s % 4 === 2) usePrevScript = covenantOutput(reserve, sha(B(s, 0xbb))).lockingScript; // wrong rules
  if (s % 4 === 3) tx = { ...tx, outputs: [{ satoshis: amount + 1n, lockingScript: p2pkhLockingFromPkh(recipientPkh) }, tx.outputs[1]!] }; // wrong amount
  const r = verifyCovenantSpend({ reserve, rulesHash }, useOutpoint, usePrevScript, tx, recipientPkh, amount);
  covVecs.push({ reserve: reserve.toString(), rulesHash: toHex(rulesHash), prevTxid: toHex(useOutpoint.txid), prevVout: useOutpoint.vout, prevScript: toHex(usePrevScript), tx: txJson(tx), recipientPkh: toHex(recipientPkh), amount: amount.toString(), ok: r.ok });
}

// ---- beacon (fairness) vectors: commit→reveal verification + seed derivation (REQ-SEC-002/003) ----
interface BeaconVec {
  commits: { party: string; commitment: string }[];
  reveals: { party: string; secret: string }[];
  eligible: string[];
  roundNo: number;
  prevBeacon: string;
  ok: boolean;
  seed: string;
}
const beaconVecs: BeaconVec[] = [];
function pid(_seed: number): Uint8Array {
  return partyId(genKeyPair().pub); // CSPRNG key → always a valid scalar; opaque to the corpus
}
function recordBeacon(round: BeaconRound, eligible: Uint8Array[]) {
  const r = verifyBeaconRound(round, eligible);
  beaconVecs.push({
    commits: round.commits.map((c) => ({ party: toHex(c.party), commitment: toHex(c.commitment) })),
    reveals: round.reveals.map((rv) => ({ party: toHex(rv.party), secret: toHex(rv.secret) })),
    eligible: eligible.map(toHex),
    roundNo: round.roundNo,
    prevBeacon: toHex(round.prevBeacon),
    ok: r.ok,
    seed: r.ok ? toHex(r.seed) : '',
  });
}
for (let s = 0; s < 24; s++) {
  const n = 2 + (s % 4);
  const ids = Array.from({ length: n }, (_, i) => pid(i + 1 + s * 11));
  const secrets = ids.map((_, i) => new Uint8Array(randomBytes(32)));
  const base: BeaconRound = {
    roundNo: 1 + s,
    commits: ids.map((id, i) => ({ party: id, commitment: commitSecret(secrets[i]!) })),
    reveals: ids.map((id, i) => ({ party: id, secret: secrets[i]! })),
    prevBeacon: ZERO_BEACON,
  };
  switch (s % 6) {
    case 0:
      recordBeacon(base, ids); // valid
      break;
    case 1:
      recordBeacon({ ...base, reveals: [...base.reveals, { party: pid(999), secret: new Uint8Array(randomBytes(32)) }] }, ids); // fake non-seat reveal
      break;
    case 2:
      recordBeacon({ ...base, commits: [base.commits[0]!, base.commits[0]!, ...base.commits.slice(1)] }, ids); // dup commit
      break;
    case 3:
      recordBeacon({ ...base, reveals: [base.reveals[0]!, base.reveals[0]!, ...base.reveals.slice(1)] }, ids); // dup reveal
      break;
    case 4:
      recordBeacon({ ...base, reveals: [{ party: ids[0]!, secret: new Uint8Array(randomBytes(32)) }, ...base.reveals.slice(1)] }, ids); // bad secret
      break;
    default:
      recordBeacon({ ...base, reveals: [] }, ids); // zero honest
      break;
  }
}

// ---- auth (signature) vectors: ECDSA verification parity (REQ-SEC-001) ----------------------
// TS signs with @noble; the self-contained Go secp256k1 verifier must agree on accept/reject across
// valid + adversarial (wrong key / tampered message / random sig) cases.
interface AuthVec { kind: 'data' | 'bitcoin'; msg: string; der: string; pub: string; ok: boolean }
const authVecs: AuthVec[] = [];
for (let s = 0; s < 24; s++) {
  const kp = genKeyPair();
  const other = genKeyPair();
  const msg = new Uint8Array(randomBytes(8 + (s % 40)));
  if (s % 2 === 0) {
    const der = signData(msg, kp);
    switch (s % 6) {
      case 0: authVecs.push({ kind: 'data', msg: toHex(msg), der: toHex(der), pub: toHex(kp.pub), ok: verifyData(msg, der, kp.pub) }); break; // valid
      case 2: authVecs.push({ kind: 'data', msg: toHex(msg), der: toHex(der), pub: toHex(other.pub), ok: verifyData(msg, der, other.pub) }); break; // wrong key
      default: {
        const bad = new Uint8Array(msg); bad[0] = (bad[0] ?? 0) ^ 0xff;
        authVecs.push({ kind: 'data', msg: toHex(bad), der: toHex(der), pub: toHex(kp.pub), ok: verifyData(bad, der, kp.pub) }); // tampered msg
      }
    }
  } else {
    const pre = new Uint8Array(randomBytes(40 + (s % 20)));
    const der = signBitcoin(pre, kp);
    switch (s % 6) {
      case 1: authVecs.push({ kind: 'bitcoin', msg: toHex(pre), der: toHex(der), pub: toHex(kp.pub), ok: verifyBitcoin(pre, der, kp.pub) }); break; // valid
      case 3: { const rnd = new Uint8Array(randomBytes(70)); authVecs.push({ kind: 'bitcoin', msg: toHex(pre), der: toHex(rnd), pub: toHex(kp.pub), ok: verifyBitcoin(pre, rnd, kp.pub) }); break; } // random der
      default: authVecs.push({ kind: 'bitcoin', msg: toHex(pre), der: toHex(der), pub: toHex(other.pub), ok: verifyBitcoin(pre, der, other.pub) }); // wrong key
    }
  }
}

const out = { version: 1, stub: stubName(), scriptVecs, txidVecs, sighashVecs, valueVecs, covVecs, beaconVecs, authVecs };
const outDir = fileURLToPath(new URL('../../go/', import.meta.url));
mkdirSync(outDir, { recursive: true });
writeFileSync(outDir + 'value-vectors.json', JSON.stringify(out));
console.log(`wrote value vectors: ${scriptVecs.length} script, ${txidVecs.length} txid, ${sighashVecs.length} sighash, ${valueVecs.length} value, ${covVecs.length} covenant, ${beaconVecs.length} beacon, ${authVecs.length} auth`);
void serializeTx;
