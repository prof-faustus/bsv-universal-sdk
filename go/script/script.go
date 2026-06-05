// Package script is the independent Go implementation of the bounded BSV Script interpreter
// (REQ-TEST-003 extended to the value layer). It MUST agree with @bsv-universal/script on accept/
// reject for every script. OP_CHECKSIG defers to an injected checker so the differential exercises
// interpreter LOGIC deterministically (signature crypto is each side's audited library).
package script

import (
	"crypto/sha256"
	"math/big"
)

const (
	opPushData1 = 0x4c
	opPushData2 = 0x4d
	opPushData4 = 0x4e
	op0         = 0x00
	op1Negate   = 0x4f
	op1         = 0x51
	op16        = 0x60
	opIf        = 0x63
	opNotIf     = 0x64
	opElse      = 0x67
	opEndIf     = 0x68
	opVerify    = 0x69
	opToAlt     = 0x6b
	opFromAlt   = 0x6c
	opDrop      = 0x75
	opDup       = 0x76
	opDepth     = 0x74
	opSwap      = 0x7c
	opEqual     = 0x87
	opEqualVfy  = 0x88
	opAdd       = 0x93
	opSub       = 0x94
	opLessThan  = 0x9f
	opGreater   = 0xa0
	opSha256    = 0xa8
	opHash160   = 0xa9
	opHash256   = 0xaa
	opCheckSig  = 0xac
	opCheckSigV = 0xad
)

var banned = map[byte]string{0x6a: "OP_RETURN", 0xb1: "CLTV", 0xb2: "CSV"}

var whitelist = map[byte]bool{
	op1Negate: true, opIf: true, opNotIf: true, opElse: true, opEndIf: true, opVerify: true,
	opToAlt: true, opFromAlt: true, opDrop: true, opDup: true, opDepth: true, opSwap: true,
	opEqual: true, opEqualVfy: true, opAdd: true, opSub: true, opLessThan: true, opGreater: true,
	opSha256: true, opHash160: true, opHash256: true, opCheckSig: true, opCheckSigV: true,
}

type Limits struct {
	MaxScriptBytes, MaxOps, MaxStack, MaxElement, MaxNumBytes int
}

func Default() Limits {
	return Limits{MaxScriptBytes: 10000, MaxOps: 20000, MaxStack: 1000, MaxElement: 520, MaxNumBytes: 4}
}

type op struct {
	isPush bool
	data   []byte
	code   byte
}

// Checker verifies a (sig, pubkey) pair.
type Checker func(sig, pub []byte) bool

func parse(b []byte, lim Limits) ([]op, bool, string) {
	if len(b) > lim.MaxScriptBytes {
		return nil, false, "script too large"
	}
	var ops []op
	i := 0
	for i < len(b) {
		c := b[i]
		i++
		switch {
		case c >= 0x01 && c <= 0x4b:
			d, ni, ok := take(b, i, int(c), lim)
			if !ok {
				return nil, false, "truncated push"
			}
			ops = append(ops, op{isPush: true, data: d})
			i = ni
		case c == opPushData1 || c == opPushData2 || c == opPushData4:
			szl := 1
			if c == opPushData2 {
				szl = 2
			} else if c == opPushData4 {
				szl = 4
			}
			ln, ok := readLE(b, i, szl)
			if !ok {
				return nil, false, "truncated pushdata len"
			}
			i += szl
			d, ni, ok := take(b, i, ln, lim)
			if !ok {
				return nil, false, "truncated pushdata"
			}
			ops = append(ops, op{isPush: true, data: d})
			i = ni
		default:
			if _, bad := banned[c]; bad {
				return nil, false, "banned opcode"
			}
			ops = append(ops, op{code: c})
		}
		if len(ops) > lim.MaxOps {
			return nil, false, "too many ops"
		}
	}
	return ops, true, ""
}

func take(b []byte, start, n int, lim Limits) ([]byte, int, bool) {
	if n > lim.MaxElement || start+n > len(b) {
		return nil, 0, false
	}
	return b[start : start+n], start + n, true
}
func readLE(b []byte, start, n int) (int, bool) {
	if start+n > len(b) {
		return 0, false
	}
	v := 0
	for k := 0; k < n; k++ {
		v += int(b[start+k]) << (8 * k)
	}
	return v, true
}

type vm struct {
	stack [][]byte
	alt   [][]byte
	vf    []bool
	ops   int
	lim   Limits
	chk   Checker
}

func castBool(v []byte) bool {
	for i, b := range v {
		if b != 0 {
			if i == len(v)-1 && b == 0x80 {
				return false
			}
			return true
		}
	}
	return false
}

func decodeNum(v []byte, max int) (*big.Int, bool) {
	if len(v) > max {
		return nil, false
	}
	if len(v) == 0 {
		return big.NewInt(0), true
	}
	if v[len(v)-1]&0x7f == 0 && (len(v) <= 1 || v[len(v)-2]&0x80 == 0) {
		return nil, false // non-minimal
	}
	r := big.NewInt(0)
	for i := 0; i < len(v); i++ {
		r.Or(r, new(big.Int).Lsh(big.NewInt(int64(v[i])), uint(8*i)))
	}
	neg := v[len(v)-1]&0x80 != 0
	if neg {
		mask := new(big.Int).Lsh(big.NewInt(0x80), uint(8*(len(v)-1)))
		r.AndNot(r, mask)
		r.Neg(r)
	}
	return r, true
}

func encodeNum(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{}
	}
	neg := n.Sign() < 0
	abs := new(big.Int).Abs(n)
	var out []byte
	for abs.Sign() > 0 {
		out = append(out, byte(new(big.Int).And(abs, big.NewInt(0xff)).Int64()))
		abs.Rsh(abs, 8)
	}
	if out[len(out)-1]&0x80 != 0 {
		if neg {
			out = append(out, 0x80)
		} else {
			out = append(out, 0x00)
		}
	} else if neg {
		out[len(out)-1] |= 0x80
	}
	return out
}

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func hash256(b []byte) []byte { return sha(sha(b)) }
func hash160(b []byte) []byte { return ripemd160Sum(sha(b)) }

// Eval mirrors evalScript: push-only unlocking, then locking; ok iff single truthy top.
func Eval(unlocking, locking []byte, chk Checker, lim Limits) (bool, string) {
	u, ok, reason := parse(unlocking, lim)
	if !ok {
		return false, "unlocking: " + reason
	}
	for _, o := range u {
		if !pushOnly(o) {
			return false, "unlocking must be push-only"
		}
	}
	l, ok, reason := parse(locking, lim)
	if !ok {
		return false, "locking: " + reason
	}
	m := &vm{lim: lim, chk: chk}
	for _, o := range u {
		if ok, r := step(m, o); !ok {
			return false, r
		}
	}
	for _, o := range l {
		if ok, r := step(m, o); !ok {
			return false, r
		}
	}
	if len(m.vf) != 0 {
		return false, "unbalanced conditional"
	}
	if len(m.stack) == 0 {
		return false, "empty stack"
	}
	if !castBool(m.stack[len(m.stack)-1]) {
		return false, "false top"
	}
	return true, ""
}

func pushOnly(o op) bool {
	if o.isPush {
		return true
	}
	return o.code == op0 || o.code == op1Negate || (o.code >= op1 && o.code <= op16)
}
func executing(m *vm) bool {
	for _, f := range m.vf {
		if !f {
			return false
		}
	}
	return true
}
func capStack(m *vm) (bool, string) {
	if len(m.stack)+len(m.alt) > m.lim.MaxStack {
		return false, "stack overflow"
	}
	return true, ""
}
func pop(m *vm) ([]byte, bool) {
	if len(m.stack) == 0 {
		return nil, false
	}
	v := m.stack[len(m.stack)-1]
	m.stack = m.stack[:len(m.stack)-1]
	return v, true
}

func step(m *vm, o op) (bool, string) {
	fexec := executing(m)
	if o.isPush {
		if fexec {
			if len(o.data) > m.lim.MaxElement {
				return false, "push too big"
			}
			m.stack = append(m.stack, o.data)
			return capStack(m)
		}
		return true, ""
	}
	c := o.code
	if c == opIf || c == opNotIf {
		val := false
		if fexec {
			v, ok := pop(m)
			if !ok {
				return false, "IF empty"
			}
			val = castBool(v)
			if c == opNotIf {
				val = !val
			}
		}
		m.vf = append(m.vf, val)
		return true, ""
	}
	if c == opElse {
		if len(m.vf) == 0 {
			return false, "ELSE without IF"
		}
		m.vf[len(m.vf)-1] = !m.vf[len(m.vf)-1]
		return true, ""
	}
	if c == opEndIf {
		if len(m.vf) == 0 {
			return false, "ENDIF without IF"
		}
		m.vf = m.vf[:len(m.vf)-1]
		return true, ""
	}
	if !fexec {
		return true, ""
	}
	if _, bad := banned[c]; bad {
		return false, "banned opcode"
	}
	if c == op0 {
		m.stack = append(m.stack, []byte{})
		return capStack(m)
	}
	if c == op1Negate {
		m.stack = append(m.stack, encodeNum(big.NewInt(-1)))
		return capStack(m)
	}
	if c >= op1 && c <= op16 {
		m.stack = append(m.stack, encodeNum(big.NewInt(int64(c-(op1-1)))))
		return capStack(m)
	}
	if !whitelist[c] {
		return false, "not in whitelist"
	}
	m.ops++
	if m.ops > m.lim.MaxOps {
		return false, "op count exceeded"
	}
	return dispatch(m, c)
}

func dispatch(m *vm, c byte) (bool, string) {
	switch c {
	case opDrop:
		if _, ok := pop(m); !ok {
			return false, "DROP empty"
		}
		return true, ""
	case opDup:
		if len(m.stack) == 0 {
			return false, "DUP empty"
		}
		m.stack = append(m.stack, m.stack[len(m.stack)-1])
		return capStack(m)
	case opDepth:
		m.stack = append(m.stack, encodeNum(big.NewInt(int64(len(m.stack)))))
		return capStack(m)
	case opSwap:
		if len(m.stack) < 2 {
			return false, "SWAP <2"
		}
		n := len(m.stack)
		m.stack[n-1], m.stack[n-2] = m.stack[n-2], m.stack[n-1]
		return true, ""
	case opToAlt:
		v, ok := pop(m)
		if !ok {
			return false, "TOALT empty"
		}
		m.alt = append(m.alt, v)
		return true, ""
	case opFromAlt:
		if len(m.alt) == 0 {
			return false, "FROMALT empty"
		}
		m.stack = append(m.stack, m.alt[len(m.alt)-1])
		m.alt = m.alt[:len(m.alt)-1]
		return capStack(m)
	case opEqual, opEqualVfy:
		b, ok1 := pop(m)
		a, ok2 := pop(m)
		if !ok1 || !ok2 {
			return false, "EQUAL <2"
		}
		eq := bytesEq(a, b)
		if c == opEqualVfy {
			if eq {
				return true, ""
			}
			return false, "EQUALVERIFY failed"
		}
		if eq {
			m.stack = append(m.stack, encodeNum(big.NewInt(1)))
		} else {
			m.stack = append(m.stack, []byte{})
		}
		return true, ""
	case opVerify:
		v, ok := pop(m)
		if !ok {
			return false, "VERIFY empty"
		}
		if castBool(v) {
			return true, ""
		}
		return false, "VERIFY failed"
	case opAdd, opSub, opLessThan, opGreater:
		return binNum(m, c)
	case opSha256:
		return hashOp(m, sha)
	case opHash160:
		return hashOp(m, hash160)
	case opHash256:
		return hashOp(m, hash256)
	case opCheckSig, opCheckSigV:
		pub, ok1 := pop(m)
		sig, ok2 := pop(m)
		if !ok1 || !ok2 {
			return false, "CHECKSIG <2"
		}
		good := len(sig) > 0 && m.chk(sig, pub)
		if c == opCheckSigV {
			if good {
				return true, ""
			}
			return false, "CHECKSIGVERIFY failed"
		}
		if good {
			m.stack = append(m.stack, encodeNum(big.NewInt(1)))
		} else {
			m.stack = append(m.stack, []byte{})
		}
		return true, ""
	default:
		return false, "unhandled"
	}
}

func binNum(m *vm, c byte) (bool, string) {
	bb, ok1 := pop(m)
	aa, ok2 := pop(m)
	if !ok1 || !ok2 {
		return false, "num <2"
	}
	a, ok3 := decodeNum(aa, m.lim.MaxNumBytes)
	b, ok4 := decodeNum(bb, m.lim.MaxNumBytes)
	if !ok3 || !ok4 {
		return false, "bad num"
	}
	var r *big.Int
	switch c {
	case opAdd:
		r = new(big.Int).Add(a, b)
	case opSub:
		r = new(big.Int).Sub(a, b)
	case opLessThan:
		r = boolNum(a.Cmp(b) < 0)
	default:
		r = boolNum(a.Cmp(b) > 0)
	}
	m.stack = append(m.stack, encodeNum(r))
	return capStack(m)
}
func boolNum(b bool) *big.Int {
	if b {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}
func hashOp(m *vm, h func([]byte) []byte) (bool, string) {
	v, ok := pop(m)
	if !ok {
		return false, "hash empty"
	}
	m.stack = append(m.stack, h(v))
	return capStack(m)
}
func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
