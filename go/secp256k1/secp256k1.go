// Package secp256k1 is a self-contained ECDSA verifier for secp256k1 (no external dependency).
// It exists to CROSS-CHECK @noble's signature verification (REQ-SEC-001) via the differential: TS
// signs with @noble, Go verifies here, and the accept/reject results must agree across a corpus of
// valid + adversarial signatures. Verification enforces low-s (BIP-62 / @noble default for Bitcoin).
//
// Affine arithmetic with math/big — clarity over speed; the corpus is small. Constant-timeness is not
// claimed (this is a verifier of public data, not a signer of secrets).
package secp256k1

import (
	"math/big"
)

var (
	p     = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	n     = mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	gx    = mustHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	gy    = mustHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	b     = big.NewInt(7)
	nHalf = new(big.Int).Rsh(n, 1)
)

func mustHex(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("bad const")
	}
	return v
}

// point in affine coords; (nil,nil) == point at infinity.
type point struct{ x, y *big.Int }

func inf() point { return point{nil, nil} }
func (q point) isInf() bool { return q.x == nil }

func modP(v *big.Int) *big.Int { return new(big.Int).Mod(v, p) }

func add(a1, b1 point) point {
	if a1.isInf() {
		return b1
	}
	if b1.isInf() {
		return a1
	}
	if a1.x.Cmp(b1.x) == 0 {
		if a1.y.Cmp(b1.y) != 0 || a1.y.Sign() == 0 {
			return inf()
		}
		return dbl(a1)
	}
	// lambda = (y2 - y1) / (x2 - x1)
	num := modP(new(big.Int).Sub(b1.y, a1.y))
	den := modP(new(big.Int).Sub(b1.x, a1.x))
	lam := modP(new(big.Int).Mul(num, new(big.Int).ModInverse(den, p)))
	return fromLambda(lam, a1, b1)
}

func dbl(a1 point) point {
	if a1.isInf() || a1.y.Sign() == 0 {
		return inf()
	}
	// lambda = 3x^2 / 2y   (a = 0)
	num := modP(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a1.x, a1.x)))
	den := modP(new(big.Int).Mul(big.NewInt(2), a1.y))
	lam := modP(new(big.Int).Mul(num, new(big.Int).ModInverse(den, p)))
	return fromLambda(lam, a1, a1)
}

func fromLambda(lam *big.Int, a1, b1 point) point {
	x3 := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lam, lam), a1.x), b1.x))
	y3 := modP(new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(a1.x, x3)), a1.y))
	return point{x3, y3}
}

func scalarMul(k *big.Int, q point) point {
	r := inf()
	addend := q
	kk := new(big.Int).Set(k)
	for kk.Sign() > 0 {
		if kk.Bit(0) == 1 {
			r = add(r, addend)
		}
		addend = dbl(addend)
		kk.Rsh(kk, 1)
	}
	return r
}

func onCurve(q point) bool {
	if q.isInf() {
		return false
	}
	// y^2 == x^3 + 7 (mod p)
	lhs := modP(new(big.Int).Mul(q.y, q.y))
	rhs := modP(new(big.Int).Add(new(big.Int).Mul(new(big.Int).Mul(q.x, q.x), q.x), b))
	return lhs.Cmp(rhs) == 0
}

// parsePub parses a 65-byte uncompressed public key (0x04 || X || Y).
func parsePub(pub []byte) (point, bool) {
	if len(pub) != 65 || pub[0] != 0x04 {
		return inf(), false
	}
	q := point{new(big.Int).SetBytes(pub[1:33]), new(big.Int).SetBytes(pub[33:65])}
	if q.x.Cmp(p) >= 0 || q.y.Cmp(p) >= 0 || !onCurve(q) {
		return inf(), false
	}
	return q, true
}

// parseDER extracts (r, s) from a DER ECDSA signature. Strict-ish: rejects obvious malformations.
func parseDER(sig []byte) (*big.Int, *big.Int, bool) {
	if len(sig) < 8 || sig[0] != 0x30 {
		return nil, nil, false
	}
	if int(sig[1]) != len(sig)-2 {
		return nil, nil, false
	}
	i := 2
	r, ni, ok := readInt(sig, i)
	if !ok {
		return nil, nil, false
	}
	s, nj, ok := readInt(sig, ni)
	if !ok || nj != len(sig) {
		return nil, nil, false
	}
	return r, s, true
}

func readInt(sig []byte, i int) (*big.Int, int, bool) {
	if i+2 > len(sig) || sig[i] != 0x02 {
		return nil, 0, false
	}
	l := int(sig[i+1])
	i += 2
	if l == 0 || i+l > len(sig) {
		return nil, 0, false
	}
	if sig[i]&0x80 != 0 {
		return nil, 0, false // negative (not allowed)
	}
	if l > 1 && sig[i] == 0x00 && sig[i+1]&0x80 == 0 {
		return nil, 0, false // non-minimal leading zero
	}
	return new(big.Int).SetBytes(sig[i : i+l]), i + l, true
}

// Verify reports whether `der` is a valid low-s ECDSA signature by `pub` over the 32-byte `hash`.
// Total: never panics; any malformation returns false. Matches @noble's default (low-s enforced).
func Verify(pub []byte, hash []byte, der []byte) bool {
	q, ok := parsePub(pub)
	if !ok {
		return false
	}
	r, s, ok := parseDER(der)
	if !ok {
		return false
	}
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	if s.Cmp(nHalf) > 0 {
		return false // high-s rejected (BIP-62 / @noble default)
	}
	z := new(big.Int).SetBytes(hash)
	w := new(big.Int).ModInverse(s, n)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mod(new(big.Int).Mul(z, w), n)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), n)
	g := point{gx, gy}
	rr := add(scalarMul(u1, g), scalarMul(u2, q))
	if rr.isInf() {
		return false
	}
	return new(big.Int).Mod(rr.x, n).Cmp(r) == 0
}
