// Package txmodel is the independent Go implementation of the BSV transaction model (REQ-TEST-003
// extended to the value layer). It MUST be byte-identical to @bsv-universal/tx: same serialization,
// same txid (double-SHA256), same BIP143/forkid sighash, same value conservation, same covenant
// binding. The differential proves it.
package txmodel

import (
	"crypto/sha256"
	"math/big"
)

const sighashAllForkid = 0x41

type Outpoint struct {
	Txid []byte // 32 bytes
	Vout uint32
}
type TxInput struct {
	Outpoint        Outpoint
	UnlockingScript []byte
	Sequence        uint32
}
type TxOutput struct {
	Satoshis      *big.Int
	LockingScript []byte
}
type Tx struct {
	Version uint32
	Inputs  []TxInput
	Outputs []TxOutput
	LockTime uint32
}

func sha256d(b []byte) []byte {
	a := sha256.Sum256(b)
	c := sha256.Sum256(a[:])
	return c[:]
}

func u32le(n uint32) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}
func u64le(n *big.Int) []byte {
	v := n.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

// Varint is the Bitcoin CompactSize encoding.
func Varint(n int) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	case n <= 0xffffffff:
		return append([]byte{0xfe}, u32le(uint32(n))...)
	default:
		return append([]byte{0xff}, u64le(big.NewInt(int64(n)))...)
	}
}

func varBytes(b []byte) []byte {
	return append(Varint(len(b)), b...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Serialize is the canonical transaction serialization.
func Serialize(tx Tx) []byte {
	out := cat(u32le(tx.Version), Varint(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		out = cat(out, in.Outpoint.Txid, u32le(in.Outpoint.Vout), varBytes(in.UnlockingScript), u32le(in.Sequence))
	}
	out = cat(out, Varint(len(tx.Outputs)))
	for _, o := range tx.Outputs {
		out = cat(out, u64le(o.Satoshis), varBytes(o.LockingScript))
	}
	return cat(out, u32le(tx.LockTime))
}

// Txid = double-SHA256(serialize), internal byte order.
func Txid(tx Tx) []byte { return sha256d(Serialize(tx)) }

func hashPrevouts(tx Tx) []byte {
	var b []byte
	for _, in := range tx.Inputs {
		b = cat(b, in.Outpoint.Txid, u32le(in.Outpoint.Vout))
	}
	return sha256d(b)
}
func hashSequence(tx Tx) []byte {
	var b []byte
	for _, in := range tx.Inputs {
		b = cat(b, u32le(in.Sequence))
	}
	return sha256d(b)
}
func hashOutputs(tx Tx) []byte {
	var b []byte
	for _, o := range tx.Outputs {
		b = cat(b, u64le(o.Satoshis), varBytes(o.LockingScript))
	}
	return sha256d(b)
}

// SighashPreimage is the BIP143 preimage for input `index` (SIGHASH_ALL|FORKID).
func SighashPreimage(tx Tx, index int, prevScript []byte, amount *big.Int) []byte {
	in := tx.Inputs[index]
	return cat(
		u32le(tx.Version),
		hashPrevouts(tx),
		hashSequence(tx),
		in.Outpoint.Txid,
		u32le(in.Outpoint.Vout),
		varBytes(prevScript),
		u64le(amount),
		u32le(in.Sequence),
		hashOutputs(tx),
		u32le(tx.LockTime),
		u32le(sighashAllForkid),
	)
}

// Sighash = double-SHA256(preimage).
func Sighash(tx Tx, index int, prevScript []byte, amount *big.Int) []byte {
	return sha256d(SighashPreimage(tx, index, prevScript, amount))
}

// VerifyTxValue conserves value against real previous amounts + fee. Returns (ok, reason).
func VerifyTxValue(tx Tx, prevAmounts []*big.Int, fee *big.Int) (bool, string) {
	if len(prevAmounts) != len(tx.Inputs) {
		return false, "prevAmounts must match inputs"
	}
	if fee.Sign() < 0 {
		return false, "fee must be non-negative"
	}
	totalIn := big.NewInt(0)
	for _, v := range prevAmounts {
		if v.Sign() < 0 {
			return false, "prev amount must be non-negative"
		}
		totalIn.Add(totalIn, v)
	}
	totalOut := big.NewInt(0)
	for _, o := range tx.Outputs {
		if o.Satoshis.Sign() < 0 {
			return false, "output satoshis must be non-negative"
		}
		totalOut.Add(totalOut, o.Satoshis)
	}
	if totalIn.Cmp(new(big.Int).Add(totalOut, fee)) != 0 {
		return false, "value not conserved"
	}
	return true, "ok"
}
