package txmodel

import (
	"bytes"
	"math/big"
)

// Opcodes used by the templates (subset; full set lives in the script package).
const (
	opDup         = 0x76
	opHash160     = 0xa9
	opEqualVerify = 0x88
	opCheckSig    = 0xac
	opDrop        = 0x75
	op1           = 0x51
	opPushData1   = 0x4c
	opPushData2   = 0x4d
)

// PushData mirrors templates.ts pushData (direct / PUSHDATA1 / PUSHDATA2).
func PushData(data []byte) []byte {
	n := len(data)
	switch {
	case n < opPushData1:
		return append([]byte{byte(n)}, data...)
	case n <= 0xff:
		return append([]byte{opPushData1, byte(n)}, data...)
	case n <= 0xffff:
		return append([]byte{opPushData2, byte(n), byte(n >> 8)}, data...)
	default:
		panic("pushData too large")
	}
}

func P2PKHLockingFromPkh(pkh []byte) []byte {
	return cat([]byte{opDup, opHash160}, PushData(pkh), []byte{opEqualVerify, opCheckSig})
}

type Covenant struct {
	Reserve   *big.Int
	RulesHash []byte // 32 bytes
}

func reserveBytes(reserve *big.Int) []byte {
	v := reserve.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

// CovenantOutput mirrors templates.ts covenantOutput.
func CovenantOutput(reserve *big.Int, rulesHash []byte) TxOutput {
	script := cat(PushData(rulesHash), []byte{opDrop}, PushData(reserveBytes(reserve)), []byte{opDrop, op1})
	return TxOutput{Satoshis: new(big.Int).Set(reserve), LockingScript: script}
}

// VerifyCovenantPayout mirrors templates.ts verifyCovenantPayout. Returns (ok, reason).
func VerifyCovenantPayout(prev Covenant, tx Tx, recipientPkh []byte, amount *big.Int) (bool, string) {
	if len(recipientPkh) != 20 {
		return false, "recipientPkh must be 20 bytes"
	}
	if amount.Sign() < 0 || amount.Cmp(prev.Reserve) > 0 {
		return false, "amount out of [0, reserve]"
	}
	if len(tx.Outputs) < 2 {
		return false, "needs payout + residual outputs"
	}
	out0 := tx.Outputs[0]
	if out0.Satoshis.Cmp(amount) != 0 || !bytes.Equal(out0.LockingScript, P2PKHLockingFromPkh(recipientPkh)) {
		return false, "output 0 must pay exactly amount to recipient"
	}
	out1 := tx.Outputs[1]
	want1 := CovenantOutput(new(big.Int).Sub(prev.Reserve, amount), prev.RulesHash)
	if out1.Satoshis.Cmp(want1.Satoshis) != 0 || !bytes.Equal(out1.LockingScript, want1.LockingScript) {
		return false, "output 1 must re-lock residual to same covenant"
	}
	return true, "ok"
}

// VerifyCovenantSpend mirrors templates.ts verifyCovenantSpend (REQ-SEC-008). Returns (ok, reason).
func VerifyCovenantSpend(prev Covenant, prevOutpoint Outpoint, prevScript []byte, tx Tx, recipientPkh []byte, amount *big.Int) (bool, string) {
	if len(tx.Inputs) == 0 {
		return false, "no inputs"
	}
	in := tx.Inputs[0]
	if !bytes.Equal(in.Outpoint.Txid, prevOutpoint.Txid) || in.Outpoint.Vout != prevOutpoint.Vout {
		return false, "tx does not spend the covenant outpoint"
	}
	if !bytes.Equal(prevScript, CovenantOutput(prev.Reserve, prev.RulesHash).LockingScript) {
		return false, "spent prevout script is not this covenant"
	}
	return VerifyCovenantPayout(prev, tx, recipientPkh, amount)
}
