// Value-layer differential runner (REQ-TEST-003 extended): replays the TS value corpus through the
// independent Go script interpreter + tx model and asserts byte-/boolean-identical results for script
// evaluation, txids, sighashes, value conservation, and covenant binding. Mismatch fails CI.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"bsvuniversal/beacon"
	"bsvuniversal/script"
	"bsvuniversal/secp256k1"
	"bsvuniversal/txmodel"
)

func fromHex(h string) []byte {
	if len(h)%2 != 0 {
		panic("bad hex len")
	}
	out := make([]byte, len(h)/2)
	for i := range out {
		out[i] = nib(h[i*2])<<4 | nib(h[i*2+1])
	}
	return out
}
func nib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	panic("bad hex char")
}
func toHex(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, x := range b {
		o[i*2] = h[x>>4]
		o[i*2+1] = h[x&0xf]
	}
	return string(o)
}
func bigOf(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad bigint " + s)
	}
	return n
}

type jTx struct {
	Version uint32 `json:"version"`
	Inputs  []struct {
		Txid            string `json:"txid"`
		Vout            uint32 `json:"vout"`
		UnlockingScript string `json:"unlockingScript"`
		Sequence        uint32 `json:"sequence"`
	} `json:"inputs"`
	Outputs []struct {
		Satoshis      string `json:"satoshis"`
		LockingScript string `json:"lockingScript"`
	} `json:"outputs"`
	LockTime uint32 `json:"lockTime"`
}

func toTx(j jTx) txmodel.Tx {
	tx := txmodel.Tx{Version: j.Version, LockTime: j.LockTime}
	for _, in := range j.Inputs {
		tx.Inputs = append(tx.Inputs, txmodel.TxInput{
			Outpoint:        txmodel.Outpoint{Txid: fromHex(in.Txid), Vout: in.Vout},
			UnlockingScript: fromHex(in.UnlockingScript), Sequence: in.Sequence,
		})
	}
	for _, o := range j.Outputs {
		tx.Outputs = append(tx.Outputs, txmodel.TxOutput{Satoshis: bigOf(o.Satoshis), LockingScript: fromHex(o.LockingScript)})
	}
	return tx
}

type corpus struct {
	ScriptVecs []struct {
		U  string `json:"u"`
		L  string `json:"l"`
		OK bool   `json:"ok"`
	} `json:"scriptVecs"`
	TxidVecs []struct {
		Tx   jTx    `json:"tx"`
		Txid string `json:"txid"`
	} `json:"txidVecs"`
	SighashVecs []struct {
		Tx        jTx    `json:"tx"`
		Index     int    `json:"index"`
		PrevScript string `json:"prevScript"`
		Amount    string `json:"amount"`
		Sighash   string `json:"sighash"`
	} `json:"sighashVecs"`
	ValueVecs []struct {
		Tx          jTx      `json:"tx"`
		PrevAmounts []string `json:"prevAmounts"`
		Fee         string   `json:"fee"`
		OK          bool     `json:"ok"`
	} `json:"valueVecs"`
	CovVecs []struct {
		Reserve      string `json:"reserve"`
		RulesHash    string `json:"rulesHash"`
		PrevTxid     string `json:"prevTxid"`
		PrevVout     uint32 `json:"prevVout"`
		PrevScript   string `json:"prevScript"`
		Tx           jTx    `json:"tx"`
		RecipientPkh string `json:"recipientPkh"`
		Amount       string `json:"amount"`
		OK           bool   `json:"ok"`
	} `json:"covVecs"`
	BeaconVecs []struct {
		Commits []struct {
			Party      string `json:"party"`
			Commitment string `json:"commitment"`
		} `json:"commits"`
		Reveals []struct {
			Party  string `json:"party"`
			Secret string `json:"secret"`
		} `json:"reveals"`
		Eligible   []string `json:"eligible"`
		RoundNo    int      `json:"roundNo"`
		PrevBeacon string   `json:"prevBeacon"`
		OK         bool     `json:"ok"`
		Seed       string   `json:"seed"`
	} `json:"beaconVecs"`
	AuthVecs []struct {
		Kind string `json:"kind"`
		Msg  string `json:"msg"`
		Der  string `json:"der"`
		Pub  string `json:"pub"`
		OK   bool   `json:"ok"`
	} `json:"authVecs"`
}

// shared stub checker — MUST match the TS generator's STUB.
func stub(sig, pub []byte) bool {
	return len(sig) > 0 && len(pub) > 0 && sig[0] == pub[0]
}

func main() {
	data, err := os.ReadFile("value-vectors.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read go/value-vectors.json — run gen-value-vectors.ts first:", err)
		os.Exit(1)
	}
	var c corpus
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintln(os.Stderr, "bad value-vectors.json:", err)
		os.Exit(1)
	}
	lim := script.Default()
	bad := 0

	for i, v := range c.ScriptVecs {
		ok, reason := script.Eval(fromHex(v.U), fromHex(v.L), stub, lim)
		if ok != v.OK {
			bad++
			fmt.Printf("script %d: ts=%v go=%v (%s)\n", i, v.OK, ok, reason)
		}
	}
	for i, v := range c.TxidVecs {
		got := toHex(txmodel.Txid(toTx(v.Tx)))
		if got != v.Txid {
			bad++
			fmt.Printf("txid %d: ts=%s go=%s\n", i, v.Txid, got)
		}
	}
	for i, v := range c.SighashVecs {
		got := toHex(txmodel.Sighash(toTx(v.Tx), v.Index, fromHex(v.PrevScript), bigOf(v.Amount)))
		if got != v.Sighash {
			bad++
			fmt.Printf("sighash %d: ts=%s go=%s\n", i, v.Sighash, got)
		}
	}
	for i, v := range c.ValueVecs {
		amts := make([]*big.Int, len(v.PrevAmounts))
		for k, a := range v.PrevAmounts {
			amts[k] = bigOf(a)
		}
		ok, _ := txmodel.VerifyTxValue(toTx(v.Tx), amts, bigOf(v.Fee))
		if ok != v.OK {
			bad++
			fmt.Printf("value %d: ts=%v go=%v\n", i, v.OK, ok)
		}
	}
	for i, v := range c.CovVecs {
		prev := txmodel.Covenant{Reserve: bigOf(v.Reserve), RulesHash: fromHex(v.RulesHash)}
		op := txmodel.Outpoint{Txid: fromHex(v.PrevTxid), Vout: v.PrevVout}
		ok, _ := txmodel.VerifyCovenantSpend(prev, op, fromHex(v.PrevScript), toTx(v.Tx), fromHex(v.RecipientPkh), bigOf(v.Amount))
		if ok != v.OK {
			bad++
			fmt.Printf("covenant %d: ts=%v go=%v\n", i, v.OK, ok)
		}
	}

	for i, v := range c.BeaconVecs {
		commits := make([]beacon.Commit, len(v.Commits))
		for k, cm := range v.Commits {
			commits[k] = beacon.Commit{Party: fromHex(cm.Party), Commitment: fromHex(cm.Commitment)}
		}
		reveals := make([]beacon.Reveal, len(v.Reveals))
		for k, rv := range v.Reveals {
			reveals[k] = beacon.Reveal{Party: fromHex(rv.Party), Secret: fromHex(rv.Secret)}
		}
		elig := make([][]byte, len(v.Eligible))
		for k, e := range v.Eligible {
			elig[k] = fromHex(e)
		}
		ok, seed := beacon.VerifyRound(commits, reveals, elig, v.RoundNo, fromHex(v.PrevBeacon))
		if ok != v.OK {
			bad++
			fmt.Printf("beacon %d: ts=%v go=%v\n", i, v.OK, ok)
		} else if ok && beacon.SeedHex(seed) != v.Seed {
			bad++
			fmt.Printf("beacon %d seed: ts=%s go=%s\n", i, v.Seed, beacon.SeedHex(seed))
		}
	}

	for i, v := range c.AuthVecs {
		msg := fromHex(v.Msg)
		var digest []byte
		if v.Kind == "bitcoin" {
			h1 := sha256.Sum256(msg)
			h2 := sha256.Sum256(h1[:])
			digest = h2[:]
		} else {
			h := sha256.Sum256(msg)
			digest = h[:]
		}
		ok := secp256k1.Verify(fromHex(v.Pub), digest, fromHex(v.Der))
		if ok != v.OK {
			bad++
			fmt.Printf("auth %d (%s): ts=%v go=%v\n", i, v.Kind, v.OK, ok)
		}
	}

	total := len(c.ScriptVecs) + len(c.TxidVecs) + len(c.SighashVecs) + len(c.ValueVecs) + len(c.CovVecs) + len(c.BeaconVecs) + len(c.AuthVecs)
	if bad > 0 {
		fmt.Printf("\nVALUE DIFFERENTIAL FAILED — %d mismatch(es) of %d checks\n", bad, total)
		os.Exit(1)
	}
	fmt.Printf("value differential OK — %d checks (script %d, txid %d, sighash %d, value %d, covenant %d, beacon %d, auth %d): Go byte-identical to TS\n",
		total, len(c.ScriptVecs), len(c.TxidVecs), len(c.SighashVecs), len(c.ValueVecs), len(c.CovVecs), len(c.BeaconVecs), len(c.AuthVecs))
}
