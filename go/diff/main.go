// Differential runner (REQ-TEST-003): replays the TS-generated corpus through the Go engine and
// asserts every canonical state hash is byte-identical. Any mismatch exits non-zero (fails CI).
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"bsvuniversal/inbetween"
)

type vecRuleset struct {
	MinBet                string `json:"minBet"`
	MaxBet                string `json:"maxBet"`
	Ante                  string `json:"ante"`
	EqualVisiblePenalty   string `json:"equalVisiblePenalty"`
	PostPenaltyMultiplier int    `json:"postPenaltyMultiplier"`
	DecisionTimeout       int    `json:"decisionTimeout"`
	RecoveryTimeout       int    `json:"recoveryTimeout"`
	MinPlayers            int    `json:"minPlayers"`
	MaxPlayers            int    `json:"maxPlayers"`
}
type vecAction struct {
	Type   string `json:"type"`
	Party  string `json:"party"`
	Amount string `json:"amount"`
}
type vecStep struct {
	Kind    string     `json:"kind"`
	SeedHex string     `json:"seedHex"`
	Branch  string     `json:"branch"`
	Action  *vecAction `json:"action"`
}
type vecInit struct {
	GameID        string     `json:"gameId"`
	Parties       []string   `json:"parties"`
	StartingStack string     `json:"startingStack"`
	RoundsTotal   int        `json:"roundsTotal"`
	Ruleset       vecRuleset `json:"ruleset"`
}
type vector struct {
	Init    vecInit   `json:"init"`
	Steps   []vecStep `json:"steps"`
	Hashes  []string  `json:"hashes"`
	InitHash string   `json:"initHash"`
	Settle  struct {
		Balances  map[string]string `json:"balances"`
		Conserved bool              `json:"conserved"`
	} `json:"settle"`
}
type corpus struct {
	Version int      `json:"version"`
	Vectors []vector `json:"vectors"`
}

func bigOf(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad bigint: " + s)
	}
	return n
}

func toRuleset(r vecRuleset) inbetween.Ruleset {
	return inbetween.Ruleset{
		MinBet: bigOf(r.MinBet), MaxBet: bigOf(r.MaxBet), Ante: bigOf(r.Ante),
		EqualVisiblePenalty: bigOf(r.EqualVisiblePenalty), PostPenaltyMultiplier: r.PostPenaltyMultiplier,
		DecisionTimeout: r.DecisionTimeout, RecoveryTimeout: r.RecoveryTimeout,
		MinPlayers: r.MinPlayers, MaxPlayers: r.MaxPlayers,
	}
}

func toStep(s vecStep) inbetween.Step {
	st := inbetween.Step{Kind: s.Kind, SeedHex: s.SeedHex, Branch: s.Branch}
	if s.Action != nil {
		a := &inbetween.Action{Type: s.Action.Type, Party: s.Action.Party}
		if s.Action.Amount != "" {
			a.Amount = bigOf(s.Action.Amount)
		}
		st.Action = a
	}
	return st
}

func main() {
	data, err := os.ReadFile("vectors.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read go/vectors.json — run `node tooling/diff/gen-vectors.ts` first:", err)
		os.Exit(1)
	}
	var c corpus
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintln(os.Stderr, "bad vectors.json:", err)
		os.Exit(1)
	}

	mismatches := 0
	steps := 0
	for vi, v := range c.Vectors {
		st := inbetween.Init(v.Init.GameID, v.Init.Parties, bigOf(v.Init.StartingStack), v.Init.RoundsTotal, toRuleset(v.Init.Ruleset))
		if got := inbetween.HashHex(st); got != v.InitHash {
			mismatches++
			fmt.Printf("vector %d INIT hash mismatch\n  ts: %s\n  go: %s\n  go-canon: %s\n", vi, v.InitHash, got, canon(st))
			continue
		}
		ok := true
		for i, vs := range v.Steps {
			next, applied, reason := inbetween.Apply(st, toStep(vs))
			if !applied {
				mismatches++
				fmt.Printf("vector %d step %d unexpectedly rejected by Go: %s (kind=%s)\n", vi, i, reason, vs.Kind)
				ok = false
				break
			}
			st = next
			steps++
			if got := inbetween.HashHex(st); got != v.Hashes[i] {
				mismatches++
				fmt.Printf("vector %d step %d (%s) hash mismatch\n  ts: %s\n  go: %s\n  go-canon: %s\n", vi, i, vs.Kind, v.Hashes[i], got, canon(st))
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		// settle parity
		bals, conserved := inbetween.Settle(st)
		if conserved != v.Settle.Conserved {
			mismatches++
			fmt.Printf("vector %d settle.conserved mismatch ts=%v go=%v\n", vi, v.Settle.Conserved, conserved)
		}
		for p, want := range v.Settle.Balances {
			if bals[p] != want {
				mismatches++
				fmt.Printf("vector %d settle balance %s mismatch ts=%s go=%s\n", vi, p, want, bals[p])
			}
		}
	}

	if mismatches > 0 {
		fmt.Printf("\nDIFFERENTIAL FAILED — %d mismatch(es) across %d vectors\n", mismatches, len(c.Vectors))
		os.Exit(1)
	}
	fmt.Printf("differential OK — %d vectors, %d steps: Go is byte-identical to TS (REQ-TEST-003)\n", len(c.Vectors), steps)
}

func canon(s *inbetween.State) string {
	return inbetween.CanonString(s)
}
