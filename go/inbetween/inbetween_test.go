package inbetween

import (
	"math/big"
	"strings"
	"testing"
)

func ruleset() Ruleset {
	return Ruleset{
		MinBet: big.NewInt(1), MaxBet: big.NewInt(10), Ante: big.NewInt(5),
		EqualVisiblePenalty: big.NewInt(2), PostPenaltyMultiplier: 2,
		DecisionTimeout: 30, RecoveryTimeout: 300, MinPlayers: 2, MaxPlayers: 6,
	}
}

func parties() []string {
	return []string{"02" + strings.Repeat("a", 62), "03" + strings.Repeat("b", 62)}
}

func TestInitConservesAndIsDeterministic(t *testing.T) {
	s1 := Init("aabb", parties(), big.NewInt(100), 6, ruleset())
	s2 := Init("aabb", parties(), big.NewInt(100), 6, ruleset())
	if HashHex(s1) != HashHex(s2) {
		t.Fatal("init hash not deterministic")
	}
	if s1.Pot.Cmp(big.NewInt(10)) != 0 || s1.Total.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("pot/total wrong: pot=%s total=%s", s1.Pot, s1.Total)
	}
	if _, conserved := Settle(s1); !conserved {
		t.Fatal("init not conserved")
	}
}

func TestRandomnessThenConservation(t *testing.T) {
	s := Init("aabb", parties(), big.NewInt(100), 6, ruleset())
	seed := strings.Repeat("11", 32) // 64 hex chars = 32 bytes
	next, ok, reason := Apply(s, Step{Kind: "randomness", SeedHex: seed})
	if !ok {
		t.Fatalf("randomness rejected: %s", reason)
	}
	if next.Phase != "await-bet" && next.Phase != "deck-commitment" && next.Phase != "complete" {
		t.Fatalf("unexpected phase %s", next.Phase)
	}
	if _, conserved := Settle(next); !conserved {
		t.Fatal("not conserved after randomness")
	}
}

func TestApplyIsTotalOnBadInput(t *testing.T) {
	s := Init("aabb", parties(), big.NewInt(100), 6, ruleset())
	if _, ok, _ := Apply(s, Step{Kind: "randomness", SeedHex: "zz"}); ok {
		t.Fatal("bad seed should be rejected")
	}
	if _, ok, _ := Apply(s, Step{Kind: "bogus"}); ok {
		t.Fatal("unknown step should be rejected")
	}
}
