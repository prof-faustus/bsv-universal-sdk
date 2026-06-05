// Package beacon is the independent Go implementation of the commit→reveal fairness verification
// (REQ-SEC-002/003), cross-checked against crypto.verifyBeaconRound. It MUST agree on accept/reject
// AND derive a byte-identical seed. Pure SHA-256 (no signature crypto). The unbiasable-randomness
// guarantee is thereby proven identical across two implementations.
package beacon

import (
	"sort"

	"bsvuniversal/canonical"
)

const maxParties = 64

type Commit struct {
	Party      []byte // 33-byte partyId
	Commitment []byte // 32 bytes
}
type Reveal struct {
	Party  []byte
	Secret []byte
}

func commit(secret []byte) []byte { return canonical.TaggedHash(canonical.TagCommit, secret) }

func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func u32be(n int) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }

func toHex(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, x := range b {
		o[i*2] = h[x>>4]
		o[i*2+1] = h[x&0xf]
	}
	return string(o)
}

// VerifyRound mirrors crypto.verifyBeaconRound. Returns (ok, seed). Total: never panics.
func VerifyRound(commits []Commit, reveals []Reveal, eligible [][]byte, roundNo int, prevBeacon []byte) (bool, []byte) {
	if roundNo < 0 || roundNo > 0xffffffff {
		return false, nil
	}
	if len(eligible) == 0 || len(eligible) > maxParties {
		return false, nil
	}
	if len(commits) > maxParties || len(reveals) > maxParties {
		return false, nil
	}
	elig := map[string]bool{}
	for _, e := range eligible {
		elig[toHex(e)] = true
	}
	commitMap := map[string][]byte{}
	for _, c := range commits {
		k := toHex(c.Party)
		if !elig[k] {
			return false, nil
		}
		if _, dup := commitMap[k]; dup {
			return false, nil
		}
		if len(c.Commitment) != 32 {
			return false, nil
		}
		commitMap[k] = c.Commitment
	}
	seen := map[string]bool{}
	type honest struct {
		party  []byte
		secret []byte
		key    string
	}
	var hon []honest
	for _, rv := range reveals {
		k := toHex(rv.Party)
		if seen[k] {
			return false, nil
		}
		seen[k] = true
		c, ok := commitMap[k]
		if !ok {
			return false, nil
		}
		if !ctEqual(commit(rv.Secret), c) {
			return false, nil
		}
		hon = append(hon, honest{party: rv.Party, secret: rv.Secret, key: k})
	}
	if len(hon) == 0 {
		return false, nil
	}
	if len(prevBeacon) != 32 {
		return false, nil
	}
	// canonical, locale-independent order by partyId hex (matches TS codepoint compare)
	sort.SliceStable(hon, func(i, j int) bool { return hon[i].key < hon[j].key })
	parts := [][]byte{u32be(roundNo), prevBeacon}
	for _, h := range hon {
		parts = append(parts, h.party, h.secret)
	}
	seed := canonical.TaggedHash(canonical.TagBeacon, parts...)
	return true, seed
}

// SeedHex is a convenience for the differential.
func SeedHex(seed []byte) string { return toHex(seed) }
