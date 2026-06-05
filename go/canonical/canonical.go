// Package canonical is the Go side of the canonical encoding (REQ-DET-001/005). It MUST produce
// byte-identical output to the TypeScript @bsv-universal/protocol-types canonicalStringify/taggedHash
// for the shapes used by the in-between module — that equivalence is what the differential proves.
package canonical

import (
	"crypto/sha256"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// Domain-separation tags — MUST match HASH_TAGS in protocol-types.
const (
	TagState   = "bsv-universal/state/v1"
	TagRuleset = "bsv-universal/ruleset/v1"
	TagBeacon  = "bsv-universal/beacon/v1"
	TagCommit  = "bsv-universal/commit/v1"
)

// TaggedHash = SHA256(utf8(tag) ++ 0x00 ++ parts...). Matches taggedHash().
func TaggedHash(tag string, parts ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte{0x00})
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// --- canonical value model (mirrors the TS Canonical union) --------------------------------------

// Value is a canonical-serializable value: string | int (number) | *big.Int (bigint) | bool | nil |
// []Value (array) | *Obj (sorted-key object).
type Value interface{}

// Obj is an ordered set of key/value pairs; Stringify sorts keys (REQ-DET-003).
type Obj struct {
	keys []string
	vals map[string]Value
}

func NewObj() *Obj { return &Obj{vals: map[string]Value{}} }

func (o *Obj) Set(k string, v Value) *Obj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

// Stringify reproduces TS canonicalStringify exactly: sorted keys, integers as decimal, *big.Int as
// "<n>n" string, arrays in order, JSON-escaped strings, no whitespace.
func Stringify(v Value) string {
	var b strings.Builder
	encode(&b, v)
	return b.String()
}

func encode(b *strings.Builder, v Value) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		encodeString(b, t)
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case *big.Int:
		// bigint → JSON string with an explicit "n" suffix, exactly as TS encodes it.
		b.WriteByte('"')
		b.WriteString(t.String())
		b.WriteString("n\"")
	case []Value:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			encode(b, e)
		}
		b.WriteByte(']')
	case *Obj:
		keys := make([]string, len(t.keys))
		copy(keys, t.keys)
		sort.Strings(keys) // codepoint (byte) order — matches JS key sort for our ASCII keys
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			encode(b, t.vals[k])
		}
		b.WriteByte('}')
	default:
		panic("canonical: unserializable type")
	}
}

// encodeString mirrors JSON.stringify(string): double-quoted, with the standard escapes.
func encodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString("\\u00")
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Hash = TaggedHash(TagState, utf8(Stringify(v))) — the canonical state hash.
func Hash(v Value) []byte {
	return TaggedHash(TagState, []byte(Stringify(v)))
}
