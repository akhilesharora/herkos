package spanguard

import (
	"encoding/json"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

// FuzzCheckFailsSafe asserts the content guard's robustness invariants for ANY bytes:
// Check never panics, a deny carries a valid JSON-RPC error (never garbage), and an allow
// never carries a reply. The guard is armed over a real lexicon and binding so the deny
// path is exercised, not just the pass-through.
func FuzzCheckFailsSafe(f *testing.F) {
	served := core.Span{File: "auth.go", StartLine: 1, EndLine: 5}
	unserved := core.Span{File: "auth.go", StartLine: 6, EndLine: 10}
	lex := NewLexicon(DefaultMinLineLen)
	lex.AddSpan(served, authBody)
	lex.AddSpan(unserved, authBody)
	ss, err := core.NewSpanSet(served)
	if err != nil {
		f.Fatal(err)
	}
	g := New(core.NewBinding(ss), lex)

	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"b":"derived := hkdf.Expand(sha256.New, masterKey, nil)"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"b":"hashed := hashPassword(pass)"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":["a",["b",{"c":"hkdf.Expand"}]]}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`,
		`{not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		allow, reply := g.Check(msg) // must never panic
		if !allow && reply != nil {
			var v map[string]any
			if err := json.Unmarshal(reply, &v); err != nil {
				t.Fatalf("deny reply is not valid JSON: %v (%q)", err, reply)
			}
		}
		if allow && reply != nil {
			t.Fatalf("an allowed message must not carry a deny reply: %q", reply)
		}
	})
}
