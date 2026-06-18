package spanguard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
	"golang.org/x/text/unicode/norm"
)

// authBody is a small source file the lexicon is built from in these tests. The served
// span (lines 1-4) holds Authenticate; the unserved span (lines 6-9) holds rotateSecret.
const authBody = `func Authenticate(user, pass string) bool {
	hashed := hashPassword(pass)
	return subtle.ConstantTimeCompare(hashed, lookup(user)) == 1
}

func rotateSecret(masterKey []byte) []byte {
	derived := hkdf.Expand(sha256.New, masterKey, nil)
	return derived[:32]
}`

func servedGuard(t *testing.T) *Guard {
	t.Helper()
	served := core.Span{File: "auth.go", StartLine: 1, EndLine: 5}
	unserved := core.Span{File: "auth.go", StartLine: 6, EndLine: 10}
	lex := NewLexicon(DefaultMinLineLen)
	lex.AddSpan(served, authBody)
	lex.AddSpan(unserved, authBody)
	if lex.Size() == 0 {
		t.Fatal("lexicon armed nothing; check minLineLen / body")
	}
	ss, err := core.NewSpanSet(served) // only the served span is in the binding
	if err != nil {
		t.Fatal(err)
	}
	return New(core.NewBinding(ss), lex)
}

// toolCall builds a tools/call frame whose single string argument is text.
func toolCall(t *testing.T, text string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "post_message", "arguments": map[string]any{"body": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServedLinePasses(t *testing.T) {
	g := servedGuard(t)
	// A line from the SERVED span may leave.
	allow, reply := g.Check(toolCall(t, "here is the code:\n\thashed := hashPassword(pass)"))
	if !allow || reply != nil {
		t.Fatalf("served repo line must pass, got allow=%v reply=%q", allow, reply)
	}
}

func TestUnservedLineBlocked(t *testing.T) {
	g := servedGuard(t)
	// A line from the UNSERVED span is exfiltration and must be blocked.
	allow, reply := g.Check(toolCall(t, "leaking:\n\tderived := hkdf.Expand(sha256.New, masterKey, nil)"))
	if allow {
		t.Fatal("unserved repo line must be blocked")
	}
	var v map[string]any
	if err := json.Unmarshal(reply, &v); err != nil {
		t.Fatalf("deny reply must be valid JSON: %v (%q)", err, reply)
	}
	if v["error"] == nil {
		t.Fatalf("deny reply must be a JSON-RPC error: %q", reply)
	}
}

func TestUnservedLineNestedArgBlocked(t *testing.T) {
	g := servedGuard(t)
	// The leak is buried in a nested array/object, not a top-level string.
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "x", "arguments": map[string]any{
			"items": []any{"safe text", map[string]any{"blob": "\tderived := hkdf.Expand(sha256.New, masterKey, nil)"}},
		}},
	})
	if allow, _ := g.Check(b); allow {
		t.Fatal("leak nested in tool arguments must still be blocked")
	}
}

func TestReflowedWhitespaceBlocked(t *testing.T) {
	g := servedGuard(t)
	// The SAME unserved line with its single interior spaces expanded to runs of spaces and
	// tabs. Byte-verbatim matching misses this; normalized matching must still trip.
	reflowed := "derived :=  hkdf.Expand(sha256.New,\tmasterKey,   nil)"
	if allow, _ := g.Check(toolCall(t, "leaking:\n\t"+reflowed)); allow {
		t.Fatal("unserved repo line with reflowed interior whitespace must be blocked")
	}
}

func TestRecasedLineBlocked(t *testing.T) {
	g := servedGuard(t)
	// The SAME unserved line, recased. Normalization lowercases both sides, so it must trip.
	recased := "DERIVED := HKDF.Expand(SHA256.New, masterKey, nil)"
	if allow, _ := g.Check(toolCall(t, "leaking:\n\t"+recased)); allow {
		t.Fatal("unserved repo line with changed case must be blocked")
	}
}

// TestUnicodeFormBlocked is the same class of evasion as reflow and recase: an unserved repo
// line re-encoded from NFC to NFD is the same visible glyphs with different bytes, so a
// case/whitespace-only match misses it. normalize must canonicalize Unicode form so the twin
// still trips. Without the NFC fold the NFD form slips through; this pins that it does not.
func TestUnicodeFormBlocked(t *testing.T) {
	// "café" carries a composable char: NFC U+00E9 vs NFD 'e'+U+0301. Files on disk are NFC.
	const body = "package main\n" +
		"\n" +
		"func deriveKey(master []byte) []byte {\n" +
		"\tcaféSalt := saltFromVault(master, defaultRounds)\n" +
		"\treturn kdf(master, caféSalt)\n" +
		"}"
	unserved := core.Span{File: "kdf.go", StartLine: 3, EndLine: 7}
	other := core.Span{File: "kdf.go", StartLine: 1, EndLine: 2}
	lex := NewLexicon(DefaultMinLineLen)
	lex.AddSpan(unserved, body)
	ss, err := core.NewSpanSet(other) // the binding serves a different span, so the line is unserved
	if err != nil {
		t.Fatal(err)
	}
	g := New(core.NewBinding(ss), lex)

	line := "\tcaféSalt := saltFromVault(master, defaultRounds)"
	// Sanity: the NFC verbatim unserved line is caught.
	if allow, _ := g.Check(toolCall(t, "out:\n"+line)); allow {
		t.Fatal("NFC verbatim unserved repo line must be blocked")
	}
	// The NFD twin is the same glyphs, different bytes; it must be blocked too.
	nfd := norm.NFD.String(line)
	if nfd == line {
		t.Fatal("test setup: NFD form equals NFC; the line needs a composable char")
	}
	if allow, _ := g.Check(toolCall(t, "out:\n"+nfd)); allow {
		t.Fatal("NFD twin of an unserved repo line bypassed the tripwire")
	}
}

func TestParaphraseStillPasses(t *testing.T) {
	g := servedGuard(t)
	// Honest residual: normalization only defeats whitespace/case reflow. A genuine
	// paraphrase that renames the variable and call expression carries the same intent but no
	// fingerprinted line, so it PASSES. This guard is a tripwire, not a boundary.
	paraphrase := "key := hkdf.Extract(sha512.New, masterKey, salt)"
	if allow, _ := g.Check(toolCall(t, "leaking:\n\t"+paraphrase)); !allow {
		t.Fatal("a genuinely paraphrased line carries no fingerprint and must pass (documented residual)")
	}
}

func TestArbitraryProsePasses(t *testing.T) {
	g := servedGuard(t)
	// Non-repo text (the agent's own words) must not be blocked.
	if allow, _ := g.Check(toolCall(t, "Summary: I refactored the auth flow and all tests pass.")); !allow {
		t.Fatal("arbitrary prose must pass; this guard gates repo content only")
	}
}

func TestNonToolCallPasses(t *testing.T) {
	g := servedGuard(t)
	frames := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}`,
	}
	for _, f := range frames {
		if allow, _ := g.Check([]byte(f)); !allow {
			t.Fatalf("non-tools/call frame must pass: %s", f)
		}
	}
}

func TestUnparseablePasses(t *testing.T) {
	// This guard does not own fail-closed on unparseable frames (mcpguard does); it must
	// not panic and must pass them through.
	g := servedGuard(t)
	for _, f := range [][]byte{[]byte(`{not json`), []byte(``), []byte(`[1,2,3]`)} {
		if allow, _ := g.Check(f); !allow {
			t.Fatalf("unparseable frame should pass this guard: %q", f)
		}
	}
}

func TestInertWhenNotArmed(t *testing.T) {
	// No lexicon (or empty) => content gate inert => everything passes, including a frame
	// that would otherwise be a leak.
	ss, _ := core.NewSpanSet()
	g := New(core.NewBinding(ss), nil)
	if allow, _ := g.Check(toolCall(t, "\tderived := hkdf.Expand(sha256.New, masterKey, nil)")); !allow {
		t.Fatal("guard with nil lexicon must be inert (pass all)")
	}
	g2 := New(core.NewBinding(ss), NewLexicon(0))
	if allow, _ := g2.Check(toolCall(t, "\tderived := hkdf.Expand(sha256.New, masterKey, nil)")); !allow {
		t.Fatal("guard with empty lexicon must be inert (pass all)")
	}
}

func TestZeroBindingBlocksAllRepoContent(t *testing.T) {
	// Lexicon armed but nothing served (zero binding) => every fingerprinted repo line is
	// unserved => blocked. This is deny-by-default for repo egress.
	lex := NewLexicon(DefaultMinLineLen)
	lex.AddSpan(core.Span{File: "auth.go", StartLine: 1, EndLine: 5}, authBody)
	g := New(core.Binding{}, lex)
	if allow, _ := g.Check(toolCall(t, "\thashed := hashPassword(pass)")); allow {
		t.Fatal("with a zero binding, no repo line may leave")
	}
}

func TestBoilerplateLineNotGated(t *testing.T) {
	// A distinctive-but-common line that appears across many spans carries no provenance and
	// must not gate, or ordinary agent output would be wrongly blocked.
	lex := NewLexicon(DefaultMinLineLen)
	boiler := "if err != nil { return err }"
	n := DefaultMaxSpansPerLine + 2
	body := strings.Repeat(boiler+"\n", n) // n identical lines
	for i := 0; i < n; i++ {
		// each span points at a distinct line of body, all equal to boiler
		lex.AddSpan(core.Span{File: "f.go", StartLine: i + 1, EndLine: i + 2}, body)
	}
	if got := lex.Spans(boiler); got != nil {
		t.Fatalf("boilerplate in %d spans must not gate, got %d spans", DefaultMaxSpansPerLine+2, len(got))
	}
	// Nothing served, but the boilerplate still passes (it is treated as non-repo content).
	g := New(core.Binding{}, lex)
	if allow, _ := g.Check(toolCall(t, boiler)); !allow {
		t.Fatal("boilerplate line must pass even with a zero binding")
	}
}

func TestTrivialLinesNotGated(t *testing.T) {
	g := servedGuard(t)
	// A bare closing brace is in the unserved span but is too trivial to fingerprint, so
	// it is not treated as a leak (false-positive guard).
	if allow, _ := g.Check(toolCall(t, "}")); !allow {
		t.Fatal("trivial punctuation line must not be gated")
	}
}
