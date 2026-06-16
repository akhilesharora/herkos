package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/index"
)

func TestParseSpanSpec(t *testing.T) {
	good := map[string]core.Span{
		"auth.go:1-20":         {File: "auth.go", StartLine: 1, EndLine: 20},
		"pkg/sub/a-b.go:5-9":   {File: "pkg/sub/a-b.go", StartLine: 5, EndLine: 9}, // hyphen in path
		"  internal/x.go:3-4 ": {File: "internal/x.go", StartLine: 3, EndLine: 4},  // trimmed
	}
	for spec, want := range good {
		got, err := parseSpanSpec(spec)
		if err != nil {
			t.Fatalf("parseSpanSpec(%q) error: %v", spec, err)
		}
		if got != want {
			t.Fatalf("parseSpanSpec(%q)=%+v want %+v", spec, got, want)
		}
	}
	for _, bad := range []string{"", "auth.go", "auth.go:", "auth.go:1", "auth.go:1-", "auth.go:a-b", "auth.go:5-5", "auth.go:0-3"} {
		if _, err := parseSpanSpec(bad); err == nil {
			t.Fatalf("parseSpanSpec(%q) should have failed", bad)
		}
	}
}

func TestBuildContentGate(t *testing.T) {
	root := t.TempDir()
	body := "package x\n\nfunc Served() int {\n\treturn 41 + computeOffset()\n}\n\nfunc Secret() string {\n\treturn fetchMasterCredential()\n}\n"
	if err := os.WriteFile(filepath.Join(root, "x.go"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := []spanselect.Node{
		{Symbol: "Served", Span: core.Span{File: "x.go", StartLine: 3, EndLine: 6}},
		{Symbol: "Secret", Span: core.Span{File: "x.go", StartLine: 7, EndLine: 10}},
	}
	idxPath := filepath.Join(root, ".herkos", "index")
	if err := index.Save(idxPath, nodes); err != nil {
		t.Fatal(err)
	}

	// Serve only Served (x.go:3-6). The lexicon must fingerprint both functions' lines.
	b, lex, unreadable, err := buildContentGate(idxPath, root, []string{"x.go:3-6"})
	if err != nil {
		t.Fatalf("buildContentGate: %v", err)
	}
	if unreadable != 0 {
		t.Fatalf("unreadable=%d want 0", unreadable)
	}
	if lex.Size() == 0 {
		t.Fatal("lexicon fingerprinted nothing")
	}
	// A line from the served span resolves to a covered span.
	if sp := lex.Spans("return 41 + computeOffset()"); len(sp) == 0 || !b.SpanSet().Covers(sp[0]) {
		t.Fatalf("served line should resolve to a covered span, got %+v", sp)
	}
	// A line from the unserved span resolves but is NOT covered (a leak).
	sp := lex.Spans("return fetchMasterCredential()")
	if len(sp) == 0 {
		t.Fatal("unserved line should be fingerprinted")
	}
	for _, s := range sp {
		if b.SpanSet().Covers(s) {
			t.Fatalf("unserved line span %s must not be covered", s)
		}
	}
}

func TestBuildContentGateMissingIndex(t *testing.T) {
	if _, _, _, err := buildContentGate(filepath.Join(t.TempDir(), "nope"), ".", []string{"a.go:1-2"}); err == nil {
		t.Fatal("missing index must error")
	}
}
