//go:build cgo

package treesitter

import (
	"context"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

func TestParseTypeScript(t *testing.T) {
	src := []byte("function authenticate() {}\n\nclass Session {}\n")
	g, err := ParseTypeScript("a.ts", src)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"authenticate"}, LineBudget: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("a.ts", 1) {
		t.Fatalf("expected the authenticate span; got %d spans", ss.Len())
	}
}

func TestParsePython(t *testing.T) {
	src := []byte("def authenticate():\n    pass\n\nclass Session:\n    pass\n")
	g, err := ParsePython("a.py", src)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"authenticate"}, LineBudget: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("a.py", 1) {
		t.Fatalf("expected the authenticate span; got %d spans", ss.Len())
	}
}
