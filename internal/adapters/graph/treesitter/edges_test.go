//go:build cgo

package treesitter

import (
	"context"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

// TestCallGraphEdges proves SELECT pulls in a callee via a real parsed edge: A calls B, so
// querying A (even at a tiny budget) force-includes B's span as a direct neighbour.
func TestCallGraphEdges(t *testing.T) {
	src := []byte("package x\nfunc B() {}\nfunc A() { B() }\n") // A (line 3) calls B (line 2)
	g, err := ParseGo("x.go", src)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"A"}, LineBudget: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("x.go", 3) {
		t.Fatal("anchor A must be selected")
	}
	if !ss.AllowsLine("x.go", 2) {
		t.Fatal("callee B must be pulled in via the call-graph edge")
	}
}

func TestTypeScriptEdges(t *testing.T) {
	src := []byte("function b() {}\nfunction a() { b() }\n") // a (line 2) calls b (line 1)
	g, err := ParseTypeScript("a.ts", src)
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := g.Select(context.Background(), core.Query{Anchors: []string{"a"}, LineBudget: 1})
	if !ss.AllowsLine("a.ts", 2) || !ss.AllowsLine("a.ts", 1) {
		t.Fatalf("expected a + callee b via edge; got %d spans", ss.Len())
	}
}
