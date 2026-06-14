//go:build cgo

package treesitter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

// TestParseDirCrossFileEdge proves directory parsing resolves a reference across files: a.go
// defines A which calls B defined in b.go, so anchoring on A (even at a tiny budget) pulls in
// B's span from the other file via the cross-file edge.
func TestParseDirCrossFileEdge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package p\nfunc A() { B() }\n")     // A (line 2) refs B
	writeFile(t, dir, "b.go", "package p\nfunc B() {}\n")          // B defined in another file
	writeFile(t, dir, "ignore.txt", "B A not source, must skip\n") // non-source: skipped

	g, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"A"}, LineBudget: 1})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if !ss.AllowsLine("a.go", 2) {
		t.Fatal("anchor A must be selected from a.go")
	}
	if !ss.AllowsLine("b.go", 2) {
		t.Fatal("callee B must be pulled in from b.go via the cross-file edge")
	}
}

// TestParseDirSkipsHiddenAndDeps confirms walk pruning: a symbol defined only under a skipped
// directory must not appear in the graph.
func TestParseDirSkipsHiddenAndDeps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package p\nfunc Main() {}\n")
	writeFile(t, filepath.Join(dir, "node_modules"), "dep.go", "package d\nfunc Dep() {}\n")
	writeFile(t, filepath.Join(dir, ".hidden"), "secret.go", "package h\nfunc Secret() {}\n")

	nodes, err := ParseDirNodes(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	for _, n := range nodes {
		if n.Symbol == "Dep" || n.Symbol == "Secret" {
			t.Fatalf("symbol %q under a skipped dir leaked into the graph", n.Symbol)
		}
	}
	if len(nodes) != 1 || nodes[0].Symbol != "Main" {
		t.Fatalf("expected only Main, got %+v", nodes)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
