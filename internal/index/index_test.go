package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
)

func sampleNodes() []spanselect.Node {
	// A (line 3) calls B (line 2): an edge A->B so SELECT pulls B in as a neighbour.
	return []spanselect.Node{
		{Symbol: "B", Span: core.Span{File: "x.go", StartLine: 2, EndLine: 3}},
		{Symbol: "A", Span: core.Span{File: "x.go", StartLine: 3, EndLine: 4}, Edges: []int{0}},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "herkos.index") // sub/ exercises MkdirAll
	want := sampleNodes()
	if err := Save(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("loaded %d nodes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Symbol != want[i].Symbol || got[i].Span != want[i].Span {
			t.Fatalf("node %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSavedIndexPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "herkos.index")
	if err := Save(path, sampleNodes()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("index perms = %o, want 600", fi.Mode().Perm())
	}
}

func TestOpenGraphSelectsViaEdge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "herkos.index")
	if err := Save(path, sampleNodes()); err != nil {
		t.Fatal(err)
	}
	g, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Anchored on A with a tiny budget, the edge must still pull in B.
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"A"}, LineBudget: 1})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if !ss.AllowsLine("x.go", 3) {
		t.Fatal("anchor A must be selected")
	}
	if !ss.AllowsLine("x.go", 2) {
		t.Fatal("callee B must be pulled in via the persisted edge")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.index")); err == nil {
		t.Fatal("loading a missing index must error")
	}
}

func TestLoadGarbageFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.index")
	if err := os.WriteFile(path, []byte("not a gob stream"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("loading a non-gob file must error, not panic")
	}
}
