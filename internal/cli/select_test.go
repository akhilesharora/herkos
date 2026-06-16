package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/index"
)

func TestSelectRequiresIndexAndAnchor(t *testing.T) {
	if code, _, _ := run("select"); code != 2 {
		t.Fatalf("select with no --index exit=%d want 2", code)
	}
	p := filepath.Join(t.TempDir(), "idx")
	if err := index.Save(p, nil); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run("select", "--index", p); code != 2 {
		t.Fatalf("select with no --anchor exit=%d want 2", code)
	}
}

func TestSelectPrintsSpansFromIndex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "idx")
	nodes := []spanselect.Node{
		{Symbol: "B", Span: core.Span{File: "b.go", StartLine: 2, EndLine: 4}},
		{Symbol: "A", Span: core.Span{File: "a.go", StartLine: 1, EndLine: 5}, Edges: []int{0}},
	}
	if err := index.Save(p, nodes); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("select", "--index", p, "--anchor", "A", "--budget", "100")
	if code != 0 {
		t.Fatalf("select exit=%d stderr=%q", code, errb)
	}
	// A is the anchor; B is pulled in via the edge. Both spans must be listed.
	if !strings.Contains(out, "a.go:1-5") {
		t.Fatalf("select output missing anchor span: %q", out)
	}
	if !strings.Contains(out, "b.go:2-4") {
		t.Fatalf("select output missing edge-pulled span: %q", out)
	}
	if !strings.Contains(out, "select: 2 spans") {
		t.Fatalf("select summary wrong: %q", out)
	}
}
