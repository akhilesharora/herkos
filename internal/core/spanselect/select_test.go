package spanselect

import (
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

// fixture: Main -> Auth -> DB -> Util (Util is 2 hops from Auth, large + low score)
func fixture() Graph {
	return NewGraph([]Node{
		{Symbol: "Main", Span: core.Span{File: "main.go", StartLine: 1, EndLine: 10}, Edges: []int{1}},
		{Symbol: "Auth", Span: core.Span{File: "auth.go", StartLine: 1, EndLine: 20}, Edges: []int{0, 2}},
		{Symbol: "DB", Span: core.Span{File: "db.go", StartLine: 1, EndLine: 30}, Edges: []int{1, 3}},
		{Symbol: "Util", Span: core.Span{File: "util.go", StartLine: 1, EndLine: 100}, Edges: []int{2}},
	})
}

func TestSelectForceIncludesAnchorAndNeighbours(t *testing.T) {
	g := fixture()
	// tiny budget: forced spans (anchor + direct neighbours) must survive anyway.
	ss, err := Select(g, core.Query{Anchors: []string{"Auth"}, LineBudget: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"auth.go", "main.go", "db.go"} {
		if !ss.AllowsLine(f, 2) {
			t.Errorf("forced span %s must be selected even under tiny budget", f)
		}
	}
	// Util is 2 hops, not forced, 99 lines -> budget-evicted at budget 5.
	if ss.AllowsLine("util.go", 50) {
		t.Error("non-forced over-budget span (util.go) must be evicted")
	}
}

func TestSelectFillsByBudget(t *testing.T) {
	g := fixture()
	ss, err := Select(g, core.Query{Anchors: []string{"Auth"}, LineBudget: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("util.go", 50) {
		t.Error("with ample budget, the 2-hop span (util.go) should be included")
	}
}

func TestSelectInvalidQueryIsEmpty(t *testing.T) {
	g := fixture()
	ss, _ := Select(g, core.Query{}) // invalid: no budget, no anchor
	if ss.Len() != 0 || ss.AllowsLine("auth.go", 2) {
		t.Fatal("invalid query must yield the empty (deny-all) set")
	}
}

func TestSelectUnresolvedAnchorIsEmpty(t *testing.T) {
	g := fixture()
	ss, _ := Select(g, core.Query{Anchors: []string{"NoSuchSymbol"}, LineBudget: 100})
	if ss.Len() != 0 {
		t.Fatal("unresolved anchor must yield the empty set")
	}
}

func TestSelectDeterministic(t *testing.T) {
	g := fixture()
	q := core.Query{Anchors: []string{"Auth"}, LineBudget: 500}
	a, _ := Select(g, q)
	b, _ := Select(g, q)
	sa, sb := a.Spans(), b.Spans()
	if len(sa) != len(sb) {
		t.Fatalf("non-deterministic length %d vs %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Fatalf("non-deterministic order at %d: %v vs %v", i, sa[i], sb[i])
		}
	}
}
