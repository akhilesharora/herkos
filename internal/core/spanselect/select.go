// Package spanselect is SpanGate's SELECT stage: a bounded, budgeted graph walk that
// turns a Query into the minimal SpanSet the model needs. It is pure (core domain only,
// no adapters, no I/O) so it runs CGO_ENABLED=0 -race. A concrete code graph is supplied
// by a GraphPort adapter (mockgraph for tests, tree-sitter in P2).
package spanselect

import (
	"sort"

	"github.com/akhilesharora/herkos/internal/core"
)

const (
	maxHops = 3
	decay   = 0.5
)

// Node is a symbol in the code graph: its source span and outgoing edges (indices into
// the graph's node slice; def-use / call / import, treated undirected for v1).
type Node struct {
	Symbol string
	Span   core.Span
	Edges  []int
}

// Graph is a resolved code graph plus a symbol -> index resolver.
type Graph struct {
	Nodes []Node
	index map[string]int
}

// NewGraph builds a Graph and its symbol index.
func NewGraph(nodes []Node) Graph {
	idx := make(map[string]int, len(nodes))
	for i, n := range nodes {
		idx[n.Symbol] = i
	}
	return Graph{Nodes: nodes, index: idx}
}

// Select runs bounded BFS (<=maxHops, decay scoring) from the query anchors and returns a
// SpanSet whose total lines do not exceed q.LineBudget. The anchor and its direct
// neighbours (hop <= 1) are force-included so the decisive span is never budget-evicted;
// the remaining budget is filled by descending relevance score with a deterministic
// symbol tie-break. An invalid/unresolvable query yields the empty (deny-all) set.
func Select(g Graph, q core.Query) (core.SpanSet, error) {
	if !q.Valid() {
		return core.SpanSet{}, nil
	}
	score := make(map[int]float64)
	forced := make(map[int]bool)

	type item struct{ node, hop int }
	for _, anchor := range q.Anchors {
		seed, ok := g.index[anchor]
		if !ok {
			continue
		}
		visited := map[int]bool{seed: true}
		queue := []item{{seed, 0}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			score[cur.node] += pow(decay, cur.hop)
			if cur.hop <= 1 {
				forced[cur.node] = true
			}
			if cur.hop >= maxHops {
				continue
			}
			for _, nb := range g.Nodes[cur.node].Edges {
				if nb >= 0 && nb < len(g.Nodes) && !visited[nb] {
					visited[nb] = true
					queue = append(queue, item{nb, cur.hop + 1})
				}
			}
		}
	}
	if len(score) == 0 {
		return core.SpanSet{}, nil
	}

	ranked := make([]int, 0, len(score))
	for i := range score {
		ranked = append(ranked, i)
	}
	sort.Slice(ranked, func(a, b int) bool {
		ia, ib := ranked[a], ranked[b]
		if forced[ia] != forced[ib] {
			return forced[ia]
		}
		if score[ia] != score[ib] {
			return score[ia] > score[ib]
		}
		return g.Nodes[ia].Symbol < g.Nodes[ib].Symbol
	})

	var spans []core.Span
	used := 0
	for _, i := range ranked {
		sp := g.Nodes[i].Span
		ln := sp.Lines()
		if !forced[i] && used+ln > q.LineBudget {
			continue // budget-evict only non-forced spans
		}
		spans = append(spans, sp)
		used += ln
	}
	return core.NewSpanSet(spans...)
}

func pow(base float64, exp int) float64 {
	r := 1.0
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}
