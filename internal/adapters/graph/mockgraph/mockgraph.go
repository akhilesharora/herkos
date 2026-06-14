// Package mockgraph is a pure-Go GraphPort over an in-memory node/edge fixture. It is
// the CGO_ENABLED=0 sibling of the tree-sitter adapter (P2): core + spanselect tests run
// against it so they never need cgo, and it is the contract the tree-sitter adapter must
// match. Selection is delegated to core/spanselect.
package mockgraph

import (
	"context"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/ports"
)

// Graph is an in-memory GraphPort.
type Graph struct {
	g spanselect.Graph
}

// New builds a mock graph from fixture nodes.
func New(nodes []spanselect.Node) *Graph {
	return &Graph{g: spanselect.NewGraph(nodes)}
}

// Select resolves the query against the fixture graph via the SpanGate SELECT stage.
func (m *Graph) Select(ctx context.Context, q core.Query) (core.SpanSet, error) {
	return spanselect.Select(m.g, q)
}

// compile-time assertion that the mock satisfies the port contract.
var _ ports.GraphPort = (*Graph)(nil)
