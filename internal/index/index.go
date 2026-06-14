// Package index is Herkos's on-disk code-graph index. It persists the (symbol, span,
// edges) nodes produced by the tree-sitter parser as gob so the expensive cgo parse runs
// once (at `herkos index` time) and every later query loads a pure-Go GraphPort without
// touching tree-sitter. The node type carries no interfaces, so gob needs no registration.
package index

import (
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/ports"
)

// indexFile is the on-disk envelope. A version guards against silently misreading a future
// format as the current one.
type indexFile struct {
	Version int
	Nodes   []spanselect.Node
}

// formatVersion is the current on-disk index version.
const formatVersion = 1

// Save writes nodes to path as a versioned gob index (0600), creating parent dirs.
func Save(path string, nodes []spanselect.Node) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("index: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("index: create %s: %w", path, err)
	}
	encErr := gob.NewEncoder(f).Encode(indexFile{Version: formatVersion, Nodes: nodes})
	// Check Close too: on a write, a deferred unchecked Close can swallow a flush failure
	// and leave a truncated index that loads as fewer symbols.
	closeErr := f.Close()
	if encErr != nil {
		return fmt.Errorf("index: encode: %w", encErr)
	}
	if closeErr != nil {
		return fmt.Errorf("index: close %s: %w", path, closeErr)
	}
	return nil
}

// Load reads the nodes from a gob index at path. A missing file, unreadable file, or a
// version mismatch is an error rather than a silently wrong graph.
func Load(path string) ([]spanselect.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("index: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only: a Close error here is harmless
	var idx indexFile
	if err := gob.NewDecoder(f).Decode(&idx); err != nil {
		return nil, fmt.Errorf("index: decode %s: %w", path, err)
	}
	if idx.Version != formatVersion {
		return nil, fmt.Errorf("index: %s is format v%d, want v%d (rebuild with `herkos index`)", path, idx.Version, formatVersion)
	}
	return idx.Nodes, nil
}

// Graph is a pure-Go GraphPort backed by an in-memory node set. It is the query-time
// sibling of the tree-sitter adapter: no cgo, selection delegated to core/spanselect.
type Graph struct {
	g spanselect.Graph
}

// NewGraph builds a queryable graph from nodes.
func NewGraph(nodes []spanselect.Node) *Graph {
	return &Graph{g: spanselect.NewGraph(nodes)}
}

// Open loads the index at path and returns a queryable graph.
func Open(path string) (*Graph, error) {
	nodes, err := Load(path)
	if err != nil {
		return nil, err
	}
	return NewGraph(nodes), nil
}

// Select resolves the query against the loaded graph via the SpanGate SELECT stage.
func (g *Graph) Select(ctx context.Context, q core.Query) (core.SpanSet, error) {
	return spanselect.Select(g.g, q)
}

// compile-time assertion that the index graph satisfies the port contract.
var _ ports.GraphPort = (*Graph)(nil)
