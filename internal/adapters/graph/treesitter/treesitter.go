//go:build cgo

// Package treesitter parses real source into a code graph via tree-sitter (cgo). It is the
// production GraphPort and the cgo sibling of mockgraph; it satisfies the same contract so
// core/spanselect tests can keep running CGO_ENABLED=0 against the mock.
package treesitter

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/ports"
)

// Graph is a parsed code graph implementing ports.GraphPort.
type Graph struct {
	g spanselect.Graph
}

// parsedDecl is one top-level declaration: its node (symbol + span, edges still empty) and
// the identifier names referenced anywhere in its subtree, left unresolved so edges can be
// resolved against a symbol table that may span multiple files.
type parsedDecl struct {
	node spanselect.Node
	refs []string
}

// build parses one file's src and turns top-level declarations whose node type is in
// declTypes into a graph, with an edge from a declaration to every other declaration in the
// SAME file it references (a coarse call/use graph so SELECT's BFS pulls in callees/types).
func build(file string, src []byte, lang *sitter.Language, declTypes map[string]bool) (*Graph, error) {
	decls, err := parseDecls(file, src, lang, declTypes)
	if err != nil {
		return nil, err
	}
	return &Graph{g: spanselect.NewGraph(resolveNodes(decls))}, nil
}

// parseDecls extracts the top-level declarations from one file as parsedDecl values. It does
// not resolve edges; that is resolveNodes' job, so the same decls can be merged across files
// before resolution (giving cross-file edges).
func parseDecls(file string, src []byte, lang *sitter.Language, declTypes map[string]bool) ([]parsedDecl, error) {
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree, err := p.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	root := tree.RootNode()
	var out []parsedDecl
	for i := 0; i < int(root.NamedChildCount()); i++ {
		c := root.NamedChild(i)
		if !declTypes[c.Type()] {
			continue
		}
		name := declName(c, src)
		if name == "" {
			continue
		}
		var refs []string
		seen := make(map[string]bool)
		walkIdents(c, src, func(id string) {
			if id != name && !seen[id] {
				seen[id] = true
				refs = append(refs, id)
			}
		})
		out = append(out, parsedDecl{
			node: spanselect.Node{
				Symbol: name,
				Span:   core.Span{File: file, StartLine: int(c.StartPoint().Row) + 1, EndLine: int(c.EndPoint().Row) + 2},
			},
			refs: refs,
		})
	}
	return out, nil
}

// resolveNodes turns parsed decls into spanselect nodes with edges: each decl's referenced
// names are looked up in a symbol->index table built from ALL the decls, so a reference to a
// symbol defined in another file resolves to a cross-file edge. When a symbol name is defined
// more than once (across files), the last definition wins; acceptable for a coarse graph.
func resolveNodes(decls []parsedDecl) []spanselect.Node {
	symIdx := make(map[string]int, len(decls))
	for i, d := range decls {
		symIdx[d.node.Symbol] = i
	}
	nodes := make([]spanselect.Node, len(decls))
	for i, d := range decls {
		nodes[i] = d.node
		seen := make(map[int]bool)
		for _, r := range d.refs {
			if j, ok := symIdx[r]; ok && j != i && !seen[j] {
				seen[j] = true
				nodes[i].Edges = append(nodes[i].Edges, j)
			}
		}
	}
	return nodes
}

func walkIdents(n *sitter.Node, src []byte, fn func(string)) {
	if t := n.Type(); t == "identifier" || t == "type_identifier" {
		fn(n.Content(src))
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walkIdents(n.NamedChild(i), src, fn)
	}
}

func declName(c *sitter.Node, src []byte) string {
	if n := c.ChildByFieldName("name"); n != nil {
		return n.Content(src)
	}
	for i := 0; i < int(c.NamedChildCount()); i++ {
		if spec := c.NamedChild(i); spec.Type() == "type_spec" {
			if n := spec.ChildByFieldName("name"); n != nil {
				return n.Content(src)
			}
		}
	}
	return ""
}

// goDeclTypes are the Go tree-sitter node types treated as top-level declarations.
var goDeclTypes = map[string]bool{
	"function_declaration": true,
	"method_declaration":   true,
	"type_declaration":     true,
}

// ParseGo parses Go source into a Graph (functions, methods, types + their call/use edges).
func ParseGo(file string, src []byte) (*Graph, error) {
	return build(file, src, golang.GetLanguage(), goDeclTypes)
}

// Select resolves a query against the parsed graph via the SpanGate SELECT stage.
func (gr *Graph) Select(ctx context.Context, q core.Query) (core.SpanSet, error) {
	return spanselect.Select(gr.g, q)
}

var _ ports.GraphPort = (*Graph)(nil)
