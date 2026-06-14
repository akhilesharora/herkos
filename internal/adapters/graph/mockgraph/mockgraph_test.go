package mockgraph

import (
	"context"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
)

func TestMockGraphSelect(t *testing.T) {
	m := New([]spanselect.Node{
		{Symbol: "Auth", Span: core.Span{File: "auth.go", StartLine: 1, EndLine: 10}, Edges: []int{1}},
		{Symbol: "DB", Span: core.Span{File: "db.go", StartLine: 1, EndLine: 5}},
	})
	ss, err := m.Select(context.Background(), core.Query{Anchors: []string{"Auth"}, LineBudget: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("auth.go", 5) {
		t.Fatal("expected the Auth span to be selected")
	}
	// The selected set is directly usable as a fail-closed egress allowlist (the dual-use).
	b := core.NewBinding(ss)
	if !b.AuthorizeLine("auth.go", 5).Allowed() {
		t.Fatal("binding must authorize an in-span line")
	}
	if b.AuthorizeLine("secret.go", 1).Allowed() {
		t.Fatal("binding must deny an out-of-span line")
	}
}
