//go:build cgo

package treesitter

import (
	"context"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

func TestParseGoSelectsRealSpans(t *testing.T) {
	src := []byte("package x\n\nfunc Authenticate() {}\n\ntype Session struct{}\n")
	g, err := ParseGo("auth.go", src)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: []string{"Authenticate"}, LineBudget: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !ss.AllowsLine("auth.go", 3) { // func Authenticate is on line 3
		t.Fatalf("expected the Authenticate span to be selected; got %d spans", ss.Len())
	}
	// the selected set is directly usable as a fail-closed egress allowlist (the dual-use)
	if core.NewBinding(ss).AuthorizeLine("secret.go", 1).Allowed() {
		t.Fatal("binding must deny an unparsed file")
	}
}
