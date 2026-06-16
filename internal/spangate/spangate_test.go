package spangate

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/akhilesharora/herkos/internal/adapters/graph/mockgraph"
	"github.com/akhilesharora/herkos/internal/adapters/pool"
	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
)

// TestSpanGatePipeline proves the full pure-Go SpanGate pipeline end-to-end: SELECT -> Binding
// -> canonicalize + pool -> signed receipt, AND the dual-use guarantee (the served set is the
// enforced set: in-binding payloads pass, out-of-binding payloads are blocked).
func TestSpanGatePipeline(t *testing.T) {
	g := mockgraph.New([]spanselect.Node{
		{Symbol: "Auth", Span: core.Span{File: "auth.go", StartLine: 1, EndLine: 20}, Edges: []int{1}},
		{Symbol: "DB", Span: core.Span{File: "db.go", StartLine: 1, EndLine: 30}},
	})
	pub, priv, _ := ed25519.GenerateKey(nil)
	pl := New(g, pool.New(), priv, "userspace")
	read := func(s core.Span) []byte { return []byte("source of " + s.File) }

	b, rcpt, err := pl.Serve(context.Background(), core.Query{Anchors: []string{"Auth"}, LineBudget: 100}, read)
	if err != nil {
		t.Fatal(err)
	}
	if err := rcpt.Verify(pub); err != nil {
		t.Fatalf("receipt must verify offline: %v", err)
	}
	if rcpt.Enforcement != "userspace" {
		t.Fatalf("enforcement not stamped: %q", rcpt.Enforcement)
	}
	// dual-use: payload from a served span is allowed
	if d := b.AuthorizePayload(core.EgressRequest{SourceSpans: []core.Span{{File: "auth.go", StartLine: 2, EndLine: 5}}}); !d.Allowed() {
		t.Fatalf("served-span payload must be allowed: %s", d.Detail())
	}
	// dual-use: out-of-binding payload is blocked (the leak case)
	if d := b.AuthorizePayload(core.EgressRequest{SourceSpans: []core.Span{{File: "secret.go", StartLine: 1, EndLine: 9}}}); d.Allowed() {
		t.Fatal("out-of-binding payload must be blocked (leak prevented)")
	}
}
