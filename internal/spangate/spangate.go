// Package spangate wires SpanGate end-to-end: SELECT -> Binding -> canonicalize + pool each
// served span -> signed receipt. The returned Binding is the SAME span set used to authorize
// egress, so "context served == egress allowed" holds by construction. It depends only on
// ports (adapters are injected), keeping it adapter-free and unit-testable.
package spangate

import (
	"context"
	"crypto/ed25519"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/canon"
	"github.com/akhilesharora/herkos/internal/ports"
	"github.com/akhilesharora/herkos/pkg/receipt"
)

// Pipeline is the SpanGate use-case wiring.
type Pipeline struct {
	graph       ports.GraphPort
	pool        ports.PoolPort
	priv        ed25519.PrivateKey
	enforcement string
}

// New builds a pipeline from injected adapters, a signing key, and the egress enforcement mode.
func New(g ports.GraphPort, p ports.PoolPort, priv ed25519.PrivateKey, enforcement string) *Pipeline {
	return &Pipeline{graph: g, pool: p, priv: priv, enforcement: enforcement}
}

// Serve resolves q into a budgeted span set, builds the dual-use Binding, canonicalizes and
// pools each served span, and returns the Binding plus a signed receipt over the canonical
// span bytes. read supplies a span's raw source bytes.
func (pl *Pipeline) Serve(ctx context.Context, q core.Query, read func(core.Span) []byte) (core.Binding, receipt.Receipt, error) {
	ss, err := pl.graph.Select(ctx, q)
	if err != nil {
		return core.Binding{}, receipt.Receipt{}, err
	}
	b := core.NewBinding(ss)
	canonSpans := make([][]byte, 0, ss.Len())
	for _, s := range ss.Spans() {
		c := canon.Canonicalize(read(s))
		if _, err := pl.pool.Put(ctx, s, c); err != nil {
			return core.Binding{}, receipt.Receipt{}, err
		}
		canonSpans = append(canonSpans, c)
	}
	return b, receipt.Build(pl.priv, pl.enforcement, canonSpans), nil
}
