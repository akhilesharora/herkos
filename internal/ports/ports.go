// Package ports declares the boundaries of Herkos's hexagonal core. internal/core
// depends ONLY on these interfaces, never on a concrete adapter or on I/O; depguard
// enforces that direction. Four ports: Graph, Egress, Transport, Pool. (ModelPort,
// the on-device inference seam, is deferred to P2 - it has no v1 adapter.)
package ports

import (
	"context"

	"github.com/akhilesharora/herkos/internal/core"
)

// GraphPort resolves a query into a minimal, budgeted SpanSet from a local code graph.
type GraphPort interface {
	Select(ctx context.Context, q core.Query) (core.SpanSet, error)
}

// EgressPort authorizes an outbound payload against the active Binding (the dual-use
// span set). Fail-closed: any error path must return the zero (deny) Decision.
type EgressPort interface {
	Authorize(ctx context.Context, b core.Binding, req core.EgressRequest) core.Decision
}

// TransportPort carries framed MCP messages between the agent and an upstream server.
// It is pure plumbing: framing and forwarding, never policy.
type TransportPort interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// PoolPort is the local, content-addressed Merkle span pool. Served spans are stored
// here (canonical bytes) so pruned spans are re-openable by cursor with zero re-query,
// and so the receipt can prove which spans touched the model.
type PoolPort interface {
	Put(ctx context.Context, s core.Span, canon []byte) (core.Cursor, error)
	Open(ctx context.Context, c core.Cursor) ([]byte, error)
}
