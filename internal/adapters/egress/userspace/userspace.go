// Package userspace is a fail-closed EgressPort that enforces the active span set
// allowlist on the mediated egress path. It delegates every decision to
// [core.Binding.AuthorizePayload], so the dual-use invariant holds structurally: a
// payload leaves only if every source span it derives from is Covered by the same
// Binding the model was served, and the zero Binding (zero SpanSet) denies everything.
//
// This is the userspace enforcement mode. It is honest about its limits: a userspace
// proxy mediates the agent's egress, but a determined local process can bypass it.
// The enforced boundary (Linux, eBPF) ships in P2. See [Guarantee].
package userspace

import (
	"context"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/ports"
)

// EnforcementLabel is the receipt stamp for this mode. The receipt records
// enforcement=userspace so a verifier knows the boundary was mediated, not enforced.
const EnforcementLabel = "userspace"

// guarantee is the honest, non-over-claiming description of what userspace mode
// provides. It MUST NOT be softened into a bare "zero code left your machine".
const guarantee = "Herkos restricts your agent's mediated egress to the active span set; " +
	"out-of-span repo bytes are blocked on the mediated path. This is NOT airtight - a " +
	"determined local process can bypass a userspace proxy. For an enforced boundary, use " +
	"hardened mode (Linux, eBPF), shipping in P2."

// Egress is a fail-closed userspace EgressPort. It holds no policy of its own; the
// active Binding is the single source of truth and is passed in per call.
type Egress struct{}

// New returns a userspace Egress adapter.
func New() *Egress { return &Egress{} }

// Authorize authorizes an outbound payload against the active Binding by delegating to
// [core.Binding.AuthorizePayload]. Fail-closed: a payload with no provenance, any source
// span outside the binding, or the zero Binding all deny.
func (e *Egress) Authorize(_ context.Context, b core.Binding, req core.EgressRequest) core.Decision {
	return b.AuthorizePayload(req)
}

// Enforcement returns the receipt enforcement label for this mode ("userspace").
func (e *Egress) Enforcement() string { return EnforcementLabel }

// Guarantee returns the honest description of what userspace enforcement provides. It
// states plainly that userspace mediation is NOT airtight and points at hardened mode.
func (e *Egress) Guarantee() string { return guarantee }

// compile-time assertion that the adapter satisfies the port contract.
var _ ports.EgressPort = (*Egress)(nil)
