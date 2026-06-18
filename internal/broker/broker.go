// Package broker sits in-path between an agent-side transport and an upstream
// MCP-server transport, pumping framed messages in both directions.
//
// The upstream-to-agent direction is passthrough, save for an optional [ResponseFilter]
// that can trim a tools/list response to the allowlist. The agent-to-upstream
// direction (the egress direction: bytes leaving toward a possibly-untrusted server)
// can be governed by an optional [Guard]. With no guard the broker is pure plumbing;
// with a guard, an outbound message the guard rejects is NOT forwarded - the broker
// answers the agent with the guard's reply and keeps the session running, so a single
// blocked tool call does not tear down the connection.
//
// Both ends are [ports.TransportPort], so a broker can be wired to real stdio
// transports or to in-memory test doubles without changing its code.
package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/akhilesharora/herkos/internal/ports"
)

// Guard inspects an agent-to-upstream message and decides whether the broker may
// forward it. Returning allow=false blocks the message: the broker does NOT forward it
// upstream and instead sends denyReply back to the agent (nothing is sent if denyReply
// is nil), then continues serving. A nil Guard means pure passthrough.
//
// A Guard decides from the message bytes alone; the broker does not interpret them. The
// shipped guard (internal/adapters/egress/mcpguard) checks the JSON-RPC method and tool
// NAME only - it does NOT validate payload bytes against the served span set. That
// byte-level boundary is core.Binding.AuthorizePayload via a separate EgressPort and is
// not part of this broker slice.
//
// Guard is defined here, where it is consumed, so the broker depends on no policy
// package; a concrete guard (e.g. a tool allowlist) satisfies it structurally.
type Guard interface {
	Check(msg []byte) (allow bool, denyReply []byte)
}

// Broker forwards messages between an agent-side transport and an upstream
// MCP-server transport. It holds no state beyond the two ports, an optional guard,
// and a write lock; a Broker is single-use - call [Broker.Run] once and create a new
// Broker for a new session.
type Broker struct {
	agent    ports.TransportPort
	upstream ports.TransportPort
	guard    Guard
	recorder Recorder
	filter   ResponseFilter

	// agentMu serializes writes to the agent transport. Once a guard is in play the
	// agent end is written by two goroutines - the upstream->agent pump and the
	// deny-reply path - and the underlying framer is not safe for concurrent writes,
	// so a frame could interleave without this lock.
	agentMu sync.Mutex
}

// New returns a pure-passthrough Broker that forwards between agent and upstream with
// no policy. Neither port is touched until [Broker.Run] is called.
func New(agent, upstream ports.TransportPort) *Broker {
	return &Broker{agent: agent, upstream: upstream}
}

// NewGuarded returns a Broker that runs every agent-to-upstream message through g
// before forwarding it. The upstream-to-agent direction is still pure passthrough.
func NewGuarded(agent, upstream ports.TransportPort, g Guard) *Broker {
	return &Broker{agent: agent, upstream: upstream, guard: g}
}

// Recorder is an optional audit sink. The broker calls Record on every agent-to-upstream
// message with the guard's allow/deny decision, before it acts on it. A Recorder decides
// itself which messages are worth recording (the shipped one records only tools/call). Like
// [Guard], it is defined here so the broker depends on no concrete logging package.
type Recorder interface {
	Record(msg []byte, allowed bool) error
}

// SetRecorder attaches an audit Recorder. It must be called before [Broker.Run]. A nil
// recorder (the default) means no audit log is written.
func (b *Broker) SetRecorder(r Recorder) { b.recorder = r }

// ResponseFilter optionally rewrites an upstream-to-agent message before it reaches the
// agent. It is used to trim a tools/list response down to the allowlist so the agent never
// loads the schema of a tool it could not call; a nil filter (the default) passes every
// message through unchanged. Like [Guard] and [Recorder], it is defined here so the broker
// depends on no concrete package, and it never blocks a message - the egress Guard does that.
type ResponseFilter interface {
	Filter(msg []byte) []byte
}

// SetResponseFilter attaches an upstream-to-agent filter. It must be called before
// [Broker.Run]. A nil filter (the default) means the upstream-to-agent direction is
// unchanged passthrough.
func (b *Broker) SetResponseFilter(f ResponseFilter) { b.filter = f }

// Run pumps messages in both directions - agent to upstream (guarded) and upstream to
// agent (plain) - until ctx is cancelled or either transport reports io.EOF.
//
// The two directions run as sibling goroutines whose lifetimes are tied to ctx: Run
// derives a cancellable child context and cancels it on return, so the first direction
// to finish tears down the other rather than leaving it blocked on a read. Run returns
// the first non-EOF, non-cancellation error observed; a clean stop (ctx cancelled or
// io.EOF on either side) returns nil.
func (b *Broker) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)
	go func() { errc <- b.pumpEgress(ctx) }()
	go func() { errc <- b.pumpToAgent(ctx) }()

	// Wait for the first direction to finish, cancel its sibling, then drain the
	// sibling so both goroutines have returned before Run does (no leak).
	first := <-errc
	cancel()
	second := <-errc

	if err := firstReal(first, second); err != nil {
		return err
	}
	return nil
}

// pumpEgress copies messages from the agent to the upstream, consulting the guard (if
// any) on each one. A rejected message is answered to the agent and dropped; the loop
// continues. A read or write that fails because ctx was cancelled, or a clean io.EOF, is
// reported as nil so a deliberate shutdown is not mistaken for a failure.
func (b *Broker) pumpEgress(ctx context.Context) error {
	for {
		msg, err := b.agent.Recv(ctx)
		if err != nil {
			return forwardErr(ctx, err)
		}
		allowed, reply := true, []byte(nil)
		if b.guard != nil {
			allowed, reply = b.guard.Check(msg)
		}
		// Audit before acting on the message. The receipt records the decision for every
		// tool call; if it cannot be written, the broker fails CLOSED - it stops rather than
		// forward an un-audited call, so there is never egress the log does not cover.
		if b.recorder != nil {
			if err := b.recorder.Record(msg, allowed); err != nil {
				return fmt.Errorf("broker: audit log write failed, stopping to avoid unaudited egress: %w", err)
			}
		}
		if !allowed {
			if reply != nil {
				if err := b.sendToAgent(ctx, reply); err != nil {
					return forwardErr(ctx, err)
				}
			}
			continue // blocked: not forwarded upstream; session continues
		}
		if err := b.upstream.Send(ctx, msg); err != nil {
			return forwardErr(ctx, err)
		}
	}
}

// pumpToAgent copies messages from the upstream to the agent, applying the optional
// [ResponseFilter] first; a nil filter is verbatim passthrough.
func (b *Broker) pumpToAgent(ctx context.Context) error {
	for {
		msg, err := b.upstream.Recv(ctx)
		if err != nil {
			return forwardErr(ctx, err)
		}
		if b.filter != nil {
			msg = b.filter.Filter(msg)
		}
		if err := b.sendToAgent(ctx, msg); err != nil {
			return forwardErr(ctx, err)
		}
	}
}

// sendToAgent writes msg to the agent transport under agentMu so concurrent writers
// (the upstream->agent pump and the egress deny-reply path) cannot interleave frames.
func (b *Broker) sendToAgent(ctx context.Context, msg []byte) error {
	b.agentMu.Lock()
	defer b.agentMu.Unlock()
	return b.agent.Send(ctx, msg)
}

// forwardErr maps a transport error to the broker's shutdown contract: a cancellation
// (because Run is tearing down) or a clean io.EOF is a normal stop and returns nil;
// anything else is a real error and is returned as-is.
func forwardErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// firstReal returns the first non-nil error among the two direction results, or nil if
// both stopped cleanly.
func firstReal(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
