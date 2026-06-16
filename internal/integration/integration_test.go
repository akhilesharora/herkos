// Package integration wires Herkos's real adapters together and proves the SpanGate
// dual-use guarantee end-to-end across package boundaries: a single SELECT produces
// one Binding that is BOTH the context served to the model AND the egress allowlist,
// and the broker forwards bytes while the egress decision (not the broker) is what
// blocks an out-of-span leak.
//
// Unlike internal/spangate's in-package test, this exercises the assembled system the
// way main does: mockgraph -> spangate.Pipeline -> a real pool, a real userspace egress
// adapter, and the real broker over in-memory transports. It is a test-only package.
package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/akhilesharora/herkos/internal/adapters/egress/userspace"
	"github.com/akhilesharora/herkos/internal/adapters/graph/mockgraph"
	"github.com/akhilesharora/herkos/internal/adapters/pool"
	"github.com/akhilesharora/herkos/internal/broker"
	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/ports"
	"github.com/akhilesharora/herkos/internal/spangate"
	"github.com/akhilesharora/herkos/pkg/receipt"
	"go.uber.org/goleak"
)

// TestMain runs every test under goleak: the broker spawns pump goroutines, so a
// failure to tear them down on shutdown fails the package instead of leaking silently.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fixtureGraph returns a two-node graph. The "Auth" anchor force-includes Auth (hop 0)
// and its neighbour DB (hop 1) via the edge, so a query anchored on "Auth" with ample
// budget serves the span set {auth.go:1-20, db.go:1-30}. secret.go is deliberately NOT
// reachable: it is the out-of-span region a malicious tool-call would try to exfiltrate.
func fixtureGraph() *mockgraph.Graph {
	return mockgraph.New([]spanselect.Node{
		{Symbol: "Auth", Span: core.Span{File: "auth.go", StartLine: 1, EndLine: 20}, Edges: []int{1}},
		{Symbol: "DB", Span: core.Span{File: "db.go", StartLine: 1, EndLine: 30}},
	})
}

// serve runs the real SpanGate pipeline (mockgraph + pool) and returns the dual-use
// Binding plus the signed receipt. read supplies deterministic per-span source bytes so
// the receipt's Merkle root is reproducible.
func serve(t *testing.T, priv ed25519.PrivateKey, enforcement string) (core.Binding, receipt.Receipt, core.Query) {
	t.Helper()
	pl := spangate.New(fixtureGraph(), pool.New(), priv, enforcement)
	q := core.Query{Anchors: []string{"Auth"}, LineBudget: 100}
	read := func(s core.Span) []byte { return []byte("source of " + s.String()) }
	b, rcpt, err := pl.Serve(context.Background(), q, read)
	if err != nil {
		t.Fatalf("pipeline serve: %v", err)
	}
	return b, rcpt, q
}

// TestServedSetIsEnforcedSet proves the SpanGate invariant across the real adapters:
//  1. Serve yields a Binding plus a receipt that verifies OFFLINE with only the public key.
//  2. The receipt's enforcement label matches the egress adapter actually mediating egress.
//  3. A MALICIOUS tool-call response that carries OUT-OF-SPAN bytes is DENIED by the
//     userspace egress adapter run against that same Binding, while an in-binding payload
//     is allowed. The served set IS the enforced set.
func TestServedSetIsEnforcedSet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	eg := userspace.New()
	binding, rcpt, _ := serve(t, priv, eg.Enforcement())

	// (2) The receipt verifies offline and is stamped with the active enforcement mode.
	if err := rcpt.Verify(pub); err != nil {
		t.Fatalf("receipt must verify offline with the public key: %v", err)
	}
	if rcpt.Verify(otherPub(t)) == nil {
		t.Fatal("receipt must NOT verify under a different public key")
	}
	// The receipt's enforcement label matches the egress adapter actually mediating egress.
	if rcpt.Enforcement != eg.Enforcement() {
		t.Fatalf("receipt enforcement %q must match active egress mode %q", rcpt.Enforcement, eg.Enforcement())
	}
	if rcpt.Enforcement != userspace.EnforcementLabel {
		t.Fatalf("enforcement label: got %q, want %q", rcpt.Enforcement, userspace.EnforcementLabel)
	}

	// The served set is exactly {auth.go:1-20, db.go:1-30}: Auth (anchor) plus DB (neighbour).
	if got := binding.SpanSet().Len(); got != 2 {
		t.Fatalf("served binding span count: got %d, want 2 (Auth + DB)", got)
	}

	ctx := context.Background()

	// (3a) In-binding payload: a tool response derived from a served span is ALLOWED.
	allowed := core.EgressRequest{
		Server:      "github",
		Payload:     []byte("answer derived from served auth.go"),
		SourceSpans: []core.Span{{File: "auth.go", StartLine: 2, EndLine: 10}},
	}
	if d := eg.Authorize(ctx, binding, allowed); !d.Allowed() {
		t.Fatalf("in-binding payload must be allowed: reason=%s detail=%s", d.Reason(), d.Detail())
	}

	// (3b) MALICIOUS payload: a tool-call response that tries to carry OUT-OF-SPAN bytes
	// (secret.go was never served) is DENIED. The leak is blocked at the egress boundary.
	leak := core.EgressRequest{
		Server:      "github",
		Payload:     []byte("exfiltrated secret.go contents"),
		SourceSpans: []core.Span{{File: "secret.go", StartLine: 1, EndLine: 9}},
	}
	d := eg.Authorize(ctx, binding, leak)
	if d.Allowed() {
		t.Fatal("malicious out-of-span payload must be DENIED (leak prevented)")
	}
	if d.Reason() != core.ReasonOutsideAllowlist {
		t.Fatalf("deny reason: got %q, want %q", d.Reason(), core.ReasonOutsideAllowlist)
	}

	// (3c) A payload whose provenance MIXES an in-span and an out-of-span source is also
	// denied: a single out-of-span source span taints the whole payload.
	mixed := core.EgressRequest{
		Server:      "github",
		Payload:     []byte("mostly auth.go but smuggling secret.go"),
		SourceSpans: []core.Span{{File: "auth.go", StartLine: 2, EndLine: 10}, {File: "secret.go", StartLine: 1, EndLine: 9}},
	}
	if eg.Authorize(ctx, binding, mixed).Allowed() {
		t.Fatal("payload mixing in-span and out-of-span provenance must be DENIED")
	}

	// (3d) A payload that overruns a served span's bounds (auth.go:1-20 was served, but the
	// payload claims auth.go:1-25) is NOT covered: Covers requires full enclosure, so the
	// overrun is denied even though the file matches.
	overrun := core.EgressRequest{
		Server:      "github",
		Payload:     []byte("auth.go plus a few unserved lines"),
		SourceSpans: []core.Span{{File: "auth.go", StartLine: 1, EndLine: 25}},
	}
	if eg.Authorize(ctx, binding, overrun).Allowed() {
		t.Fatal("payload overrunning a served span's bounds must be DENIED")
	}

	// A payload with NO provenance is denied: fail-closed by default.
	if eg.Authorize(ctx, binding, core.EgressRequest{Server: "github", Payload: []byte("x")}).Allowed() {
		t.Fatal("payload with no provenance must be DENIED (fail-closed)")
	}
}

// TestBrokerForwardsWhileEgressGates routes a request and a (malicious) response through
// the real broker between two in-memory transports and shows the division of labour: the
// BROKER forwards the upstream tool-call response verbatim (it is pure plumbing and holds
// no policy), and a SEPARATE userspace egress check against the served Binding is what
// blocks the out-of-span payload. The broker is not the gate; the egress decision is.
func TestBrokerForwardsWhileEgressGates(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	eg := userspace.New()
	binding, _, _ := serve(t, priv, eg.Enforcement())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Wire the broker between an agent-side transport and an upstream-server transport.
	// agentEnd / upstreamEnd are the broker's two ports; agentPeer is the agent process,
	// upstreamPeer is the (malicious) upstream MCP server.
	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)

	br := broker.New(agentEnd, upstreamEnd)
	runErr := make(chan error, 1)
	go func() { runErr <- br.Run(ctx) }()

	// Agent -> upstream: a tool-call request is forwarded verbatim.
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	if err := agentPeer.Send(ctx, req); err != nil {
		t.Fatalf("agent send request: %v", err)
	}
	gotReq, err := upstreamPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("upstream recv request: %v", err)
	}
	if string(gotReq) != string(req) {
		t.Fatalf("broker altered request: got %q, want %q", gotReq, req)
	}

	// Upstream -> agent: a MALICIOUS response that smuggles out-of-span bytes. The broker
	// forwards it verbatim - it does no inspection - so the agent peer receives it.
	maliciousResp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"text":"contents of secret.go"}}`)
	if err := upstreamPeer.Send(ctx, maliciousResp); err != nil {
		t.Fatalf("upstream send response: %v", err)
	}
	gotResp, err := agentPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("agent recv response: %v", err)
	}
	if string(gotResp) != string(maliciousResp) {
		t.Fatalf("broker is plumbing and must forward verbatim: got %q, want %q", gotResp, maliciousResp)
	}

	// The broker forwarded the bytes; it is NOT the policy point. The egress decision is.
	// Modelling that response as an outbound egress derived from the unserved secret.go,
	// the userspace adapter DENIES it against the served Binding - the leak is blocked
	// here, not by the broker.
	leak := core.EgressRequest{
		Server:      "github",
		Payload:     gotResp,
		SourceSpans: []core.Span{{File: "secret.go", StartLine: 1, EndLine: 9}},
	}
	if d := eg.Authorize(ctx, binding, leak); d.Allowed() {
		t.Fatal("egress must deny the out-of-span payload the broker forwarded")
	}

	// A benign response derived from a served span passes the egress check, confirming the
	// gate blocks leaks specifically rather than everything.
	benign := core.EgressRequest{
		Server:      "github",
		Payload:     []byte(`{"jsonrpc":"2.0","id":2,"result":{"text":"served auth.go summary"}}`),
		SourceSpans: []core.Span{{File: "auth.go", StartLine: 2, EndLine: 10}},
	}
	if d := eg.Authorize(ctx, binding, benign); !d.Allowed() {
		t.Fatalf("egress must allow the in-span payload: reason=%s", d.Reason())
	}

	// Clean shutdown: cancel, then confirm Run returns without error and goleak (TestMain)
	// asserts both pump goroutines exited.
	cancel()
	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("broker Run returned unexpected error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker Run did not return within 2s of cancel - goroutines may be leaked")
	}
}

// otherPub returns a public key from a different keypair, used to prove the receipt does
// not verify under the wrong key.
func otherPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	return pub
}

// memTransport is an in-memory [ports.TransportPort] backed by a pair of channels: out is
// the channel a peer writes into via Send, in is the channel this end drains via Recv.
// Wiring two ends so each one's out is the other's in yields a bidirectional link with no
// real I/O. Closing done unblocks any in-flight Send/Recv with io.EOF.
type memTransport struct {
	in   <-chan []byte
	out  chan<- []byte
	done chan struct{}
}

var _ ports.TransportPort = (*memTransport)(nil)

// newLink returns two transports wired back to back: a message sent on a is received on b
// and vice versa. capacity sizes the underlying channels.
func newLink(capacity int) (a, b *memTransport) {
	ab := make(chan []byte, capacity)
	ba := make(chan []byte, capacity)
	a = &memTransport{in: ba, out: ab, done: make(chan struct{})}
	b = &memTransport{in: ab, out: ba, done: make(chan struct{})}
	return a, b
}

// Send delivers msg to the peer, or returns ctx.Err() on cancellation / io.EOF if this end
// has been closed before the peer can receive it.
func (t *memTransport) Send(ctx context.Context, msg []byte) error {
	select {
	case t.out <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return io.EOF
	}
}

// Recv returns the next message from the peer, ctx.Err() on cancellation, or io.EOF once
// this end is closed.
func (t *memTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg := <-t.in:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, io.EOF
	}
}
