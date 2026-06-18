package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akhilesharora/herkos/internal/ports"
	"go.uber.org/goleak"
)

// stubRecorder captures the (msg, allowed) pairs the broker hands it, and can be told to fail
// on a message containing failOn so the fail-closed path can be exercised.
type stubRecorder struct {
	mu     sync.Mutex
	calls  []stubRec
	failOn string
}

type stubRec struct {
	msg     []byte
	allowed bool
}

func (r *stubRecorder) Record(msg []byte, allowed bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failOn != "" && bytes.Contains(msg, []byte(r.failOn)) {
		return errors.New("audit write failed")
	}
	r.calls = append(r.calls, stubRec{append([]byte(nil), msg...), allowed})
	return nil
}

// stubGuard denies any agent->upstream message that contains denyMark, answering with a
// fixed reply, and forwards everything else. It exercises the broker's guard seam without
// pulling in a real policy package.
type stubGuard struct {
	denyMark string
	reply    []byte
}

func (g stubGuard) Check(msg []byte) (bool, []byte) {
	if bytes.Contains(msg, []byte(g.denyMark)) {
		return false, g.reply
	}
	return true, nil
}

// TestMain runs every test under goleak so a broker that fails to tear down its
// pump goroutines on shutdown fails the package rather than leaking silently.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// memTransport is an in-memory [ports.TransportPort] backed by a pair of
// channels: out is the channel a peer writes into via Send, in is the channel
// this end drains via Recv. Wiring two ends so that each one's out is the
// other's in yields a bidirectional link with no real I/O. Closing done unblocks
// any in-flight Recv with io.EOF so a transport can simulate a closed stream.
type memTransport struct {
	in   <-chan []byte
	out  chan<- []byte
	done chan struct{}
}

var _ ports.TransportPort = (*memTransport)(nil)

// newLink returns two transports wired back to back: a message sent on a is
// received on b and vice versa. cap sizes the underlying channels.
func newLink(capacity int) (a, b *memTransport) {
	ab := make(chan []byte, capacity)
	ba := make(chan []byte, capacity)
	a = &memTransport{in: ba, out: ab, done: make(chan struct{})}
	b = &memTransport{in: ab, out: ba, done: make(chan struct{})}
	return a, b
}

// Send delivers msg to the peer, or returns ctx.Err() if ctx is cancelled or
// io.EOF if this end has been closed, before the peer can receive it.
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

// Recv returns the next message from the peer, ctx.Err() on cancellation, or
// io.EOF once this end is closed.
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

// close unblocks any in-flight Send/Recv on this end with io.EOF.
func (t *memTransport) close() { close(t.done) }

func TestBrokerForwardsBothDirectionsUnmodified(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "request json", payload: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)},
		{name: "binary bytes", payload: []byte{0x00, 0x01, 0xff, 0x7f, 0x80}},
		{name: "empty", payload: []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// agentEnd / upstreamEnd are the broker's two ports. agentPeer is what
			// a real agent process would hold; upstreamPeer is the upstream server.
			agentEnd, agentPeer := newLink(1)
			upstreamEnd, upstreamPeer := newLink(1)

			b := New(agentEnd, upstreamEnd)
			runErr := make(chan error, 1)
			go func() { runErr <- b.Run(ctx) }()

			// Agent -> upstream: the upstream peer must see the bytes verbatim.
			if err := agentPeer.Send(ctx, tt.payload); err != nil {
				t.Fatalf("agent send: %v", err)
			}
			got, err := upstreamPeer.Recv(ctx)
			if err != nil {
				t.Fatalf("upstream recv: %v", err)
			}
			if !bytesEqual(got, tt.payload) {
				t.Fatalf("agent->upstream: got %q, want %q", got, tt.payload)
			}

			// Upstream -> agent: the agent peer must see the response verbatim.
			if err := upstreamPeer.Send(ctx, tt.payload); err != nil {
				t.Fatalf("upstream send: %v", err)
			}
			got, err = agentPeer.Recv(ctx)
			if err != nil {
				t.Fatalf("agent recv: %v", err)
			}
			if !bytesEqual(got, tt.payload) {
				t.Fatalf("upstream->agent: got %q, want %q", got, tt.payload)
			}

			cancel()
			if err := <-runErr; err != nil {
				t.Fatalf("Run returned error on cancel: %v", err)
			}
		})
	}
}

// TestGuardedBrokerBlocksDisallowedThenStaysAlive proves the egress seam: a message the
// guard rejects is NOT forwarded upstream, the agent gets the guard's deny reply, and the
// session keeps running so a following allowed message IS forwarded. The ordering check -
// upstream's first received message is the allowed one - is what proves the blocked
// message never reached upstream.
func TestGuardedBrokerBlocksDisallowedThenStaysAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)

	denyReply := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"blocked"}}`)
	g := stubGuard{denyMark: "delete_repo", reply: denyReply}

	b := NewGuarded(agentEnd, upstreamEnd, g)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	// Blocked: a tools/call for delete_repo. The agent receives the deny reply...
	blocked := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`)
	if err := agentPeer.Send(ctx, blocked); err != nil {
		t.Fatalf("agent send blocked: %v", err)
	}
	gotReply, err := agentPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("agent recv deny reply: %v", err)
	}
	if !bytesEqual(gotReply, denyReply) {
		t.Fatalf("agent should receive the guard deny reply: got %q, want %q", gotReply, denyReply)
	}

	// Allowed: a tools/call for read_file. It must reach upstream - and be the FIRST
	// thing upstream sees, which proves the blocked message was never forwarded.
	allowed := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`)
	if err := agentPeer.Send(ctx, allowed); err != nil {
		t.Fatalf("agent send allowed: %v", err)
	}
	gotUp, err := upstreamPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("upstream recv: %v", err)
	}
	if !bytesEqual(gotUp, allowed) {
		t.Fatalf("upstream's first message must be the allowed one (blocked one was forwarded?): got %q", gotUp)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run returned error on cancel: %v", err)
	}
}

// TestGuardedBrokerForwardsAllowedUpstreamReplyStillFlows confirms the upstream->agent
// direction stays pure passthrough under a guard.
func TestGuardedBrokerForwardsAllowedUpstreamReplyStillFlows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)

	g := stubGuard{denyMark: "never-matches", reply: []byte("x")}
	b := NewGuarded(agentEnd, upstreamEnd, g)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	if err := upstreamPeer.Send(ctx, resp); err != nil {
		t.Fatalf("upstream send: %v", err)
	}
	got, err := agentPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("agent recv: %v", err)
	}
	if !bytesEqual(got, resp) {
		t.Fatalf("upstream->agent must be verbatim under a guard: got %q, want %q", got, resp)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run returned error on cancel: %v", err)
	}
}

// TestGuardedBrokerNilReplyDropsSilently checks that a guard returning a nil reply blocks
// the message without sending anything back, and the session still serves later traffic.
func TestGuardedBrokerNilReplyDropsSilently(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)

	g := stubGuard{denyMark: "drop_me", reply: nil}
	b := NewGuarded(agentEnd, upstreamEnd, g)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	if err := agentPeer.Send(ctx, []byte(`{"method":"tools/call","params":{"name":"drop_me"}}`)); err != nil {
		t.Fatalf("agent send drop: %v", err)
	}
	// A following allowed message must still be forwarded (and be upstream's first).
	allowed := []byte(`{"method":"tools/call","params":{"name":"ok"}}`)
	if err := agentPeer.Send(ctx, allowed); err != nil {
		t.Fatalf("agent send allowed: %v", err)
	}
	got, err := upstreamPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("upstream recv: %v", err)
	}
	if !bytesEqual(got, allowed) {
		t.Fatalf("silently dropped message must not reach upstream: got %q", got)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run returned error on cancel: %v", err)
	}
}

func TestBrokerCleanShutdownOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	agentEnd, _ := newLink(1)
	upstreamEnd, _ := newLink(1)

	b := New(agentEnd, upstreamEnd)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	// Both directions are idle (blocked in Recv); cancelling must return cleanly.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel - goroutines may be leaked")
	}
	// goleak in TestMain asserts both pump goroutines have exited.
}

func TestBrokerStopsOnUpstreamEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, _ := newLink(1)
	upstreamEnd, _ := newLink(1)

	b := New(agentEnd, upstreamEnd)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	// Upstream closing its stream is a clean stop, not an error.
	upstreamEnd.close()
	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("Run returned unexpected error on upstream EOF: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of upstream EOF")
	}
}

// TestBrokerRecordsAllowAndDeny proves the audit hook sees every brokered tool call with the
// guard's decision: a denied call is recorded allowed=false, an allowed call allowed=true.
func TestBrokerRecordsAllowAndDeny(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)
	g := stubGuard{denyMark: "delete_repo", reply: []byte(`{"error":"no"}`)}
	rec := &stubRecorder{}
	b := NewGuarded(agentEnd, upstreamEnd, g)
	b.SetRecorder(rec)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	// Denied: draining the deny reply guarantees Record already ran for it.
	if err := agentPeer.Send(ctx, []byte(`{"method":"tools/call","params":{"name":"delete_repo"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := agentPeer.Recv(ctx); err != nil {
		t.Fatal(err)
	}
	// Allowed: draining the forwarded message guarantees Record already ran for it.
	allowed := []byte(`{"method":"tools/call","params":{"name":"read_file"}}`)
	if err := agentPeer.Send(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamPeer.Recv(ctx); err != nil {
		t.Fatal(err)
	}

	cancel()
	<-runErr

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 2 {
		t.Fatalf("recorded %d calls, want 2", len(rec.calls))
	}
	if rec.calls[0].allowed {
		t.Error("delete_repo should be recorded allowed=false")
	}
	if !rec.calls[1].allowed {
		t.Error("read_file should be recorded allowed=true")
	}
}

// TestBrokerFailsClosedOnRecordError proves the audit invariant: if the receipt cannot be
// written, the broker stops the session rather than forward an unaudited call.
func TestBrokerFailsClosedOnRecordError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, _ := newLink(1)
	rec := &stubRecorder{failOn: "read_file"}
	b := New(agentEnd, upstreamEnd) // no guard: the call would otherwise be forwarded
	b.SetRecorder(rec)
	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx) }()

	if err := agentPeer.Send(ctx, []byte(`{"method":"tools/call","params":{"name":"read_file"}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runErr:
		if err == nil || !strings.Contains(err.Error(), "audit") {
			t.Fatalf("Run must stop with an audit error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not fail closed on audit write failure")
	}
	// The broker returned before reaching upstream.Send (record happens first), so the call
	// was never forwarded - the fail-closed guarantee.
}

// BenchmarkForwardRoundtrip measures the per-message round-trip overhead of
// pushing a request through the broker to the upstream and a response back to
// the agent, using the in-memory transports so the number reflects broker and
// channel cost rather than real I/O.
func BenchmarkForwardRoundtrip(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)

	br := New(agentEnd, upstreamEnd)
	go func() { _ = br.Run(ctx) }()

	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)

	b.SetBytes(int64(len(req) + len(resp)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := agentPeer.Send(ctx, req); err != nil {
			b.Fatalf("agent send: %v", err)
		}
		if _, err := upstreamPeer.Recv(ctx); err != nil {
			b.Fatalf("upstream recv: %v", err)
		}
		if err := upstreamPeer.Send(ctx, resp); err != nil {
			b.Fatalf("upstream send: %v", err)
		}
		if _, err := agentPeer.Recv(ctx); err != nil {
			b.Fatalf("agent recv: %v", err)
		}
	}
}

// bytesEqual reports whether two byte slices have identical contents, treating
// nil and empty as equal so the empty-payload case round-trips cleanly.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stubFilter rewrites every upstream-to-agent message through replace, proving the broker
// applies a ResponseFilter in pumpToAgent.
type stubFilter struct{ replace func([]byte) []byte }

func (s stubFilter) Filter(msg []byte) []byte { return s.replace(msg) }

func TestResponseFilterRewritesUpstreamToAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentEnd, agentPeer := newLink(1)
	upstreamEnd, upstreamPeer := newLink(1)
	br := New(agentEnd, upstreamEnd)
	br.SetResponseFilter(stubFilter{func(b []byte) []byte { return append([]byte("filtered:"), b...) }})

	done := make(chan error, 1)
	go func() { done <- br.Run(ctx) }()

	if err := upstreamPeer.Send(ctx, []byte("hello")); err != nil {
		t.Fatalf("upstream send: %v", err)
	}
	got, err := agentPeer.Recv(ctx)
	if err != nil {
		t.Fatalf("agent recv: %v", err)
	}
	if string(got) != "filtered:hello" {
		t.Fatalf("agent should receive the filtered message, got %q", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
}
