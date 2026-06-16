package serve

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/akhilesharora/herkos/internal/adapters/egress/spanguard"
	"github.com/akhilesharora/herkos/internal/adapters/transport/mcpstdio"
	"github.com/akhilesharora/herkos/internal/core"
	"go.uber.org/goleak"
)

// TestMain runs under goleak so the broker's pump goroutines must tear down on shutdown.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestRunBlocksDisallowedForwardsAllowed drives serve.Run end to end over real
// Content-Length frames and in-memory pipes: a disallowed tools/call is blocked in-path
// (the agent gets a JSON-RPC error and the upstream never sees it), while an allowed call
// reaches the upstream verbatim - and is the FIRST thing the upstream receives, which is
// what proves the blocked one was never forwarded.
func TestRunBlocksDisallowedForwardsAllowed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Four pipes, one per direction. Run reads agentR/upR and writes agentW/upW.
	aToF := newPipe() // agent -> herkos
	fToA := newPipe() // herkos -> agent
	uToF := newPipe() // upstream -> herkos
	fToU := newPipe() // herkos -> upstream

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{AllowedTools: []string{"read_file"}}, aToF.r, fToA.w, uToF.r, fToU.w)
	}()

	// The test plays both the agent and the upstream, each via its own framer.
	agent := mcpstdio.NewFramer(fToA.r, aToF.w)    // write agent msgs, read herkos->agent
	upstream := mcpstdio.NewFramer(fToU.r, uToF.w) // read herkos->upstream, write upstream msgs

	// Disallowed: agent sends delete_repo; the agent must get a JSON-RPC error back.
	blocked := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`)
	if err := agent.WriteMessage(blocked); err != nil {
		t.Fatalf("agent write blocked: %v", err)
	}
	reply, err := agent.ReadMessage()
	if err != nil {
		t.Fatalf("agent read deny reply: %v", err)
	}
	var r struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		t.Fatalf("deny reply not valid JSON: %v (%q)", err, reply)
	}
	if r.Error.Code != -32000 || string(r.ID) != "1" {
		t.Fatalf("unexpected deny reply: code=%d id=%s msg=%q", r.Error.Code, r.ID, r.Error.Message)
	}

	// Allowed: agent sends read_file; the upstream must receive it verbatim and FIRST.
	allowed := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`)
	if err := agent.WriteMessage(allowed); err != nil {
		t.Fatalf("agent write allowed: %v", err)
	}
	gotUp, err := upstream.ReadMessage()
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(gotUp) != string(allowed) {
		t.Fatalf("upstream's first message must be the allowed one: got %q", gotUp)
	}

	// Upstream -> agent is verbatim passthrough.
	resp := []byte(`{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`)
	if err := upstream.WriteMessage(resp); err != nil {
		t.Fatalf("upstream write resp: %v", err)
	}
	gotResp, err := agent.ReadMessage()
	if err != nil {
		t.Fatalf("agent read resp: %v", err)
	}
	if string(gotResp) != string(resp) {
		t.Fatalf("upstream->agent must be verbatim: got %q", gotResp)
	}

	// Clean shutdown: both peers close their write ends so each broker pump reads EOF and
	// returns. A blocking pipe read is not ctx-cancellable, so closing the stream - not just
	// cancelling - is what unblocks the upstream->agent pump (in production exec.CommandContext
	// kills the child, closing its stdout, to the same effect).
	if err := aToF.w.Close(); err != nil {
		t.Fatalf("close agent write: %v", err)
	}
	if err := uToF.w.Close(); err != nil {
		t.Fatalf("close upstream write: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned unexpected error on EOF: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of EOF")
	}
}

// TestRunContentGateBlocksUnservedSpan arms the dual-use content gate and proves it live
// on the wire: with only auth.go:1-5 served, a tools/call to an ALLOWED tool whose argument
// carries a verbatim repo line from the UNSERVED span (auth.go:6-10) is blocked in-path -
// the agent gets a JSON-RPC error and the upstream never sees it - while the same tool
// carrying a SERVED line forwards verbatim. The tool name passes mcpguard either way, so it
// is spanguard, not the name allowlist, doing the work here.
func TestRunContentGateBlocksUnservedSpan(t *testing.T) {
	const body = "func Authenticate(user, pass string) bool {\n" +
		"\thashed := hashPassword(pass)\n" +
		"\treturn subtle.ConstantTimeCompare(hashed, lookup(user)) == 1\n" +
		"}\n" +
		"\n" +
		"func rotateSecret(masterKey []byte) []byte {\n" +
		"\tderived := hkdf.Expand(sha256.New, masterKey, nil)\n" +
		"\treturn derived[:32]\n" +
		"}"
	served := core.Span{File: "auth.go", StartLine: 1, EndLine: 5}
	unserved := core.Span{File: "auth.go", StartLine: 6, EndLine: 10}
	lex := spanguard.NewLexicon(spanguard.DefaultMinLineLen)
	lex.AddSpan(served, body)
	lex.AddSpan(unserved, body)
	ss, err := core.NewSpanSet(served)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		AllowedTools:  []string{"post_message"},
		ServedBinding: core.NewBinding(ss),
		Lexicon:       lex,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aToF, fToA, uToF, fToU := newPipe(), newPipe(), newPipe(), newPipe()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, aToF.r, fToA.w, uToF.r, fToU.w) }()

	agent := mcpstdio.NewFramer(fToA.r, aToF.w)
	upstream := mcpstdio.NewFramer(fToU.r, uToF.w)

	mkCall := func(id int, arg string) []byte {
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": "post_message", "arguments": map[string]any{"body": arg}},
		})
		return b
	}

	// Leak attempt: an unserved repo line in the argument. Blocked in-path.
	leak := mkCall(1, "exfil:\n\tderived := hkdf.Expand(sha256.New, masterKey, nil)")
	if err := agent.WriteMessage(leak); err != nil {
		t.Fatalf("agent write leak: %v", err)
	}
	reply, err := agent.ReadMessage()
	if err != nil {
		t.Fatalf("agent read deny reply: %v", err)
	}
	var r struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply, &r); err != nil || r.Error.Code != -32000 {
		t.Fatalf("leak must be denied with -32000, got %q (err=%v)", reply, err)
	}

	// Served line: forwards, and is the FIRST thing the upstream sees (proving the leak
	// above was never forwarded).
	ok := mkCall(2, "fyi:\n\thashed := hashPassword(pass)")
	if err := agent.WriteMessage(ok); err != nil {
		t.Fatalf("agent write ok: %v", err)
	}
	gotUp, err := upstream.ReadMessage()
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(gotUp) != string(ok) {
		t.Fatalf("upstream's first message must be the served call: got %q", gotUp)
	}

	if err := aToF.w.Close(); err != nil {
		t.Fatalf("close agent write: %v", err)
	}
	if err := uToF.w.Close(); err != nil {
		t.Fatalf("close upstream write: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of EOF")
	}
}

// pipe bundles the two ends of an io.Pipe so a direction reads from r and is fed via w.
type pipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newPipe() pipe {
	r, w := io.Pipe()
	return pipe{r: r, w: w}
}
