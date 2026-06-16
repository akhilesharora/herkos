package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akhilesharora/herkos/internal/adapters/transport/mcpstdio"
)

// TestHelperProcess is not a real test: when HERKOS_HELPER=1 it impersonates an upstream
// MCP server for TestServeProxiesAllowedCallThroughSubprocess. It echoes a canned response
// to each framed request and exits when its stdin closes (the standard os/exec
// helper-process pattern). Staying alive across requests avoids racing its own exit against
// the broker relaying the reply.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("HERKOS_HELPER") != "1" {
		return
	}
	f := mcpstdio.NewFramer(os.Stdin, os.Stdout)
	for {
		if _, err := f.ReadMessage(); err != nil {
			os.Exit(0)
		}
		if err := f.WriteMessage([]byte(`{"jsonrpc":"2.0","id":2,"result":{"echo":true}}`)); err != nil {
			os.Exit(0)
		}
	}
}

func TestServeMissingUpstreamExits2(t *testing.T) {
	code, _, errb := run("serve", "--allow-tool", "read_file")
	if code != 2 {
		t.Fatalf("serve with no upstream command exit=%d want 2", code)
	}
	if !strings.Contains(errb, "missing upstream") {
		t.Fatalf("expected a missing-upstream message, got %q", errb)
	}
}

// TestServeProxiesAllowedCallThroughSubprocess is the capstone e2e: a real `herkos serve`
// spawns a real upstream subprocess, forwards an allowed tools/call to it, and relays the
// upstream's framed response back to the agent. The agent is simulated over pipes that stay
// open for the whole session (as a real MCP client's stdio would), then disconnects to end
// it - which is what lets the broker forward the reply before tearing down.
func TestServeProxiesAllowedCallThroughSubprocess(t *testing.T) {
	t.Setenv("HERKOS_HELPER", "1") // inherited by the spawned upstream
	keyPath := filepath.Join(t.TempDir(), "key")

	agentInR, agentInW := io.Pipe()   // agent -> herkos stdin
	agentOutR, agentOutW := io.Pipe() // herkos stdout -> agent
	errb := &syncBuf{}

	done := make(chan int, 1)
	args := []string{
		"--allow-tool", "read_file",
		"--key", keyPath,
		"--", os.Args[0], "-test.run=TestHelperProcess",
	}
	go func() { done <- serveCmd(args, agentInR, agentOutW, errb) }()

	agent := mcpstdio.NewFramer(agentOutR, agentInW) // write requests, read relayed responses
	if err := agent.WriteMessage(
		[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`),
	); err != nil {
		t.Fatalf("agent write request: %v", err)
	}
	resp, err := agent.ReadMessage()
	if err != nil {
		t.Fatalf("agent read relayed response: %v (stderr=%q)", err, errb.String())
	}
	if !bytes.Contains(resp, []byte(`"echo":true`)) {
		t.Fatalf("relayed response not from upstream: %q", resp)
	}

	// Agent disconnects, ending the session; serve must return cleanly.
	_ = agentInW.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit=%d stderr=%q", code, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("serve did not return after agent disconnect (stderr=%q)", errb.String())
	}
	if !strings.Contains(errb.String(), "signing key") {
		t.Fatalf("serve should announce the signing key on stderr: %q", errb.String())
	}
}

// syncBuf is a goroutine-safe buffer: serve writes its banner to it while exec concurrently
// copies the child's stderr into it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
