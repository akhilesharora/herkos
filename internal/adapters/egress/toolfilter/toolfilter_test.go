package toolfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// toolNames pulls result.tools[].name out of a filtered message for assertions.
func toolNames(t *testing.T, msg []byte) []string {
	t.Helper()
	var top struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(msg, &top); err != nil {
		t.Fatalf("filtered message is not valid JSON: %v", err)
	}
	var names []string
	for _, tl := range top.Result.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestFiltersToolsListToAllowed(t *testing.T) {
	f := New("echo", "read_file")
	in := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		`{"name":"echo","description":"e","inputSchema":{"type":"object"}},` +
		`{"name":"add","description":"a"},` +
		`{"name":"read_file","description":"r"},` +
		`{"name":"delete_repo","description":"d"}]}}`)
	got := toolNames(t, f.Filter(in))
	want := map[string]bool{"echo": true, "read_file": true}
	if len(got) != 2 {
		t.Fatalf("want 2 tools kept, got %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("tool %q should have been filtered out; got %v", n, got)
		}
	}
	// The kept tool's schema must survive intact (the point is fewer tokens,
	// not a stripped schema for the tools that remain).
	if !strings.Contains(string(f.Filter(in)), `"inputSchema"`) {
		t.Fatal("kept tool lost its inputSchema")
	}
}

func TestPassesNonToolsListThrough(t *testing.T) {
	f := New("echo")
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}`, // tools/call response
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo"}}`,     // a request, not a response
		`{"jsonrpc":"2.0","id":4,"result":{}}`,                                        // result without tools
		`{"jsonrpc":"2.0","id":5,"error":{"code":-32000,"message":"x"}}`,              // an error response
		`not json at all`,
	} {
		if got := string(f.Filter([]byte(msg))); got != msg {
			t.Fatalf("message should pass through unchanged:\n in:  %s\n out: %s", msg, got)
		}
	}
}

func TestEmptyAllowlistTrimsEveryTool(t *testing.T) {
	f := New() // deny-all
	in := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"},{"name":"add"}]}}`)
	if got := toolNames(t, f.Filter(in)); len(got) != 0 {
		t.Fatalf("empty allowlist must trim all tools, got %v", got)
	}
}
