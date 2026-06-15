package mcpguard

import (
	"encoding/json"
	"strings"
	"testing"
)

// rpcError mirrors the deny-reply shape so tests can assert on the parsed response
// instead of matching raw bytes.
type rpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func parseReply(t *testing.T, b []byte) rpcError {
	t.Helper()
	var r rpcError
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("deny reply is not valid JSON: %v (%q)", err, b)
	}
	if r.JSONRPC != "2.0" {
		t.Fatalf("deny reply jsonrpc = %q, want 2.0", r.JSONRPC)
	}
	if r.Error.Code != denyCode {
		t.Fatalf("deny reply code = %d, want %d", r.Error.Code, denyCode)
	}
	return r
}

func TestAllowedToolPasses(t *testing.T) {
	g := New("read_file", "list_dir")
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)
	allow, reply := g.Check(msg)
	if !allow || reply != nil {
		t.Fatalf("allowed tool: allow=%v reply=%q, want allow=true reply=nil", allow, reply)
	}
}

func TestDisallowedToolDenied(t *testing.T) {
	g := New("read_file")
	msg := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repo"}}`)
	allow, reply := g.Check(msg)
	if allow {
		t.Fatal("disallowed tool must be denied")
	}
	r := parseReply(t, reply)
	if string(r.ID) != "7" {
		t.Fatalf("deny reply must echo request id 7, got %s", r.ID)
	}
	if !strings.Contains(r.Error.Message, "delete_repo") {
		t.Fatalf("deny message should name the blocked tool: %q", r.Error.Message)
	}
}

func TestEmptyAllowlistDeniesEveryToolCall(t *testing.T) {
	g := New() // deny-by-default
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anything"}}`)
	if allow, _ := g.Check(msg); allow {
		t.Fatal("empty allowlist must deny every tools/call (deny-by-default)")
	}
}

func TestControlMethodsPass(t *testing.T) {
	g := New() // even with an empty allowlist, control traffic must flow
	for _, m := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		allow, reply := g.Check([]byte(m))
		if !allow || reply != nil {
			t.Fatalf("control method must pass: %s -> allow=%v reply=%q", m, allow, reply)
		}
	}
}

func TestMalformedFailsClosed(t *testing.T) {
	g := New("read_file")
	allow, reply := g.Check([]byte(`{not valid json`))
	if allow {
		t.Fatal("unparseable message must fail closed (deny)")
	}
	r := parseReply(t, reply)
	if string(r.ID) != "null" {
		t.Fatalf("deny reply for unparseable input must use id null, got %s", r.ID)
	}
}

func TestBatchArrayFailsClosed(t *testing.T) {
	g := New("read_file")
	// A JSON-RPC batch is a valid JSON array but not an object; v1 does not inspect
	// batches and must fail closed rather than wave it through.
	if allow, _ := g.Check([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}]`)); allow {
		t.Fatal("a batch array must fail closed in v1")
	}
}

func TestDenyReplyEchoesStringID(t *testing.T) {
	g := New("read_file")
	msg := []byte(`{"jsonrpc":"2.0","id":"req-abc","method":"tools/call","params":{"name":"nope"}}`)
	_, reply := g.Check(msg)
	r := parseReply(t, reply)
	if string(r.ID) != `"req-abc"` {
		t.Fatalf("deny reply must echo string id verbatim, got %s", r.ID)
	}
}

func TestDenyMessageStaysValidJSONWithHostileToolName(t *testing.T) {
	g := New("read_file")
	// A tool name carrying quotes/newlines must not break the reply frame.
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a\"b\nc"}}`)
	allow, reply := g.Check(msg)
	if allow {
		t.Fatal("hostile tool name not on allowlist must be denied")
	}
	parseReply(t, reply) // must still parse as valid JSON-RPC
}

func TestMissingToolNameDenied(t *testing.T) {
	g := New("read_file")
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	if allow, _ := g.Check(msg); allow {
		t.Fatal("tools/call with no tool name must be denied (empty name not on allowlist)")
	}
}

// TestEmptyNameDeniedEvenIfAllowlisted guards against a blank config line (New("")) putting
// "" into the allowlist: a nameless tools/call must STILL be denied. An empty tool name is
// never a legitimate call, so the deny is unconditional, independent of the allowlist.
func TestEmptyNameDeniedEvenIfAllowlisted(t *testing.T) {
	g := New("") // a stray empty entry slipped into the allowlist
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":""}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":null}}`,
	} {
		if allow, _ := g.Check([]byte(msg)); allow {
			t.Fatalf("empty tool name must be denied even if \"\" is allowlisted: %s", msg)
		}
	}
}

// TestMethodCaseInsensitive proves a case variant of tools/call cannot slip past the guard
// as "control traffic". The guard, not the upstream's case handling, must make the deny
// decision, so any casing of the tool-call method is routed through the allowlist.
func TestMethodCaseInsensitive(t *testing.T) {
	g := New("read_file")
	for _, m := range []string{"Tools/Call", "TOOLS/CALL", "tools/Call", " tools/call "} {
		msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + m + `","params":{"name":"delete_repo"}}`)
		if allow, _ := g.Check(msg); allow {
			t.Fatalf("case/whitespace variant %q with a disallowed tool must be denied", m)
		}
	}
	// A case variant with an ALLOWED tool still passes (we gate the name, not the casing).
	if allow, _ := g.Check([]byte(`{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"read_file"}}`)); !allow {
		t.Fatal("case variant with an allowed tool should pass the allowlist")
	}
}
