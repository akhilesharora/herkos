package mcpguard

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzCheckFailsClosed is the red-team review turned into a standing check: for ANY bytes,
// Check must not panic, any deny reply must be valid JSON-RPC, and the fail-closed invariant
// must hold - a tools/call (in any casing, with whitespace) whose tool name is not exactly
// on the allowlist is NEVER allowed. This is the property the manual review verified by
// hand (the empty-name and Tools/Call bypasses); fuzzing keeps it verified.
func FuzzCheckFailsClosed(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"delete_repo"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}]`,
		`{not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	g := New("read_file") // only read_file is allowed

	f.Fuzz(func(t *testing.T, msg []byte) {
		allow, reply := g.Check(msg) // must never panic

		// A deny must carry a valid JSON-RPC reply (or nil); never garbage.
		if !allow && reply != nil {
			var v map[string]any
			if err := json.Unmarshal(reply, &v); err != nil {
				t.Fatalf("deny reply is not valid JSON: %v (%q)", err, reply)
			}
		}
		// An allow never carries a reply.
		if allow && reply != nil {
			t.Fatalf("an allowed message must not carry a deny reply: %q", reply)
		}

		// Fail-closed invariant: if msg is a tools/call (any casing/whitespace) for a tool
		// that is not exactly "read_file", it must be denied.
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(msg, &req) == nil {
			if strings.EqualFold(strings.TrimSpace(req.Method), "tools/call") && req.Params.Name != "read_file" {
				if allow {
					t.Fatalf("fail-closed violated: tools/call for %q was allowed (msg=%q)", req.Params.Name, msg)
				}
			}
		}
	})
}
