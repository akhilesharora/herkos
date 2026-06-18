package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Main(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestStatusJSON(t *testing.T) {
	code, out, _ := run("status", "--json")
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("status --json not valid JSON: %v (%q)", err, out)
	}
	if m["name"] != "herkos" || m["version"] == "" || m["status"] != "ok" {
		t.Fatalf("unexpected status payload: %v", m)
	}
}

func TestStatusText(t *testing.T) {
	code, out, _ := run("status")
	if code != 0 || !strings.Contains(out, "herkos") {
		t.Fatalf("status text: code=%d out=%q", code, out)
	}
}

func TestUnknownCommandExits2(t *testing.T) {
	if code, _, _ := run("frobnicate"); code != 2 {
		t.Fatalf("unknown command exit=%d want 2", code)
	}
}

func TestNoArgsExits2(t *testing.T) {
	if code, _, _ := run(); code != 2 {
		t.Fatalf("no args exit=%d want 2", code)
	}
}

func TestHelpExits0(t *testing.T) {
	if code, out, _ := run("help"); code != 0 || !strings.Contains(out, "usage") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}
}

func TestReceiptRequiresFile(t *testing.T) {
	if code, _, _ := run("receipt"); code != 2 {
		t.Fatalf("receipt without -file exit=%d want 2", code)
	}
}

func TestKeygenCreatesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	code, out, errb := run("keygen", "--key", path)
	if code != 0 {
		t.Fatalf("keygen exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "public:") || !strings.Contains(out, path) {
		t.Fatalf("keygen output missing path/public: %q", out)
	}
	// Second run must be idempotent: same public key, still exit 0.
	_, out2, _ := run("keygen", "--key", path)
	if out2 != out {
		t.Fatalf("keygen not idempotent:\n first=%q\nsecond=%q", out, out2)
	}
}
