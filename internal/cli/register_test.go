package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterRequiresConfig(t *testing.T) {
	if code, _, _ := run("register", "--allow-tool", "read_file", "--", "npx", "srv"); code != 2 {
		t.Fatalf("register without -config exit=%d want 2", code)
	}
}

func TestRegisterRequiresUpstream(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	if code, _, errb := run("register", "--config", cfg); code != 2 || !strings.Contains(errb, "missing upstream") {
		t.Fatalf("register without upstream exit=%d stderr=%q", code, errb)
	}
}

func TestRegisterOnExistingConfigClaimsBackup(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("register", "--config", cfg, "--allow-tool", "read_file", "--", "srv")
	if code != 0 {
		t.Fatalf("register exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "backup at") {
		t.Fatalf("registering over an existing config should report the backup: %q", out)
	}
	if _, err := os.Stat(cfg + ".bak"); err != nil {
		t.Fatalf("a .bak must exist after registering over an existing config: %v", err)
	}
}

func TestRegisterThenUnregisterRoundTrip(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "mcp.json")

	code, out, errb := run("register", "--config", cfg, "--allow-tool", "read_file", "--", "npx", "weather-mcp")
	if code != 0 {
		t.Fatalf("register exit=%d stderr=%q", code, errb)
	}
	// First-time registration creates the file, so there is no backup; the message must
	// not claim one (a .bak is only written when a prior config existed).
	if !strings.Contains(out, "registered herkos") || strings.Contains(out, "backup") {
		t.Fatalf("first-time register must not claim a backup: %q", out)
	}
	if _, err := os.Stat(cfg + ".bak"); err == nil {
		t.Fatalf("no .bak should exist after first-time registration")
	}

	// The written entry must be a runnable `herkos serve ...` invocation.
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		MCP map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("written config invalid: %v", err)
	}
	entry, ok := root.MCP["herkos"]
	if !ok {
		t.Fatalf("no herkos entry written: %s", raw)
	}
	if entry.Command != "herkos" || len(entry.Args) == 0 || entry.Args[0] != "serve" {
		t.Fatalf("entry must invoke `herkos serve ...`: %+v", entry)
	}
	want := []string{"serve", "--allow-tool", "read_file", "--", "npx", "weather-mcp"}
	if strings.Join(entry.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("entry args = %v, want %v", entry.Args, want)
	}

	if code, _, errb := run("unregister", "--config", cfg); code != 0 {
		t.Fatalf("unregister exit=%d stderr=%q", code, errb)
	}
	raw2, _ := os.ReadFile(cfg)
	if strings.Contains(string(raw2), "herkos") {
		t.Fatalf("herkos entry survived unregister: %s", raw2)
	}
}
