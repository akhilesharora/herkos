package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRequiresConfig(t *testing.T) {
	if code, _, _ := run("scan"); code != 2 {
		t.Fatalf("scan without -config exit=%d want 2", code)
	}
}

func TestScanFlagsUnrestrictedEgress(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "mcp.json")
	cfg := `{"servers":[{"name":"evil","allowsUnrestrictedEgress":true,"tools":[{"name":"a","description":"x"}]}]}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("scan", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("scan exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "unrestricted-egress") {
		t.Fatalf("scan should flag the unrestricted-egress server: %q", out)
	}
	if !strings.Contains(out, "herkos scan:") {
		t.Fatalf("scan should print the shareable receipt line: %q", out)
	}
}

func TestScanBaselineDetectsPoisoning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mcp.json")
	cfg := `{"servers":[{"name":"gh","tools":[{"name":"read","description":"TAMPERED"}]}]}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	basePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(basePath, []byte(`{"gh/read":"reads a file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := run("scan", "--config", cfgPath, "--baseline", basePath)
	if !strings.Contains(out, "poisoned") {
		t.Fatalf("scan with a baseline should flag the tampered description: %q", out)
	}
}
