//go:build cgo

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akhilesharora/herkos/internal/index"
)

func TestIndexRequiresDir(t *testing.T) {
	if code, _, _ := run("index"); code != 2 {
		t.Fatalf("index with no dir exit=%d want 2", code)
	}
}

// TestIndexThenSelectEndToEnd is the real-repo path: index a source tree, then query the
// written index with select - no cgo needed for the query half.
func TestIndexThenSelectEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package p\nfunc A() { B() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package p\nfunc B() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	idxPath := filepath.Join(t.TempDir(), "index")

	code, out, errb := run("index", dir, "--out", idxPath)
	if code != 0 {
		t.Fatalf("index exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "indexed 2 symbols") {
		t.Fatalf("index output: %q", out)
	}
	if _, err := index.Load(idxPath); err != nil {
		t.Fatalf("written index must load: %v", err)
	}

	// Query the index for A; the cross-file edge must pull in B from b.go.
	code, out, errb = run("select", "--index", idxPath, "--anchor", "A", "--budget", "1")
	if code != 0 {
		t.Fatalf("select exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "a.go:2-3") || !strings.Contains(out, "b.go:2-3") {
		t.Fatalf("select should list A and its cross-file callee B: %q", out)
	}
}
