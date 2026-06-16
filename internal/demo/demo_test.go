package demo

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var buf bytes.Buffer
	if err := Run(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// all three roles of the binding must be shown
	for _, want := range []string{"[1] CONTEXT", "[2] EGRESS", "[3] RECEIPT", "dual-use binding"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in demo output:\n%s", want, out)
		}
	}
	// role 1: a positive token saving
	if !strings.Contains(out, "fewer tokens") || strings.Contains(out, "0% fewer tokens") {
		t.Fatalf("demo should report a positive token saving:\n%s", out)
	}
	// role 2: in-set allowed, out-of-set 256-byte exfil blocked
	if !strings.Contains(out, "blocked 256 bytes") {
		t.Fatalf("out-of-set exfil should be blocked:\n%s", out)
	}
	// role 3: verifies under the signer's key, fails under a different key
	if !strings.Contains(out, "signer's public key  -> VERIFIED") {
		t.Fatalf("receipt should verify under the signer's key:\n%s", out)
	}
	if !strings.Contains(out, "different key          -> FAILED") {
		t.Fatalf("receipt must fail under a different key:\n%s", out)
	}
}

func TestRunDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	_ = Run(&a)
	_ = Run(&b)
	// Everything before the receipt root line is deterministic; the root varies with the
	// ephemeral signing key, so compare only the prefix up to that line.
	trim := func(s string) string {
		if i := strings.Index(s, "        root "); i >= 0 {
			return s[:i]
		}
		return s
	}
	if trim(a.String()) != trim(b.String()) {
		t.Fatalf("demo metrics must be deterministic:\n%q\n%q", a.String(), b.String())
	}
}
