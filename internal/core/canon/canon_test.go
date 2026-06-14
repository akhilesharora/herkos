package canon

import (
	"bytes"
	"testing"
)

func TestPrefixStableAcrossVolatileFields(t *testing.T) {
	a := []byte("read /home/alice/proj/main.go at 2026-06-16T10:00:00Z")
	b := []byte("read /home/bob/proj/main.go at 2026-06-15T22:13:41Z")
	if !bytes.Equal(Canonicalize(a), Canonicalize(b)) {
		t.Fatalf("volatile fields must canonicalize identically:\n%q\n%q", Canonicalize(a), Canonicalize(b))
	}
}

func TestRedactsSecrets(t *testing.T) {
	out := string(Canonicalize([]byte("token ghp_abcdefghijklmnopqrstuvwx hex 0123456789abcdef0123456789abcdef")))
	if bytes.Contains([]byte(out), []byte("ghp_abc")) {
		t.Fatalf("gh token not redacted: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("<TOKEN>")) {
		t.Fatalf("expected <TOKEN>: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("<SECRET>")) {
		t.Fatalf("expected <SECRET> for hex blob: %s", out)
	}
}

func TestDeterministic(t *testing.T) {
	in := []byte("/var/log/x at 2026-01-01T00:00:00Z")
	if !bytes.Equal(Canonicalize(in), Canonicalize(in)) {
		t.Fatal("canonicalize must be deterministic")
	}
}
