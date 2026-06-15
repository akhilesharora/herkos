package receiptlog

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempChain(t *testing.T) (string, *Chain, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "log.jsonl")
	c, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	return path, c, pub
}

func call(tool string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`)
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecordVerifyClosed(t *testing.T) {
	path, c, pub := tempChain(t)
	if err := c.Record(call("read_file"), true); err != nil {
		t.Fatal(err)
	}
	if err := c.Record(call("delete_repo"), false); err != nil { // denied call still gets a receipt
		t.Fatal(err)
	}
	if err := c.Record([]byte(`{"jsonrpc":"2.0","method":"tools/list"}`), true); err != nil { // not recorded
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(read(t, path), pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Calls != 2 || !res.Closed {
		t.Fatalf("got %+v, want Calls=2 Closed=true", res)
	}
	if res.Session != c.Session() || res.Tip != c.Tip() {
		t.Fatalf("session/tip mismatch: res=%+v chain session=%s tip=%s", res, c.Session(), c.Tip())
	}
}

func TestTailTruncationDetected(t *testing.T) {
	path, c, pub := tempChain(t)
	_ = c.Record(call("read_file"), true)
	_ = c.Record(call("send_money"), true)
	_ = c.Close() // file: open, call, call, close (4 lines)

	lines := strings.Split(strings.TrimRight(string(read(t, path)), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	// Drop the close record (tail-truncation): still a valid chain, but NOT cleanly closed.
	truncated := strings.Join(lines[:3], "\n") + "\n"
	res, err := Verify([]byte(truncated), pub)
	if err != nil {
		t.Fatalf("a truncated-but-internally-valid log should verify with Closed=false, got err: %v", err)
	}
	if res.Closed {
		t.Fatal("truncation must be detectable: Closed should be false when the close record is gone")
	}
	// Dropping a middle record breaks the chain entirely.
	spliced := lines[0] + "\n" + lines[2] + "\n" + lines[3] + "\n"
	if _, err := Verify([]byte(spliced), pub); err == nil {
		t.Fatal("dropping a middle record must fail verification")
	}
}

func TestEmptyFileFails(t *testing.T) {
	_, _, pub := tempChain(t)
	for _, data := range []string{"", "\n\n   \n"} {
		if _, err := Verify([]byte(data), pub); err == nil {
			t.Fatalf("an empty/blank log must fail verification (no genesis), data=%q", data)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	path, c, _ := tempChain(t)
	_ = c.Record(call("read_file"), true)
	_ = c.Close()
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(read(t, path), other); err == nil {
		t.Fatal("verify under the wrong key must fail")
	}
}

func TestTamperBreaksVerify(t *testing.T) {
	path, c, pub := tempChain(t)
	_ = c.Record(call("read_file"), true)
	_ = c.Record(call("send_email"), true)
	_ = c.Close()
	data := string(read(t, path))
	tampered := strings.Replace(data, `"tool":"send_email"`, `"tool":"transfer_funds"`, 1)
	if tampered == data {
		t.Fatal("setup: nothing tampered")
	}
	if _, err := Verify([]byte(tampered), pub); err == nil {
		t.Fatal("editing a record must break verification")
	}
}

func TestCanonicalIsInjective(t *testing.T) {
	// The classic newline-collision: a tool name and a req_hash that, under a naive newline
	// join, would produce identical signed bytes. Length-prefixing must keep them distinct.
	a := canonical(Entry{Type: typeCall, Tool: "send_money\nAAAA", ReqHash: "BBBB"})
	b := canonical(Entry{Type: typeCall, Tool: "send_money", ReqHash: "AAAA\nBBBB"})
	if bytes.Equal(a, b) {
		t.Fatal("canonical() collided on a newline-injection pair; encoding is not injective")
	}
}

func TestRecordRejectsControlChars(t *testing.T) {
	_, c, _ := tempChain(t)
	// Valid JSON whose tool name decodes to a string containing a newline (the \n here is an
	// escape in the JSON, not a raw control char), so it reaches hasControl and is rejected.
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_money\nAAAA"}}`)
	if err := c.Record(msg, true); err == nil {
		t.Fatal("a tool name with a control character must be rejected, not signed")
	}
}

func TestOpenRefusesNonEmptyFile(t *testing.T) {
	_, priv, _ := func() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(nil) }()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, priv); err == nil {
		t.Fatal("Open must refuse a non-empty file (one file = one session)")
	}
}
