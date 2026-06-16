package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akhilesharora/herkos/pkg/receipt"
)

// writeReceipt builds a signed receipt and writes it as JSON, returning the path and the
// signer's public key in hex (as `herkos keygen` would print it).
func writeReceipt(t *testing.T) (path, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rc := receipt.Build(priv, "userspace", [][]byte{[]byte("auth.go:1-20"), []byte("db.go:1-30")})
	raw, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(pub)
}

func TestVerifyRequiresFlags(t *testing.T) {
	if code, _, _ := run("verify"); code != 2 {
		t.Fatalf("verify with no flags exit=%d want 2", code)
	}
}

func TestVerifyGoodReceipt(t *testing.T) {
	path, pubHex := writeReceipt(t)
	code, out, errb := run("verify", "--file", path, "--pubkey", pubHex)
	if code != 0 {
		t.Fatalf("verify exit=%d stderr=%q", code, errb)
	}
	if !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "spans=2") {
		t.Fatalf("verify output: %q", out)
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	path, _ := writeReceipt(t)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	code, out, _ := run("verify", "--file", path, "--pubkey", hex.EncodeToString(otherPub))
	if code != 1 {
		t.Fatalf("verify under the wrong key must exit 1, got %d", code)
	}
	if !strings.Contains(out, "FAILED") {
		t.Fatalf("verify output should say FAILED: %q", out)
	}
}

func TestVerifyBadPubkeyHex(t *testing.T) {
	path, _ := writeReceipt(t)
	if code, _, _ := run("verify", "--file", path, "--pubkey", "not-hex"); code != 2 {
		t.Fatalf("verify with a bad pubkey must exit 2, got %d", code)
	}
}
