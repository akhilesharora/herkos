package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	a, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(path) // second call must load the same key
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("LoadOrCreate must return the same key on the second call")
	}
}

func TestKeyFilePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file perms = %o, want 600", fi.Mode().Perm())
	}
}

func TestSignVerifyWithLoadedKey(t *testing.T) {
	priv, err := LoadOrCreate(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("receipt root")
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("loaded key must sign+verify")
	}
}
