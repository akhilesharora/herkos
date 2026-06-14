package receipt

import (
	"crypto/ed25519"
	"testing"
)

func TestBuildVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := Build(priv, "userspace", [][]byte{[]byte("span a"), []byte("span b")})
	if err := r.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.Enforcement != "userspace" {
		t.Fatalf("enforcement not stamped: %q", r.Enforcement)
	}
}

func TestTamperFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := Build(priv, "userspace", [][]byte{[]byte("a"), []byte("b"), []byte("c")})
	r.Leaves[0] = leaf([]byte("evil")) // tamper one leaf
	if err := r.Verify(pub); err == nil {
		t.Fatal("tampered receipt must fail verification")
	}
}

func TestRootOrderIndependent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	a := Build(priv, "u", [][]byte{[]byte("x"), []byte("y")})
	b := Build(priv, "u", [][]byte{[]byte("y"), []byte("x")})
	if a.Root != b.Root {
		t.Fatalf("root must be order-independent: %s vs %s", a.Root, b.Root)
	}
}

func TestWrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	r := Build(priv, "u", [][]byte{[]byte("a")})
	if err := r.Verify(otherPub); err == nil {
		t.Fatal("verification with the wrong public key must fail")
	}
}
