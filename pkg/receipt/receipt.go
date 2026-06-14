// Package receipt builds and verifies a signed, tamper-evident Merkle receipt over the
// canonical span bytes that touched the model - proof of which code regions were served,
// without shipping the code. Offline-verifiable with the public key.
package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
)

// Receipt is the signed proof. Leaves are sorted hex span hashes; Root is their Merkle
// root; Enforcement records the egress mode in effect ("userspace" | "hardened").
type Receipt struct {
	Root        string   `json:"root"`
	Leaves      []string `json:"leaves"`
	Enforcement string   `json:"enforcement"`
	Sig         string   `json:"sig"`
}

var (
	ErrTampered = errors.New("receipt: root does not match leaves")
	ErrBadSig   = errors.New("receipt: signature invalid")
)

func leaf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func merkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				h := sha256.Sum256([]byte(level[i] + level[i+1]))
				next = append(next, hex.EncodeToString(h[:]))
			} else {
				next = append(next, level[i]) // odd node carries up
			}
		}
		level = next
	}
	return level[0]
}

// Build hashes each canonical span, sorts the leaves (order-independent root), computes the
// Merkle root, and signs it.
func Build(priv ed25519.PrivateKey, enforcement string, canonSpans [][]byte) Receipt {
	leaves := make([]string, 0, len(canonSpans))
	for _, b := range canonSpans {
		leaves = append(leaves, leaf(b))
	}
	sort.Strings(leaves)
	root := merkleRoot(leaves)
	sig := ed25519.Sign(priv, []byte(root))
	return Receipt{Root: root, Leaves: leaves, Enforcement: enforcement, Sig: hex.EncodeToString(sig)}
}

// Verify recomputes the root from the leaves (tamper check) and verifies the signature.
func (rc Receipt) Verify(pub ed25519.PublicKey) error {
	if merkleRoot(rc.Leaves) != rc.Root {
		return ErrTampered
	}
	sig, err := hex.DecodeString(rc.Sig)
	if err != nil || !ed25519.Verify(pub, []byte(rc.Root), sig) {
		return ErrBadSig
	}
	return nil
}
