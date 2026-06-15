// Package keys manages Herkos's local ed25519 signing key used to sign receipts. The key
// is stored as a hex-encoded seed at a local path with 0600 permissions; nothing leaves the
// machine.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidKeyFile is returned when an existing key file is not a valid hex ed25519 seed.
var ErrInvalidKeyFile = errors.New("keys: invalid key file")

// LoadOrCreate returns the signing key at path, generating and persisting a new one (0600)
// if the file does not exist. It is idempotent: a second call returns the same key.
func LoadOrCreate(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, ErrInvalidKeyFile
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("keys: read %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// PublicHex returns the hex-encoded public key for a private key.
func PublicHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}
