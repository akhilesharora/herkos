package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/akhilesharora/herkos/internal/receiptlog"
	"github.com/akhilesharora/herkos/pkg/receipt"
)

// verifyCmd checks a receipt's signature against a public key, fully offline. A receipt
// verifies only under the key that signed it, so a third party can confirm which spans
// touched the model without trusting Herkos or the network.
//
// Usage: herkos verify --file RECEIPT.json --pubkey HEX
func verifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "path to a receipt JSON file")
	pubHex := fs.String("pubkey", "", "hex ed25519 public key (from `herkos keygen`)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *pubHex == "" {
		fmt.Fprintln(stderr, "verify: --file and --pubkey are required")
		return 2
	}
	pub, err := hex.DecodeString(strings.TrimSpace(*pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(stderr, "verify: --pubkey must be a %d-byte hex ed25519 key\n", ed25519.PublicKeySize)
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	// A receipt-log chain (JSONL whose first record is a genesis) verifies differently from a
	// single Merkle receipt: it checks the whole hash-chain and reports whether it was sealed.
	if looksLikeChain(raw) {
		res, err := receiptlog.Verify(raw, ed25519.PublicKey(pub))
		if err != nil {
			fmt.Fprintf(stdout, "FAILED: %v\n", err)
			return 1
		}
		if !res.Closed {
			fmt.Fprintf(stdout, "INCOMPLETE  session=%s calls=%d  not cleanly closed (possible truncation)  tip=%s\n", res.Session, res.Calls, res.Tip)
			return 1
		}
		fmt.Fprintf(stdout, "VERIFIED  session=%s calls=%d cleanly closed  tip=%s\n", res.Session, res.Calls, res.Tip)
		return 0
	}

	var rc receipt.Receipt
	if err := json.Unmarshal(raw, &rc); err != nil {
		fmt.Fprintf(stderr, "verify: invalid receipt JSON: %v\n", err)
		return 1
	}
	if err := rc.Verify(ed25519.PublicKey(pub)); err != nil {
		fmt.Fprintf(stdout, "FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "VERIFIED  root=%s enforcement=%s spans=%d\n", rc.Root, rc.Enforcement, len(rc.Leaves))
	return 0
}

// looksLikeChain reports whether raw is a receipt-log chain (JSONL whose first non-blank line
// is a typed record) rather than a single Merkle receipt.
func looksLikeChain(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		return json.Unmarshal([]byte(line), &probe) == nil && probe.Type != ""
	}
	return false
}
