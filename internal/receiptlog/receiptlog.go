// Package receiptlog is the live-broker audit trail: a tamper-evident, append-only chain of
// ed25519-signed receipts written JSONL, one file per session. The chain opens with a signed
// genesis record (binding a session id and the signer's public key), then one record per
// brokered tools/call, and is sealed by a signed close record that commits the call count and
// the tip hash. A third party verifies the whole log offline with [Verify] and the signer's
// public key.
//
// What it detects: any edit, reorder, or mid-chain insertion/deletion breaks the hash chain
// and signatures; a truncated log is missing its close record, so [Verify] reports it as not
// cleanly closed; an empty or deleted file has no genesis and fails. What it does NOT do: a
// local attacker with write access can still truncate the file to a smaller, internally-valid
// "incomplete" prefix - that is detectable (no clean close) but not cryptographically
// prevented without an external transparency log. And [Verify] only proves the records were
// signed by the holder of the given public key; the verifier must obtain the authentic public
// key out of band. The recorded `allowed` is the broker's decision at audit time, not a
// delivery confirmation.
//
// This is the serve-path counterpart to pkg/receipt (a Merkle root over a static span set):
// a live stream needs a chain, not a single root.
package receiptlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// domainTag separates this signature scheme from any other use of the same key.
const domainTag = "herkos/receiptlog/v1\x00"

// Record types.
const (
	typeOpen  = "open"
	typeCall  = "call"
	typeClose = "close"
)

// Entry is one record in the chain. Hash is sha256 of the injective canonical encoding of all
// fields; Prev is the previous entry's Hash; Sig is ed25519 over Hash. Fields not used by a
// record type are empty/zero (and still committed in the canonical form).
type Entry struct {
	Type    string `json:"type"`
	Seq     int    `json:"seq"`
	Prev    string `json:"prev"`
	Session string `json:"session"`
	Method  string `json:"method,omitempty"`
	Tool    string `json:"tool,omitempty"`
	ReqHash string `json:"req_hash,omitempty"`
	Allowed bool   `json:"allowed"`
	PubKey  string `json:"pubkey,omitempty"`
	// Context is the fingerprint of the served span set, carried on the open record only, so the
	// signed audit proves the brokered calls happened under THIS served set. Empty when the
	// content gate is not armed.
	Context string `json:"context,omitempty"`
	Count   int    `json:"count,omitempty"`
	Hash    string `json:"hash"`
	Sig     string `json:"sig"`
}

// canonical renders the signed content of an entry as an injective byte string: a version tag
// followed by every field length-prefixed (strings) or fixed-encoded (ints, bool). Because
// each field is length-delimited, no agent-controlled value (method, tool) can shift a field
// boundary, so distinct entries cannot share a canonical form.
func canonical(e Entry) []byte {
	var b bytes.Buffer
	b.WriteString(domainTag)
	putStr(&b, e.Type)
	putInt(&b, int64(e.Seq))
	putStr(&b, e.Prev)
	putStr(&b, e.Session)
	putStr(&b, e.Method)
	putStr(&b, e.Tool)
	putStr(&b, e.ReqHash)
	if e.Allowed {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	putStr(&b, e.PubKey)
	putStr(&b, e.Context)
	putInt(&b, int64(e.Count))
	return b.Bytes()
}

func putStr(b *bytes.Buffer, s string) {
	var n [binary.MaxVarintLen64]byte
	b.Write(n[:binary.PutUvarint(n[:], uint64(len(s)))])
	b.WriteString(s)
}

func putInt(b *bytes.Buffer, i int64) {
	var n [binary.MaxVarintLen64]byte
	b.Write(n[:binary.PutVarint(n[:], i)])
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Chain is an open, append-only session log. The zero value is unusable; use [Open].
type Chain struct {
	priv    ed25519.PrivateKey
	pub     string // hex of the signer's public key
	session string

	mu     sync.Mutex
	f      *os.File
	seq    int
	prev   string
	calls  int
	closed bool
}

// Open creates the JSONL log at path, refusing to touch a non-empty file (one file = one
// session, which keeps the chain unambiguous and avoids a second genesis on restart). It mints
// a random session id and writes the signed genesis record, binding the session, the signer's
// public key, and contextFingerprint - a fingerprint of the served span set, so the signed
// audit proves the brokered calls happened under this served set. Pass ""
// when the content gate is not armed.
func Open(path string, priv ed25519.PrivateKey, contextFingerprint string) (*Chain, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("receiptlog: invalid signing key")
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return nil, fmt.Errorf("receiptlog: %s already exists and is non-empty; use a fresh per-session path", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("receiptlog: open %s: %w", path, err)
	}
	sid, err := newSession()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	c := &Chain{priv: priv, pub: pub, session: sid, f: f}

	c.mu.Lock()
	err = c.write(Entry{Type: typeOpen, PubKey: pub, Context: contextFingerprint})
	c.mu.Unlock()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return c, nil
}

func newSession() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("receiptlog: session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// write signs and appends one entry, then fsyncs so a forwarded call's receipt is durable
// before the broker treats it as recorded. The caller must hold c.mu.
func (c *Chain) write(e Entry) error {
	e.Seq = c.seq
	e.Prev = c.prev
	e.Session = c.session
	sum := sha256.Sum256(canonical(e))
	e.Hash = hex.EncodeToString(sum[:])
	e.Sig = hex.EncodeToString(ed25519.Sign(c.priv, sum[:]))

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("receiptlog: marshal: %w", err)
	}
	if _, err := c.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("receiptlog: write: %w", err)
	}
	if err := c.f.Sync(); err != nil {
		return fmt.Errorf("receiptlog: sync: %w", err)
	}
	c.seq++
	c.prev = e.Hash
	return nil
}

// Record appends a receipt for a single agent-to-upstream message, but only for a tools/call
// (other methods and unparseable frames are ignored, returning nil). allowed records the
// broker's decision. The receipt binds the method, tool name, and a hash of the exact request
// bytes; it does not store the request body. A method or tool name carrying control characters
// is rejected, so a crafted name cannot smuggle anything into the signed content.
func (c *Chain) Record(msg []byte, allowed bool) error {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(req.Method), "tools/call") {
		return nil
	}
	if hasControl(req.Method) || hasControl(req.Params.Name) {
		return fmt.Errorf("receiptlog: refusing to record a tool call with control characters in method/tool")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.f == nil {
		return errors.New("receiptlog: log is closed")
	}
	if err := c.write(Entry{Type: typeCall, Method: req.Method, Tool: req.Params.Name, ReqHash: sha256hex(msg), Allowed: allowed}); err != nil {
		return err
	}
	c.calls++
	return nil
}

// Close writes the signed close record (committing the call count and the tip hash) and closes
// the file. It is idempotent. After Close, Tip and Calls reflect the sealed chain.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil || c.closed {
		return nil
	}
	werr := c.write(Entry{Type: typeClose, Count: c.calls})
	c.closed = true
	cerr := c.f.Close()
	c.f = nil
	if werr != nil {
		return werr
	}
	return cerr
}

// Session returns the chain's session id.
func (c *Chain) Session() string { c.mu.Lock(); defer c.mu.Unlock(); return c.session }

// Calls returns the number of tool-call records written so far.
func (c *Chain) Calls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

// Tip returns the hash of the last written record (the close record after Close).
func (c *Chain) Tip() string { c.mu.Lock(); defer c.mu.Unlock(); return c.prev }

// Result is the outcome of [Verify]: the bound session, the verified call count, whether the
// chain was cleanly closed (a false here means the log was not sealed - possible truncation),
// the tip hash, and the served-context fingerprint bound at open (empty when the content gate
// was not armed).
type Result struct {
	Session string
	Calls   int
	Closed  bool
	Tip     string
	Context string
}

// Verify checks a receipt-log against pub, fully offline. It requires a valid genesis (open)
// record bound to pub, an unbroken hash chain with valid per-entry signatures, a shared session
// id, and (if present) a close record whose count matches. Any inconsistency returns
// (Result{}, err) - a non-zero result is only meaningful when err is nil. A log with no close
// record verifies with Closed=false, the truncation-suspect signal. An empty/deleted file (no
// genesis) is an error.
func Verify(data []byte, pub ed25519.PublicKey) (Result, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Result{}, errors.New("receiptlog: invalid public key")
	}
	pubHex := hex.EncodeToString(pub)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")

	prev, session, contextFP := "", "", ""
	seq, calls := 0, 0
	closed := false

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if closed {
			return Result{}, fmt.Errorf("receiptlog: entry after close at line %d", i)
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return Result{}, fmt.Errorf("receiptlog: line %d: invalid JSON: %w", i, err)
		}
		if e.Seq != seq {
			return Result{}, fmt.Errorf("receiptlog: line %d: seq=%d want %d", i, e.Seq, seq)
		}
		if e.Prev != prev {
			return Result{}, fmt.Errorf("receiptlog: line %d: broken chain", i)
		}
		sum := sha256.Sum256(canonical(e))
		if hex.EncodeToString(sum[:]) != e.Hash {
			return Result{}, fmt.Errorf("receiptlog: line %d: content does not match hash (tampered)", i)
		}
		sig, err := hex.DecodeString(e.Sig)
		if err != nil || !ed25519.Verify(pub, sum[:], sig) {
			return Result{}, fmt.Errorf("receiptlog: line %d: signature invalid", i)
		}

		switch e.Type {
		case typeOpen:
			if seq != 0 {
				return Result{}, fmt.Errorf("receiptlog: line %d: open record out of place", i)
			}
			if e.PubKey != pubHex {
				return Result{}, fmt.Errorf("receiptlog: line %d: log is bound to a different key than the one given", i)
			}
			session = e.Session
			contextFP = e.Context
		case typeCall:
			if seq == 0 {
				return Result{}, fmt.Errorf("receiptlog: line %d: first record must be the genesis (open)", i)
			}
			calls++
		case typeClose:
			if seq == 0 {
				return Result{}, fmt.Errorf("receiptlog: line %d: close before genesis", i)
			}
			if e.Count != calls {
				return Result{}, fmt.Errorf("receiptlog: line %d: close count %d != %d records seen", i, e.Count, calls)
			}
			closed = true
		default:
			return Result{}, fmt.Errorf("receiptlog: line %d: unknown record type %q", i, e.Type)
		}
		if e.Session != session {
			return Result{}, fmt.Errorf("receiptlog: line %d: session mismatch", i)
		}
		prev = e.Hash
		seq++
	}

	if seq == 0 {
		return Result{}, errors.New("receiptlog: empty log (no genesis record)")
	}
	return Result{Session: session, Calls: calls, Closed: closed, Tip: prev, Context: contextFP}, nil
}

// hasControl reports whether s contains any control character (notably newline), which must
// never reach the signed content.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
