// Package spanguard is the broker egress Guard that makes SpanGate's dual-use invariant
// LIVE on the wire: the same span set the model was served (a [core.Binding]) is the set
// outbound tool-call bytes are authorized against. It recovers provenance by recognizing
// repo lines in a tools/call's arguments (via a [Lexicon] built from the code-graph index)
// and denies the call if it carries a repo line whose every containing span lies outside
// the binding - i.e. un-served code trying to leave. Lines are matched after a shallow
// normalization (see normalize): Unicode NFC, lowercase, and whitespace-run collapse, so a
// trivial reflow, recase, or Unicode re-encoding of a served line does not slip past a
// byte-verbatim match.
//
// Honesty, stated plainly so nothing is mistaken for a wall it is not:
//
//   - This is a TRIPWIRE, not a boundary. Normalization buys exactly whitespace- and
//     case-insensitivity; it stops there. An adversary who base64s, paraphrases, token-
//     rewrites, or chunks the code still defeats it, exactly as any userspace content filter
//     is defeated. The airtight boundary is kernel-enforced (Landlock/seccomp/eBPF) and is a
//     separate, ENV-gated mode.
//   - Only lines that fall inside an indexed symbol span are fingerprinted. Code outside a
//     parsed top-level declaration (and any line shorter than the min length, or with no
//     letter/digit) is not gated, to keep false positives off ordinary prose and braces.
//   - Only DISTINCTIVE lines gate. A line that occurs across more than a few spans
//     (boilerplate like `if err != nil {`) carries no reliable provenance and is treated as
//     non-repo content, so the gate does not block ordinary agent output that happens to
//     quote it.
//   - It gates the tools/call method only; resources/* and other methods pass (the broker's
//     mcpguard owns the tool-NAME allowlist; this guard owns the content check). Compose the
//     two so a call must satisfy both.
//
// A line is allowed if ANY span that contains it is covered by the binding (the agent could
// legitimately hold it); it is denied only when the line is repo content and NONE of its
// containing spans was served. That bias is deliberate - it favors not breaking a real
// session over catching a leak that also happens to appear verbatim inside the served set.
package spanguard

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/akhilesharora/herkos/internal/core"
	"golang.org/x/text/unicode/norm"
)

// denyCode mirrors mcpguard: -32000 is the JSON-RPC reserved server-error range MCP uses
// for application-level errors.
const denyCode = -32000

// DefaultMinLineLen is the shortest trimmed repo line that is fingerprinted. Short lines
// (closing braces, single keywords) collide with ordinary text and would cause false
// denials, so they are not gated.
const DefaultMinLineLen = 12

// DefaultMaxSpansPerLine bounds how distinctive a line must be to gate. A line that occurs
// in more spans than this (boilerplate like `if err != nil {`, which appears across the
// whole repo) carries no reliable provenance, so matching it would only generate false
// denials on ordinary agent output. Such lines are treated as non-repo content and pass.
const DefaultMaxSpansPerLine = 4

// Lexicon recognizes verbatim repo lines and recovers their provenance: the indexed spans
// that contain a given line. It is the read-only repo fingerprint the guard matches
// outbound bytes against. The zero value recognizes nothing; build one with NewLexicon.
type Lexicon struct {
	lines    map[string][]core.Span
	minLen   int
	maxSpans int
}

// NewLexicon returns an empty Lexicon. minLineLen <= 0 uses DefaultMinLineLen. Populate it
// with AddSpan for every indexed span and its source body.
func NewLexicon(minLineLen int) *Lexicon {
	if minLineLen <= 0 {
		minLineLen = DefaultMinLineLen
	}
	return &Lexicon{lines: make(map[string][]core.Span), minLen: minLineLen, maxSpans: DefaultMaxSpansPerLine}
}

// AddSpan fingerprints the lines of one indexed span. body is the source text of the file
// the span belongs to (the whole file, or at least the span's lines); only the lines that
// fall within [s.StartLine, s.EndLine) and qualify (see qualifies) are recorded, each
// keyed to s. Calling AddSpan for overlapping spans records a line under each, which is
// what the any-containing-span allow rule needs.
func (l *Lexicon) AddSpan(s core.Span, body string) {
	if !s.Valid() {
		return
	}
	// Lines are 1-based; split body and walk only the span's range.
	src := strings.Split(body, "\n")
	for ln := s.StartLine; ln < s.EndLine && ln-1 < len(src); ln++ {
		key := normalize(src[ln-1])
		if !qualifies(key, l.minLen) {
			continue
		}
		l.lines[key] = append(l.lines[key], s)
	}
}

// Spans returns the indexed spans that contain a line equal to the given text, or nil if
// the (normalized) line is not fingerprinted repo content or is not distinctive enough to
// carry provenance (occurs in more than maxSpans spans - boilerplate). The returned slice
// must not be mutated.
func (l *Lexicon) Spans(line string) []core.Span {
	if l == nil || len(l.lines) == 0 {
		return nil
	}
	key := normalize(line)
	if !qualifies(key, l.minLen) {
		return nil
	}
	spans := l.lines[key]
	if len(spans) > l.maxSpans {
		return nil // boilerplate: present too widely to be a provenance signal
	}
	return spans
}

// Size reports how many distinct repo lines are fingerprinted. Used by callers to log that
// the content gate is actually armed (a zero lexicon gates nothing).
func (l *Lexicon) Size() int {
	if l == nil {
		return 0
	}
	return len(l.lines)
}

// normalize folds away the trivial line edits that would otherwise let a reflow, recase, or
// Unicode re-encoding slip a repo line past a byte-verbatim match. It applies, in order:
// Unicode NFC (so a precomposed char and its combining-sequence twin compare equal), lowercase,
// collapse of every run of whitespace to a single ASCII space, and a trim of leading/trailing
// space. It is applied to both sides of every comparison (lines entering the lexicon and
// outbound candidate lines), so the match is normalized-vs-normalized.
//
// This is deliberately shallow. It defeats whitespace, case, and Unicode-form evasions only; a
// paraphrase, a base64/encoding, or any token-level rewrite still passes, exactly as the package
// doc states. Widening normalization further (e.g. stripping all whitespace, or token folding)
// would start matching unrelated prose and turn the tripwire into a false-positive source.
func normalize(s string) string {
	s = norm.NFC.String(s) // canonicalize Unicode form so an NFC line and its NFD twin compare equal
	s = strings.ToLower(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// qualifies reports whether a normalized line is worth fingerprinting: long enough and
// carrying at least one letter or digit (so pure punctuation/braces are skipped).
func qualifies(norm string, minLen int) bool {
	if len(norm) < minLen {
		return false
	}
	for _, r := range norm {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// Guard authorizes a tools/call's outbound bytes against the served binding using the
// lexicon for provenance recovery. A nil lexicon or a guard with no fingerprints allows
// everything (the content gate is simply not armed); construct with New.
type Guard struct {
	binding core.Binding
	lex     *Lexicon
}

// New returns a content-aware egress Guard over the served binding b and the repo lexicon.
// When lex is nil or empty the guard is inert (every message passes), so callers can wire
// it unconditionally and arm it only once a served set exists.
func New(b core.Binding, lex *Lexicon) *Guard {
	return &Guard{binding: b, lex: lex}
}

// Check implements the broker's Guard contract. It returns (true, nil) to forward, or
// (false, reply) to block and have the broker answer the agent with reply.
//
// Non-tools/call methods pass. A tools/call is blocked when any string in its arguments
// contains a verbatim repo line whose containing spans are all outside the served binding.
// An unparseable message passes here: the composed tool-name guard (mcpguard) already
// fails closed on unparseable frames, so failing closed again would be redundant; this
// guard's job is the content check on calls it can read.
func (g *Guard) Check(msg []byte) (bool, []byte) {
	if g == nil || g.lex == nil || g.lex.Size() == 0 {
		return true, nil // content gate not armed
	}
	var req struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return true, nil // not ours to fail closed; mcpguard already denied unparseable
	}
	if !strings.EqualFold(strings.TrimSpace(req.Method), "tools/call") {
		return true, nil
	}
	var params any
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return true, nil
	}
	for _, s := range collectStrings(params) {
		if span, ok := g.firstUnservedRepoLine(s); ok {
			return false, denyReply(req.ID,
				"herkos: egress denied: tool-call argument carries repo line outside the served set ("+span.String()+")")
		}
	}
	return true, nil
}

// firstUnservedRepoLine scans the lines of one argument string and returns the first line
// that is fingerprinted repo content whose every containing span is outside the binding.
// ok is false when the string carries no such line.
func (g *Guard) firstUnservedRepoLine(arg string) (core.Span, bool) {
	for _, line := range strings.Split(arg, "\n") {
		spans := g.lex.Spans(line)
		if len(spans) == 0 {
			continue // not repo content (or too trivial to fingerprint)
		}
		served := false
		for _, s := range spans {
			if g.binding.SpanSet().Covers(s) {
				served = true
				break
			}
		}
		if !served {
			return spans[0], true // repo line, none of its spans served -> leak
		}
	}
	return core.Span{}, false
}

// collectStrings walks a decoded JSON value and returns every string leaf, so a repo line
// hidden anywhere in a nested tool-argument object is still examined.
func collectStrings(v any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// denyReply builds a JSON-RPC error response echoing id verbatim (or null), marshaled
// through typed structs so the result is always valid JSON. Matches mcpguard's shape.
func denyReply(id json.RawMessage, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	type rpcResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcErr          `json:"error"`
	}
	b, err := json.Marshal(rpcResp{JSONRPC: "2.0", ID: id, Error: rpcErr{Code: denyCode, Message: message}})
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"herkos: egress denied"}}`)
	}
	return b
}
