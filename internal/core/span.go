// Package core is Herkos's domain heart: the SpanGate model in which a single
// span set is simultaneously the agent's context payload and the egress
// allowlist.
//
// Fail-closed is a type invariant here. The zero value of [SpanSet] authorizes
// nothing, so any code path that forgets to build an explicit allowlist denies
// all egress rather than leaking. This package is pure: it imports no adapters
// and performs no I/O.
package core

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ErrInvalidSpan is returned when constructing a [SpanSet] from a malformed span.
var ErrInvalidSpan = errors.New("core: invalid span")

// Span is a contiguous line range within a single file, using 1-based,
// half-open [StartLine, EndLine) semantics: StartLine is inclusive, EndLine is
// exclusive. It is the atomic unit of both context selection and egress
// authorization in SpanGate.
type Span struct {
	File      string
	StartLine int
	EndLine   int
}

// Valid reports whether s is well-formed.
func (s Span) Valid() bool {
	return s.File != "" && s.StartLine >= 1 && s.EndLine > s.StartLine
}

// ContainsLine reports whether the given 1-based line in file lies within s.
func (s Span) ContainsLine(file string, line int) bool {
	return s.File == file && line >= s.StartLine && line < s.EndLine
}

// Lines returns the number of lines covered by s, or 0 if s is invalid.
func (s Span) Lines() int {
	if !s.Valid() {
		return 0
	}
	return s.EndLine - s.StartLine
}

// String renders s as "file:start-end" with end exclusive.
func (s Span) String() string {
	return fmt.Sprintf("%s:%d-%d", s.File, s.StartLine, s.EndLine)
}

// SpanSet is an immutable, deny-by-default allowlist of spans.
//
// SECURITY INVARIANT: the zero value (SpanSet{}) authorizes NOTHING. There is no
// exported field and no constructor that yields an "allow all" set; callers must
// pass explicit, validated spans through [NewSpanSet]. Failing open is therefore
// structurally impossible.
type SpanSet struct {
	spans []Span
}

// NewSpanSet builds an immutable allowlist from spans. Every span must be
// [Span.Valid]; otherwise it returns [ErrInvalidSpan] and the zero (deny-all)
// SpanSet. Passing no spans yields a valid, empty, deny-all set.
func NewSpanSet(spans ...Span) (SpanSet, error) {
	out := make([]Span, 0, len(spans))
	for _, s := range spans {
		if !s.Valid() {
			return SpanSet{}, fmt.Errorf("%w: %s", ErrInvalidSpan, s.String())
		}
		s.File = filepath.Clean(s.File) // normalize so ./a.go, a.go resolve identically
		out = append(out, s)
	}
	return SpanSet{spans: out}, nil
}

// AllowsLine reports whether (file, line) is authorized by the set. The zero
// value authorizes nothing.
func (ss SpanSet) AllowsLine(file string, line int) bool {
	file = filepath.Clean(file)
	for _, s := range ss.spans {
		if s.ContainsLine(file, line) {
			return true
		}
	}
	return false
}

// Covers reports whether the whole span s is enclosed by some single span in the set
// (same file, fully containing range). Used by payload egress authorization: a payload
// is allowed only if every span it derives from is Covered by the active allowlist.
func (ss SpanSet) Covers(s Span) bool {
	if !s.Valid() {
		return false
	}
	f := filepath.Clean(s.File)
	for _, t := range ss.spans {
		if t.File == f && t.StartLine <= s.StartLine && t.EndLine >= s.EndLine {
			return true
		}
	}
	return false
}

// Len returns the number of spans in the set.
func (ss SpanSet) Len() int { return len(ss.spans) }

// TotalLines returns the total number of lines authorized by the set, counting
// each span independently (overlaps are not deduplicated). Used for budget
// accounting.
func (ss SpanSet) TotalLines() int {
	n := 0
	for _, s := range ss.spans {
		n += s.Lines()
	}
	return n
}

// Spans returns a defensive copy of the set's spans; SpanSet is immutable.
func (ss SpanSet) Spans() []Span {
	out := make([]Span, len(ss.spans))
	copy(out, ss.spans)
	return out
}
