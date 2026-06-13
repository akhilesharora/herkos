package core

// Query is the input to SpanGate's SELECT stage: anchors to resolve in the code
// graph plus a hard line budget the returned SpanSet must not exceed.
type Query struct {
	Anchors    []string // symbol names / identifiers seeding the graph walk
	RawText    string   // free-text query used when no anchor resolves
	LineBudget int      // hard cap on total served lines (must be > 0)
}

// Valid reports whether q can drive a SELECT.
func (q Query) Valid() bool {
	return q.LineBudget > 0 && (len(q.Anchors) > 0 || q.RawText != "")
}

// EgressRequest is an outbound payload to authorize against the active Binding.
// SourceSpans records the spans the payload was derived from (provenance).
type EgressRequest struct {
	Server      string
	Payload     []byte
	SourceSpans []Span
}

// Cursor is a content-addressed handle into the local Merkle span pool (PoolPort).
type Cursor string
