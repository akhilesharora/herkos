package core

// Binding is the value that makes SpanGate's core invariant atomic: the context the
// model is served and the egress allowlist that is enforced are the SAME span set,
// computed once. A Binding is constructed once from a SpanSet and is the ONLY thing
// both the context-serve path and the egress authorizer read. There is no API to
// serve one set and enforce another, so the "context-set == egress-set" guarantee is
// structural, not a convention.
type Binding struct {
	spans SpanSet
}

// NewBinding constructs the single dual-use binding from a resolved SpanSet.
func NewBinding(ss SpanSet) Binding { return Binding{spans: ss} }

// SpanSet returns the bound span set. Both the serve path and the egress path read
// exactly this value.
func (b Binding) SpanSet() SpanSet { return b.spans }

// AuthorizeLine authorizes an outbound line against the bound allowlist. The zero
// Binding (zero SpanSet) authorizes nothing.
func (b Binding) AuthorizeLine(file string, line int) Decision {
	return b.spans.AuthorizeLine(file, line)
}
