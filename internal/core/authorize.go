package core

// AuthorizePayload authorizes an outbound payload against the binding's allowlist. A
// payload is allowed iff EVERY source span it derives from is Covered by the binding (the
// same span set the model was served). Fail-closed: missing provenance, or any source span
// outside the binding, denies. This is the egress half of the SpanGate dual-use guarantee.
func (b Binding) AuthorizePayload(req EgressRequest) Decision {
	if len(req.SourceSpans) == 0 {
		return Deny(ReasonDenyByDefault, "no provenance: payload has no source spans")
	}
	for _, s := range req.SourceSpans {
		if !b.spans.Covers(s) {
			return Deny(ReasonOutsideAllowlist, s.String())
		}
	}
	return Allow()
}
