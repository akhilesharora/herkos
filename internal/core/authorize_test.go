package core

import "testing"

func TestAuthorizePayloadDualUse(t *testing.T) {
	ss, _ := NewSpanSet(Span{"auth.go", 1, 20}, Span{"db.go", 1, 30})
	b := NewBinding(ss)

	// payload derived from served spans -> allowed
	ok := EgressRequest{Server: "x", Payload: []byte("..."), SourceSpans: []Span{{"auth.go", 5, 10}}}
	if d := b.AuthorizePayload(ok); !d.Allowed() {
		t.Fatalf("in-binding payload must be allowed: %s", d.Detail())
	}

	// payload with a span outside the binding -> denied (the leak case)
	leak := EgressRequest{Server: "x", Payload: []byte("secret"), SourceSpans: []Span{{"secret.go", 1, 5}}}
	if d := b.AuthorizePayload(leak); d.Allowed() {
		t.Fatal("out-of-binding source span must be denied")
	}

	// no provenance -> denied (fail-closed)
	if b.AuthorizePayload(EgressRequest{Server: "x", Payload: []byte("x")}).Allowed() {
		t.Fatal("payload without provenance must be denied")
	}

	// zero binding authorizes nothing
	var zero Binding
	if zero.AuthorizePayload(ok).Allowed() {
		t.Fatal("zero Binding must deny every payload")
	}
}
