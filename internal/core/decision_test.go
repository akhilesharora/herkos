package core

import "testing"

func TestZeroDecisionDenies(t *testing.T) {
	var d Decision
	if d.Allowed() {
		t.Fatal("zero Decision must be deny")
	}
	if d.Reason() != ReasonDenyByDefault {
		t.Fatalf("Reason=%q want %q", d.Reason(), ReasonDenyByDefault)
	}
}

func TestAllowDeny(t *testing.T) {
	if !Allow().Allowed() {
		t.Fatal("Allow must be allowed")
	}
	d := Deny(ReasonOutsideAllowlist, "a.go:9")
	if d.Allowed() {
		t.Fatal("Deny must not be allowed")
	}
	if d.Reason() != ReasonOutsideAllowlist || d.Detail() != "a.go:9" {
		t.Fatalf("got reason=%q detail=%q", d.Reason(), d.Detail())
	}
}

func TestAuthorizeLine(t *testing.T) {
	ss, _ := NewSpanSet(Span{"a.go", 10, 20})
	if d := ss.AuthorizeLine("a.go", 12); !d.Allowed() || d.Reason() != ReasonInSpan {
		t.Fatalf("in-span: allowed=%v reason=%q", d.Allowed(), d.Reason())
	}
	if d := ss.AuthorizeLine("a.go", 99); d.Allowed() || d.Reason() != ReasonOutsideAllowlist {
		t.Fatalf("out-span: allowed=%v reason=%q", d.Allowed(), d.Reason())
	}
	// zero set authorizes nothing
	var zero SpanSet
	if zero.AuthorizeLine("a.go", 1).Allowed() {
		t.Fatal("zero SpanSet must deny AuthorizeLine")
	}
}
