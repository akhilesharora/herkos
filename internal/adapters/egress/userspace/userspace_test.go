package userspace

import (
	"context"
	"strings"
	"testing"

	"github.com/akhilesharora/herkos/internal/core"
)

// bindingFrom builds a Binding over a single span allowlist for the tests below.
func bindingFrom(t *testing.T, spans ...core.Span) core.Binding {
	t.Helper()
	ss, err := core.NewSpanSet(spans...)
	if err != nil {
		t.Fatalf("NewSpanSet: %v", err)
	}
	return core.NewBinding(ss)
}

func TestAuthorize(t *testing.T) {
	allow := bindingFrom(t, core.Span{File: "auth.go", StartLine: 1, EndLine: 20})

	tests := []struct {
		name        string
		binding     core.Binding
		req         core.EgressRequest
		wantAllowed bool
		wantReason  core.DenyReason
	}{
		{
			name:    "in-binding payload allowed",
			binding: allow,
			req: core.EgressRequest{
				Server:      "upstream",
				Payload:     []byte("derived from auth.go:5-10"),
				SourceSpans: []core.Span{{File: "auth.go", StartLine: 5, EndLine: 10}},
			},
			wantAllowed: true,
			wantReason:  core.ReasonInSpan,
		},
		{
			name:    "out-of-binding source span blocked (exfil)",
			binding: allow,
			req: core.EgressRequest{
				Server:      "upstream",
				Payload:     []byte("smuggling secrets.go"),
				SourceSpans: []core.Span{{File: "secrets.go", StartLine: 1, EndLine: 2}},
			},
			wantAllowed: false,
			wantReason:  core.ReasonOutsideAllowlist,
		},
		{
			name:    "in-binding plus out-of-binding span blocked",
			binding: allow,
			req: core.EgressRequest{
				Server: "upstream",
				SourceSpans: []core.Span{
					{File: "auth.go", StartLine: 5, EndLine: 10},
					{File: "secrets.go", StartLine: 1, EndLine: 2},
				},
			},
			wantAllowed: false,
			wantReason:  core.ReasonOutsideAllowlist,
		},
		{
			name:        "no provenance denied",
			binding:     allow,
			req:         core.EgressRequest{Server: "upstream", Payload: []byte("anon")},
			wantAllowed: false,
			wantReason:  core.ReasonDenyByDefault,
		},
		{
			name:    "zero binding denies everything",
			binding: core.Binding{},
			req: core.EgressRequest{
				Server:      "upstream",
				SourceSpans: []core.Span{{File: "auth.go", StartLine: 5, EndLine: 10}},
			},
			wantAllowed: false,
			wantReason:  core.ReasonOutsideAllowlist,
		},
	}

	e := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Authorize(context.Background(), tt.binding, tt.req)
			if d.Allowed() != tt.wantAllowed {
				t.Fatalf("Allowed()=%v want %v (reason=%q detail=%q)",
					d.Allowed(), tt.wantAllowed, d.Reason(), d.Detail())
			}
			if d.Reason() != tt.wantReason {
				t.Fatalf("Reason()=%q want %q", d.Reason(), tt.wantReason)
			}
		})
	}
}

func TestEnforcementLabel(t *testing.T) {
	if EnforcementLabel != "userspace" {
		t.Fatalf("EnforcementLabel=%q want %q", EnforcementLabel, "userspace")
	}
	if got := New().Enforcement(); got != "userspace" {
		t.Fatalf("Enforcement()=%q want %q", got, "userspace")
	}
}

func TestGuaranteeIsHonest(t *testing.T) {
	g := New().Guarantee()
	if !strings.Contains(g, "NOT airtight") {
		t.Fatalf("Guarantee() must admit it is NOT airtight, got %q", g)
	}
	// Never over-claim total isolation in userspace mode.
	if strings.Contains(g, "zero code left your machine") {
		t.Fatalf("Guarantee() must not over-claim, got %q", g)
	}
}
