package core

import "fmt"

// DenyReason is a machine-checkable authorization outcome code, so offline receipt
// replay can reason about WHY something was denied without parsing free text.
type DenyReason string

const (
	ReasonInSpan           DenyReason = "in-span"
	ReasonDenyByDefault    DenyReason = "deny-by-default"
	ReasonOutsideAllowlist DenyReason = "outside-allowlist"
)

// Decision is the outcome of an authorization check. Its zero value is a DENY
// (reason "deny-by-default"), so an uninitialized Decision can never accidentally
// authorize an action.
type Decision struct {
	allowed bool
	reason  DenyReason
	detail  string
}

// Allow returns an allow Decision.
func Allow() Decision { return Decision{allowed: true, reason: ReasonInSpan} }

// Deny returns a deny Decision with a machine-checkable reason and human detail.
func Deny(reason DenyReason, detail string) Decision {
	return Decision{allowed: false, reason: reason, detail: detail}
}

// Allowed reports whether the action is authorized.
func (d Decision) Allowed() bool { return d.allowed }

// Reason returns the machine-checkable code; a zero Decision reports deny-by-default.
func (d Decision) Reason() DenyReason {
	if d.reason == "" {
		return ReasonDenyByDefault
	}
	return d.reason
}

// Detail returns the human-readable explanation, if any.
func (d Decision) Detail() string { return d.detail }

// AuthorizeLine returns an allow/deny Decision for sending the given file line across
// an egress boundary; authorized only if the line is within the set.
func (ss SpanSet) AuthorizeLine(file string, line int) Decision {
	if ss.AllowsLine(file, line) {
		return Allow()
	}
	return Deny(ReasonOutsideAllowlist, fmt.Sprintf("%s:%d", file, line))
}
