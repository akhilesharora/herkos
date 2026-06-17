# The dual-use binding

**Thesis:** the minimal code context a model is served and the egress allowlist that bounds
what it may send should be the *same* object, computed once. Herkos calls that object a
`Binding`. This note states the idea, separates it from the signed-receipt and
information-flow-control work it superficially resembles, and says plainly where it holds and
where it does not. It is a design note, not a product pitch (see [README](README.md) for what
Herkos is and is not).

## The problem

An AI coding agent reads private source and can also call tools that leave the machine. The
usual response bolts on two separate mechanisms: one to trim the context sent to the model,
another to police egress. Provenance, "which lines of my code actually went to the model," is
then reconstructed after the fact from logs, if at all. The two mechanisms can disagree, and
the after-the-fact reconstruction is exactly that.

## The insight: one object, three roles

A `Binding` is constructed once from a resolved `SpanSet` (a set of `(file, line-range)`
spans produced by the local tree-sitter code graph). That single value is simultaneously:

1. **the context** the model is served (those spans, canonicalized);
2. **the deny-by-default read + egress allowlist** (a payload is authorized only if every
   source span it derives from is `Covers`-ed by the set; the zero value authorizes nothing);
3. **the signed input manifest** (the spans are the leaves of an ed25519 Merkle receipt,
   verifiable offline with only the public key).

There is no API that serves one set and enforces another. "Context set == egress set" is a
type invariant, not a convention, because both the serve path and the egress authorizer read
exactly the same `Binding`.

```go
// internal/core: the only value both the serve path and the egress authorizer read.
type Binding struct{ spans SpanSet }

func NewBinding(ss SpanSet) Binding { return Binding{spans: ss} }

// AuthorizePayload allows a payload iff EVERY source span it derives from is covered by the
// bound set. No provenance, or any span outside the set, denies. The zero Binding denies all.
func (b Binding) AuthorizePayload(req EgressRequest) Decision {
	if len(req.SourceSpans) == 0 {
		return Deny(ReasonDenyByDefault, "no provenance")
	}
	for _, s := range req.SourceSpans {
		if !b.spans.Covers(s) {
			return Deny(ReasonOutsideAllowlist, s.String())
		}
	}
	return Allow()
}
```

## Why this is not the prior art

The pieces look familiar; the combination is not.

- **Information-flow control for agents** (e.g. Microsoft's Fides, `arXiv:2505.23643`):
  propagates confidentiality/integrity *labels* through messages, tool calls, and results,
  and enforces deterministically. Powerful and shipped. But labels are assigned at trust
  boundaries and bind to *messages*, not to source-code spans. The dual-use binding is one
  notch finer: the unit is `(file, line-range)`, auto-derived from the code graph, with no
  manual label assignment.
- **Signed agent receipts** (Agent Receipts/AGA, Vouched KYA-OS, Prismer Signet, mcptrust,
  Microsoft's agent-governance-toolkit): sign the *output* envelope of a tool call (method,
  params, result). None signs the *input* context the model saw. Same primitives
  (Ed25519, Merkle, RFC 8785 JCS), different referent.
- **SLSA / in-toto provenance**: "materials" are repo- or artifact-granular. The dual-use
  binding is the input predicate at *span* granularity.
- **Outbound allowlists** (HTTP/domain egress for agents): bind to agent identity,
  destination domains, or IPs. Not to the content the model was given.

The field is output- and traffic-centric: it can assert *what flowed* and *what was called*,
never *what was allowed in* bound to *what is allowed out*. The span set is the only artifact
organized around the input set, and binding it to egress upgrades it from a log to a boundary.

## The hard constraint, stated plainly

The binding is only real where the broker mediates **100% of the agent's code access and
egress**. A coding agent that reads files natively (`cat`, `grep`, its own Read tool) bypasses
an MCP-broker-level binding, leaving the manifest incomplete and the allowlist unenforced. To
be complete, the binding must sit on the *sole* filesystem-read and egress path: a
syscall/FUSE-level interception or a policy-mandated sandbox, not an in-path MCP broker. In a
topology where the agent can bypass it, the binding is an honest log, not a boundary, and it
should be described as exactly that.

## What it does and does not protect

- **Does:** bound direct egress of repo content outside the served set; produce an exact,
  deterministic record of what entered context (as opposed to probabilistic NL taint-tracking,
  which is ~0.9-F1 at best).
- **Does not:** stop denial-feedback / causal side channels (`arXiv:2604.04035`); stop
  exfiltration via logs, stdout, or subagents outside the mediated path (the majority of
  real-world leak channels); stop regurgitation from the model's training memory. A span
  boundary mediates the read+egress path and nothing beyond it.

## Where it is meaningful

Forced-mediation deployments where org policy routes all model context through the broker:
regulated or air-gapped shops (defense, finance, medical-device firmware). There the
chokepoint is real, the allowlist is enforceable, and line-range granularity is contractually
meaningful for license-contamination ("prove the authorized context excluded GPL span X") and
data-residency ("these lines never crossed the boundary"). Outside such a topology, the value
collapses to provenance-as-log, and the market currently asks for that at file/commit
granularity, not span.

## As a standard

The cleanest form of the idea is not a proprietary receipt but an in-toto / SLSA
`inputs`/`materials` predicate at `(file, line-range)` granularity, captured at the
point of generation and verified downstream. That is the interoperable contribution, and a
more useful one than another signed-receipt format.

## Status

Reference implementation in Go: `internal/core` (`Binding`, `SpanSet`), the SpanGate pipeline,
and ed25519 Merkle receipts (`pkg/receipt`), with the egress half wired into `herkos serve`
as an opt-in content gate. Reference implementation, not a product.
