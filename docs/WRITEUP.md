# Herkos: an MCP egress broker, and why I am not shipping it as a product

This is the honest write-up of a project I built end to end and then talked myself out of. It
is a reference implementation, not a product, and the interesting part is *why* - because the
reasoning is a reasonable map of what is solved, what is not, and what is worth a reader's time
in agent security right now.

## The idea

When an AI coding agent answers a query, a local code graph can emit a minimal set of
`(file, line-range)` spans that are exactly what the model needs as context. The bet of
**SpanGate** is that this same set is also exactly what the agent should be *allowed to send
back out*: the minimal context an agent needs to answer is the only thing it should be able to
exfiltrate. So one relevance set is both the model's context and the egress allowlist.

The one part of this I still think is clean: I made that a *type invariant*. A single
`core.Binding` value is the only thing both the serve path and the egress authorizer read, so
"the context set and the egress set are identical" is enforced by the type system, not by a
convention two code paths politely agree to. There is no API that serves one set and enforces a
different one.

## What I built

All pure Go, tested under the race detector, fuzzed, lint-clean:

- An in-path **stdio MCP broker** with a deny-by-default tool-name allowlist (a `tools/call` to
  a tool you did not allow gets a hard error in-path; the session keeps running).
- A **content tripwire**: with a served set pinned, verbatim repo lines from outside it are
  blocked on the way to a tool call.
- A **signed, hash-chained, offline-verifiable audit log** of every brokered call, fail-closed.
- Unprivileged **kernel network-namespace egress isolation** (`serve --isolate`).
- `herkos scan`: structural hygiene for an MCP config (unpinned, unbrokered, over-scoped,
  baseline-drift, remote).

## The finding that ended it: you cannot prevent the thing people want prevented

The expensive breaches of 2025-2026 ride *approved* tools or leak server-side. Prompt injection
and tool poisoning are near-provably not preventable, and the literature is blunt about it:
tool-description poisoning hits roughly 100% attack success (arXiv:2605.24069), adaptive attacks
recover 28-64% against filters (arXiv:2606.15057), and a recent benchmark finds "not a single
attack objective reliably resisted" (arXiv:2606.13385). CaMeL's whole framing is that you do not
beat injection, you constrain what the agent can do with tainted data (arXiv:2503.18813).

So an in-path broker cannot prevent the marquee attacks, and Herkos says so on its own homepage.
The honest value of the entire category is *harm-reduction and forensics*, not prevention. The
market budget chases prevention nobody can deliver, which is the category's core problem.

## Where it stands against the field, honestly

Three of the four pillars are commodity:

- **Tool allowlisting and egress sandboxing are native** in the hosts the user already runs:
  Claude Code, Cursor, and VS Code Copilot all ship deny-by-default MCP allowlists and OS-level
  network sandboxes, enterprise-managed.
- **Signed offline-verifiable receipts** ship in open-source **Pipelock** (Go, Ed25519 + hash
  chain + a non-Go verifier, covering MCP stdio *and* HTTP) and in patented AGA, and are
  standardized in an MCP extension (arXiv:2605.24248).
- **Admission scanning** is Snyk's / Invariant's `mcp-scan`, which detects the tool-poisoning
  Herkos's scan does not.

And the one idea that was mine - the dual-use binding - is real but verbatim-only today (base64
defeats it) and lives in a stdio broker (the wrong layer; the honest vehicle is a syscall/FUSE
interceptor). Worse for novelty: the *smart* version, transformation-resistant taint that
survives encoding, is already published as **NeuroTaint** (arXiv:2604.23374), and bounding exfil
with certified leakage budgets is **OCELOT** (arXiv:2606.12341). The agent-security field is a
hyperactive frontier; there were a dozen relevant papers in the last two weeks of arXiv alone.

## So what is it good for

The product does not have a lane: commodity pillars, a niche idea, no proven buyer, and a
transport (stdio) the ecosystem is leaving. I am not going to pretend otherwise.

What is genuinely useful is the rest:

- **The map.** A verified, cited account of what the real attacks are, why in-path brokering is
  necessary but insufficient (the MCP-DPT defense-placement taxonomy, arXiv:2604.07551), and
  where the defenses actually live. That is more useful to a reader than the binary.
- **The method.** Shipping a security tool *with* its own bypass list, and scoring each real
  incident as "prevents / does not," is a discipline most tools skip. See the
  [case studies](CASE-STUDIES.md) and the security model.
- **A 30-second utility.** `herkos scan ~/.claude.json` is a real, zero-install local check that
  flags an unpinned / unbrokered / remote MCP server. Snyk does it deeper; this does it for free
  in a second.
- **Reference code.** The unprivileged netns egress trick and the fail-closed hash-chained log
  are clean snippets a learner can lift.

The name fits the conclusion: *Herkos* (ancient Greek for the bulwark that stands in front;
Homer's epithet for Ajax, the wall of his army) is a good name for a thing that holds a line.
It just turns out the line was already held.
