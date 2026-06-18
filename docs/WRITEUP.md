# Herkos: an MCP egress broker, and an honest map of where it stands

This is an MCP egress broker, built end to end, plus an honest, cited map of where it stands.
It is a reference implementation of the idea, and the interesting part is the map: a grounded
account of what is solved in agent security right now, what is not, and what is worth a reader's
time.

## The idea

When an AI coding agent answers a query, a local code graph can emit a minimal set of
`(file, line-range)` spans that are exactly what the model needs as context. The bet of
**SpanGate** is that this same set is also exactly what the agent should be *allowed to send
back out*: the minimal context an agent needs to answer is the only thing it should be able to
exfiltrate. So one relevance set is both the model's context and the egress allowlist.

The clean, distinct part is that I made that a *type invariant*. A single `core.Binding` value
is the only thing both the serve path and the egress authorizer read, so "the context set and
the egress set are identical" is enforced by the type system, not by a convention two code paths
politely agree to. There is no API that serves one set and enforces a different one.

## What I built

All pure Go, tested under the race detector, fuzzed, lint-clean:

- An in-path **stdio MCP broker** with a deny-by-default tool-name allowlist (a `tools/call` to
  a tool you did not allow gets a hard error in-path; the session keeps running).
- A **content tripwire**: with a served set pinned, repo lines from outside it are blocked on
  the way to a tool call, after normalizing case and whitespace (so a reflow or recase still
  trips it; base64, paraphrase, or splitting a line across calls still pass).
- A **signed, hash-chained, offline-verifiable audit log** of every brokered call, fail-closed.
- An unprivileged **Linux network namespace with no route out** (`serve --isolate`).
- `herkos scan`: structural hygiene for an MCP config (unpinned, unbrokered, over-scoped,
  baseline-drift, remote).

## What this category can and cannot do

The expensive breaches of 2025-2026 ride *approved* tools or leak server-side. Prompt injection
and tool poisoning are near-provably not preventable, and the literature is blunt about it:
tool-description poisoning hits roughly 100% attack success ([arXiv:2605.24069](https://arxiv.org/abs/2605.24069)), adaptive attacks
recover 28-64% against filters ([arXiv:2606.15057](https://arxiv.org/abs/2606.15057)), and a recent benchmark finds "not a single
attack objective reliably resisted" ([arXiv:2606.13385](https://arxiv.org/abs/2606.13385)). CaMeL's whole framing is that you do not
beat injection, you constrain what the agent can do with tainted data ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)).

So this is the scope of the whole category, not a flaw unique to Herkos: an in-path broker
cannot prevent the marquee attacks, and Herkos says so on its own homepage. What an in-path
broker delivers is *harm-reduction and forensics* - a tighter blast radius and a verifiable
record of what happened - not prevention. Knowing that line up front is the difference between a
tool sold honestly and a market budget chasing prevention nobody can deliver.

## Where it stands against the field, honestly

Three of the four pillars are commodity:

- **Tool allowlisting and egress sandboxing are native** in the hosts the user already runs:
  Claude Code, Cursor, and VS Code Copilot all ship deny-by-default MCP allowlists and OS-level
  network sandboxes, enterprise-managed.
- **Signed offline-verifiable receipts** ship in open-source **Pipelock** (Go, Ed25519 + hash
  chain + a non-Go verifier, covering MCP stdio *and* HTTP) and in patented AGA, and are
  standardized in an MCP extension ([arXiv:2605.24248](https://arxiv.org/abs/2605.24248)). Pipelock is a strict superset of the
  Herkos receipt: it covers more transport and ships a verifier outside Go.
- **Admission scanning** is Snyk's / Invariant's `mcp-scan`, which detects tool-poisoning by
  content analysis with no baseline; Herkos's scan only flags tool-description drift against a
  trusted baseline, so it misses first-seen poisoning.

The one distinct position is the dual-use binding: context-derived egress as a type invariant.
That is real and distinct in a shipping product, though the concept itself is anticipated in the
research (CaMeL, OCELOT, NeuroTaint), so it is distinct-in-product, not new-as-an-idea. Two
honest limits ride with it. The binding is enforced today by a shallow content tripwire: it
normalizes case and whitespace (so reflow/recase trip it) but base64, paraphrase, or token
rewrites defeat it. And it lives in a stdio broker, which is the wrong layer; the
transformation-resistant version belongs in a syscall/FUSE interceptor. The smarter forms of
this are already published - transformation-resistant taint that survives encoding is
**NeuroTaint** ([arXiv:2604.23374](https://arxiv.org/abs/2604.23374)), and bounding exfil with certified leakage budgets is
**OCELOT** ([arXiv:2606.12341](https://arxiv.org/abs/2606.12341)). The agent-security field is a hyperactive frontier; there were a
dozen relevant papers in the last two weeks of arXiv alone.

## So what is it good for

Four things:

- **The map.** A verified, cited account of what the real attacks are, why in-path brokering is
  necessary but insufficient (the MCP-DPT defense-placement taxonomy, [arXiv:2604.07551](https://arxiv.org/abs/2604.07551)), and
  where the defenses actually live. For a reader deciding what to trust in this space, that is
  the most useful artifact here.
- **The method.** Shipping a security tool *with* its own bypass list, and scoring each real
  incident as "prevents / does not," is a discipline most tools skip. See the
  [case studies](CASE-STUDIES.md) and the security model.
- **A 30-second utility.** `herkos scan ~/.claude.json` is a real, zero-install local check that
  flags unpinned, unbrokered, over-scoped, remote, and baseline-drift MCP servers. Snyk's
  `mcp-scan` goes deeper and catches first-seen poisoning the baseline scan does not; Herkos
  does the structural hygiene pass for free in a second.
- **Reference code.** The unprivileged netns egress trick and the fail-closed hash-chained log
  are clean snippets a learner can lift.

The name fits the work: *Herkos* (ancient Greek for the bulwark that stands in front; Homer's
epithet for Ajax, the wall of his army) is a good name for a thing that holds a line. Herkos
holds the line it can actually hold: not prevention, but a smaller blast radius and a receipt
you can verify after the fact. That line is a narrow one - harm-reduction, forensics, and an
honest map - and this holds it in the open, gaps and all.
