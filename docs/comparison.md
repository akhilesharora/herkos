# Herkos vs the field

An honest map. Herkos occupies one position no shipping tool here occupies, and concedes every other lane to more mature tools. This page makes both halves explicit.

## The one position no profiled shipping tool occupies

**Context-derived egress.** The minimal code-graph context the agent is served *is* the egress allowlist: a single `core.Binding` is the only value both the serve path and the egress gate read, so "what may leave" and "what was read in" cannot drift apart. The signed audit receipt commits a fingerprint of that served context, so it proves the brokered calls happened under that exact binding.

No tool surveyed derives its egress decision from the served code context - they decide from traffic content, static policy, or hand-written allowlists. The idea itself is anticipated in the literature (CaMeL, OCELOT, NeuroTaint), so this is novel-in-product, not novel-in-concept.

## The field on three axes

Each agent-security tool sits on three independent axes: where the allow/deny is computed (`decision`), where it is applied (`enforcement`), and what the receipt proves (`evidence`).

| Tool | decision | enforcement | evidence | vs Herkos |
|---|---|---|---|---|
| **Herkos** | context-derived (served span set) | mcp_proxy + Linux netns | ed25519 hash-chain, offline-verifiable, binds served context | the wedge; everything else below is more mature in its lane |
| Pipelock | network_mediator (content scan) | http/ws/mcp proxy + kernel sandbox | ed25519, 2 spec'd formats, 4 verifiers, conformance suite | strict superset on receipts, coverage, sandbox |
| capgate | scanner (compile-time) | emits bwrap/docker/nftables config | unsigned manifest hash | stronger per-host egress allowlist; no runtime, no signed audit |
| mcp-spine | in_runtime proxy | mcp_proxy | symmetric HMAC (not offline-verifiable) | more features; audit is not third-party verifiable; no egress control |
| Invariant/Snyk mcp-scan | scanner | pre-connect / mcp_proxy | runtime log | broader config/tool-definition risk scan |
| srt (Claude Code sandbox) | network_mediator | OS sandbox (Seatbelt/bubblewrap) | none | real cross-platform sandbox + domain allowlist; no audit, no broker |

## What Herkos concedes

- **Signed receipts:** Pipelock ships a strict superset (two versioned formats, JCS canonicalization, Go/TS/Rust/Python verifiers, a conformance suite). Herkos has one format and one verifier.
- **Egress isolation:** srt, CAPSEM, agentsh, capgate, and Pipelock enforce at a harder boundary (hardware VM, kernel seccomp/eBPF/Landlock, in-kernel nftables). Herkos's `serve --isolate` is a single unprivileged Linux netns.
- **Content inspection:** mcp-scan and Pipelock do real DLP and injection detection. Herkos's content gate is a case- and whitespace-normalized verbatim tripwire, defeatable by paraphrase or encoding.
- **Maturity:** Pipelock (CNCF-listed), srt and AGT (~4.4k stars), mcp-scan (Snyk, ~2.6k) are all more mature than Herkos.

## What is true and battle-tested today

- `herkos serve` brokers a real MCP server (`@modelcontextprotocol/server-everything`) deny-by-default; a non-allowlisted tool is answered with a JSON-RPC error in-path and the session continues.
- The audit receipt is ed25519-signed, sha256 hash-chained, and offline-verifiable with only the public key; it commits the served-context fingerprint; an edit, a truncation, a flipped context byte, or a wrong key all fail `herkos verify`.
- `herkos scan` audits an MCP config for unbrokered, unpinned-install, over-scoped, poisoned, unrestricted-egress, and remote servers.

Reproduce all three yourself from the commands in the [README](../README.md).

## Claims this project will not make

Checkable-false, so absent here by design: "first or only to bind context to egress" (the literature predates it); "strongest or most complete signed receipt"; "best egress isolation or sandbox"; "blocks data exfiltration" (the tripwire does not); "enforces a network-destination allowlist" (the netns is all-or-nothing); "cross-platform"; "more mature or more battle-tested than the field".
