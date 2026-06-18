# Herkos

[![ci](https://github.com/akhilesharora/herkos/actions/workflows/ci.yml/badge.svg)](https://github.com/akhilesharora/herkos/actions/workflows/ci.yml) · [Live site](https://akhilesharora.github.io/herkos/) · Apache-2.0

A local-first, pure-Go reference implementation of **SpanGate**: the idea that the minimal
code context an AI agent *needs* to answer a query is exactly the set it should be *allowed*
to send back out. One code-graph relevance set serves as both the model's context and a
deny-by-default egress allowlist, and every answer produces a signed, offline-verifiable
Merkle receipt of which spans touched the model.

This is a working utility built around that idea, end to end and scoped honestly - see
[Findings](#findings) for the market and threat analysis. It is a clean, tested codebase you can
read, run, and verify.

## SpanGate
For each query, Herkos's local tree-sitter code graph emits a minimal set of
`(file, line-range)` spans. That same set is both the model's context (fewer tokens) and the
egress allowlist (deny-by-default). The dual-use is structural: a single `core.Binding` is the
only value both the serve path and the egress authorizer read, so "the context set and the
egress set are identical" is a type invariant, not a convention. Every answer ships a signed
Merkle receipt, verifiable offline by a third party with only the public key.

## What works
The pure-Go SpanGate core (SELECT -> Binding -> canonicalize -> pool -> signed receipt, with
the dual-use leak provably blocked), the tree-sitter parser (Go/TS/Python), the on-disk index,
the CLI, and the live in-path MCP broker (`herkos serve`, MCP newline-framed and verified end
to end against a real MCP server) all work and are tested under the race detector, fuzzed, and
gated on a clean-checkout build.

Enforcement is described plainly, because a security tool that hides its gaps is worse than
none:

- The broker's **default egress guard is tool-name only** - it gates which `tools/call` reach
  the upstream, not payload bytes or other methods.
- Pinning a served set (`--served-span` with `--index`) adds a **content gate** that blocks
  tool-call arguments carrying repo lines from outside the set, after normalizing case and
  whitespace so a reflow or recase still trips. This is a userspace tripwire that paraphrase,
  encoding, or token rewrite still defeat - not an airtight boundary.
- `serve --receipts <dir>` keeps a **signed, hash-chained audit log** of every brokered tool
  call, fail-closed (an audit-write failure stops the session rather than letting an unlogged
  call through). `herkos verify` detects any edit, reorder, or mid-drop offline with only the
  public key, and reports a truncated log (one missing its signed close) as incomplete. With a
  served set pinned, the opening record commits a fingerprint of that served context, so the
  receipt proves which context-egress binding was in force.
- `serve --isolate` runs a server in a **kernel network namespace with no route out**
  (unprivileged, Linux), so a server that only needs stdio to Herkos cannot open its own
  socket to any host. The transformation-resistant, full per-destination egress seal (eBPF
  host allowlisting) is still not built.

The signed receipt is the one durable, distinctive piece, and it works today.

## Reproduce it yourself
Broker a real MCP server, deny a tool in-path, and verify the signed receipt offline:
```
herkos keygen
# brokers the real server; echo is allowed, any other tools/call is blocked in-path
herkos serve --allow-tool echo --receipts /tmp/r -- npx -y @modelcontextprotocol/server-everything
herkos verify --file /tmp/r/<session>.jsonl --pubkey <public-key>   # VERIFIED ... cleanly closed
```
Editing a record, dropping the sealed last line, or using a different public key all make
`herkos verify` fail. Pin a served set and it is bound into the receipt:
```
herkos index .
herkos serve --allow-tool read_file --index .herkos/index --served-span auth.go:1-40 \
  --receipts /tmp/r -- npx -y @some/mcp-server
# the receipt's opening record now commits a fingerprint of the served set; flipping it fails verify
```

## Findings
Market and threat analysis (see [`CASE-STUDIES.md`](docs/CASE-STUDIES.md) for worked examples
against real 2025 MCP incidents) found:

- The in-path tool-name broker is **commodity** - Claude Code ships native MCP tool
  allow/deny in `settings.json`.
- The minimal-span code graph is **commoditizing** - shipping coding agents do their own
  conversation-aware retrieval, which beats an offline graph on quality.
- The marquee MCP attacks (GitHub toxic-agent-flow, `postmark-mcp`) ride *approved* tools or
  leak server-side, so a tool-name allowlist does not stop them; the broker's value is mostly
  **audit, not prevention**.
- The distinctive piece - a cryptographically signed, offline-verifiable, span-level receipt -
  maps directly to NIST 800-53 **AU-10** (non-repudiation), but AU-10 is a High-baseline-only
  requirement; mainstream and financial-sector compliance is satisfied by SIEM-fed audit logs,
  and signed agent-action provenance is itself an emerging, commoditizing pattern.

So Herkos stands as a reference implementation of the idea and the engineering - SpanGate's
dual-use invariant and verifiable receipts, done cleanly.

The one genuinely novel idea, written up honestly (what it is, why it differs from IFC and
signed-receipt work, and exactly where it holds and does not), is in
[`DUAL-USE-BINDING.md`](docs/DUAL-USE-BINDING.md). The honest field map, on three axes against
Pipelock, capgate, mcp-spine, mcp-scan, and srt, is in [`comparison.md`](docs/comparison.md).

## Run
```
# Generate the local signing key (stays on your machine, 0600).
herkos keygen

# Wrap a server already in your MCP config, in place, leaving no un-brokered entry behind.
herkos register --config .mcp.json --server github --allow-tool get_issue --allow-tool list_issues

# Or broker an upstream server directly. The agent's MCP client launches `herkos serve ...`;
# everything after -- is the upstream server command.
herkos serve --allow-tool read_file --allow-tool list_dir -- npx -y @some/mcp-server
```
A `tools/call` to any tool you did not `--allow-tool` is blocked in-path and answered with a
JSON-RPC error; the agent's session keeps running.

```
# Optional: arm the content gate. Build an index, then pin the spans the model may see.
# A tool-call argument carrying a verbatim repo line from outside auth.go:1-40 is blocked.
herkos index .
herkos serve --allow-tool post_message --index .herkos/index --served-span auth.go:1-40 \
  -- npx -y @some/mcp-server
```

```
# Keep a signed audit log of every brokered call, and cut the server's own network (Linux).
# On shutdown the log is sealed and its tip hash printed, so a later truncation is detectable.
herkos serve --allow-tool read_file --receipts ~/.herkos/audit --isolate -- npx -y @some/mcp-server
```

```
# Verify a receipt or a sealed audit log offline, with only the public key (no network, no
# trust in Herkos). A cleanly closed log reports VERIFIED; a chopped one reports INCOMPLETE.
herkos verify --file session-receipt.json --pubkey <hex>
herkos verify --file ~/.herkos/audit/<session>.jsonl --pubkey <hex>
```

## Develop
```
make build         # go build ./...
make race          # go test ./... -race
make lint          # golangci-lint run
make check         # build + vet + race + lint
make verify-clean  # build+vet+race the COMMITTED tree (HEAD) from a throwaway worktree
```

## Write-up
The honest account - what I built, why prevention is not achievable, and where it stands
against the field - is in [WRITEUP.md](docs/WRITEUP.md).

## License
Apache-2.0.
