# Contributing to Herkos

Herkos is a local-first context and egress broker for AI coding agents, and a reference
implementation of the SpanGate idea. It is small, pure-Go, and meant to be read as much as
run. Contributions that keep it honest and tested are welcome.

## Build and test

```
make build         # go build ./...
make test          # go test ./...
make race          # go test ./... -race
make lint          # golangci-lint run
make check         # build + vet + race + lint
make verify-clean  # build + test the committed tree (HEAD) in a throwaway worktree
```

`make verify-clean` is the bar a change has to clear: it builds and tests HEAD from a clean
checkout, so an uncommitted file can never mask a broken commit.

`herkos index` needs a C toolchain (the tree-sitter parser is cgo). Everything else is pure Go.

## What a good change looks like

- Tests first, or alongside. Match the existing table-driven style and the package layout.
- Keep the honesty. Herkos publishes what gets past it (see the security model). If a change
  narrows or widens a guarantee, say so in the docs and on the security page; do not oversell.
- Small, focused commits with a plain conventional-commit subject (`feat:`, `fix:`, `docs:`).
- No new dependencies without a reason. The point is a tight, auditable surface.

## Reporting a bypass

The most useful issue is a way past the broker that is not already on the published bypass
list. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under Apache-2.0, the same as the project.
