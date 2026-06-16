// Command herkos is the local-first context + egress broker for AI coding agents.
// SpanGate computes a minimal span set per query and uses it as both the model's context
// and the egress allowlist.
package main

import (
	"os"

	"github.com/akhilesharora/herkos/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
