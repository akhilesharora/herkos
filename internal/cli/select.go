package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/index"
)

// selectCmd runs the SpanGate SELECT stage against a prebuilt index and prints the minimal
// span set for the query. It is pure-Go (no cgo): it queries an index built by `herkos
// index`. This is the served set - the same spans that would become the egress allowlist.
//
// Usage: herkos select --index PATH --anchor SYM [--anchor SYM]... [--budget N]
func selectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("select", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	idxPath := fs.String("index", "", "path to an index built by `herkos index`")
	budget := fs.Int("budget", 200, "line budget for the span set")
	var anchors stringList
	fs.Var(&anchors, "anchor", "symbol to anchor the query on (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *idxPath == "" {
		fmt.Fprintln(stderr, "select: --index is required")
		return 2
	}
	if len(anchors) == 0 {
		fmt.Fprintln(stderr, "select: at least one --anchor is required")
		return 2
	}
	g, err := index.Open(*idxPath)
	if err != nil {
		fmt.Fprintf(stderr, "select: %v\n", err)
		return 1
	}
	ss, err := g.Select(context.Background(), core.Query{Anchors: anchors, LineBudget: *budget})
	if err != nil {
		fmt.Fprintf(stderr, "select: %v\n", err)
		return 1
	}
	spans := ss.Spans()
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].File != spans[j].File {
			return spans[i].File < spans[j].File
		}
		return spans[i].StartLine < spans[j].StartLine
	})
	for _, s := range spans {
		fmt.Fprintf(stdout, "  %s:%d-%d\n", s.File, s.StartLine, s.EndLine)
	}
	fmt.Fprintf(stdout, "select: %d spans, %d lines (budget %d)\n", ss.Len(), ss.TotalLines(), *budget)
	return 0
}
