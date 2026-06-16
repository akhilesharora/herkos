//go:build cgo

package cli

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/akhilesharora/herkos/internal/adapters/graph/treesitter"
	"github.com/akhilesharora/herkos/internal/index"
)

// indexCmd parses a source tree with tree-sitter and writes a portable on-disk index that
// `herkos select` (and, later, serve) can query without cgo.
//
// Usage: herkos index <dir> [--out PATH]
func indexCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "index output path (default <dir>/.herkos/index)")
	// Accept the dir either before or after flags: Go's flag stops at the first positional,
	// so a leading non-flag arg is pulled out before parsing the rest.
	var dir string
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if dir == "" {
		dir = fs.Arg(0)
	}
	if dir == "" {
		fmt.Fprintln(stderr, "index: usage: herkos index [--out PATH] <dir>")
		return 2
	}
	nodes, err := treesitter.ParseDirNodes(dir)
	if err != nil {
		fmt.Fprintf(stderr, "index: %v\n", err)
		return 1
	}
	path := *out
	if path == "" {
		path = filepath.Join(dir, ".herkos", "index")
	}
	if err := index.Save(path, nodes); err != nil {
		fmt.Fprintf(stderr, "index: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "indexed %d symbols from %s -> %s\n", len(nodes), dir, path)
	return 0
}
