//go:build !cgo

package cli

import (
	"fmt"
	"io"
)

// indexCmd in a non-cgo build cannot parse: tree-sitter needs cgo. Query commands
// (`herkos select`) still work against an index built elsewhere with a cgo build.
func indexCmd(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "index: this build has no tree-sitter parser; rebuild with CGO_ENABLED=1")
	return 1
}
