package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/akhilesharora/herkos/internal/scan"
)

// scanCmd inspects an MCP config and prints a shareable one-line receipt. On a real launch
// config ({"mcpServers":{...}}, the Claude Code / Cursor / Cline shape) it flags servers that
// run directly instead of through the broker (unbrokered) and npx auto-installs of unpinned
// packages. On a security manifest ({"servers":[...]} with declared tool metadata) it flags
// over-scoped servers, unrestricted egress, and - when --baseline is supplied - poisoned
// tool descriptions.
func scanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "path to an MCP config JSON to scan")
	baselinePath := fs.String("baseline", "", "optional JSON map of \"server/tool\" -> trusted description")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "scan: -config is required")
		return 2
	}
	cfg, err := scan.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return 1
	}
	var baseline map[string]string
	if *baselinePath != "" {
		raw, err := os.ReadFile(*baselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "scan: baseline: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &baseline); err != nil {
			fmt.Fprintf(stderr, "scan: baseline: invalid JSON: %v\n", err)
			return 1
		}
	}
	rep := scan.Scan(cfg, baseline)
	for _, f := range rep.Findings {
		target := f.Server
		if f.Tool != "" {
			target += "/" + f.Tool
		}
		fmt.Fprintf(stdout, "  [%s] %s: %s\n", f.Kind, target, f.Detail)
	}
	fmt.Fprintln(stdout, rep.String())
	return 0
}
