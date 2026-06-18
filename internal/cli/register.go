package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/akhilesharora/herkos/internal/register"
)

// registerCmd wires Herkos into an MCP config. There are two modes:
//
//	--server NAME : wrap an existing server in place so the agent launches it THROUGH the
//	                broker, leaving no direct bypass. This is the recommended way to gate a
//	                server you already have configured.
//	-- CMD ARGS   : add a standalone herkos broker entry for the given upstream. Any servers
//	                already in the config are left as-is (and can still be called directly).
//
// The prior config is backed up to <config>.bak before the rewrite, and both modes are
// idempotent.
//
// Usage: herkos register --config PATH --server NAME [--allow-tool NAME]...
//
//	or: herkos register --config PATH [--allow-tool NAME]... -- CMD [ARGS...]
func registerCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "path to the MCP config JSON to modify")
	server := fs.String("server", "", "wrap an existing server by name, in place (no direct bypass left)")
	all := fs.Bool("all", false, "broker every local stdio server in the config in place, pinning each to the tools it exposes now")
	var allow stringList
	fs.Var(&allow, "allow-tool", "tool the agent may call upstream (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "register: -config is required")
		return 2
	}
	if *all && (*server != "" || len(fs.Args()) > 0) {
		fmt.Fprintln(stderr, "register: --all cannot be combined with --server or an upstream command")
		return 2
	}
	// A backup is only written when the config already exists, so report accurately:
	// claim a .bak only when there was a prior file to preserve.
	_, statErr := os.Stat(*cfgPath)
	existed := statErr == nil
	bak := ""
	if existed {
		bak = fmt.Sprintf(" (backup at %s.bak)", *cfgPath)
	}

	// Auto-wrap mode: broker every local stdio server in one pass, pinning each to its current
	// tools. This is the one-command adoption path - point an agent's whole config through the
	// broker without hand-editing each launch line.
	if *all {
		results, err := register.WrapAll(*cfgPath, register.DiscoverTools)
		if err != nil {
			fmt.Fprintf(stderr, "register: %v\n", err)
			return 1
		}
		wrapped := 0
		for _, r := range results {
			if r.Wrapped {
				wrapped++
				fmt.Fprintf(stdout, "wrapped %q through herkos (pinned %d tool(s): %s)\n", r.Name, len(r.Tools), strings.Join(r.Tools, ", "))
			} else {
				fmt.Fprintf(stderr, "skipped %q: %s\n", r.Name, r.Skip)
			}
		}
		fmt.Fprintf(stdout, "register --all: wrapped %d server(s) in %s%s\n", wrapped, *cfgPath, bak)
		return 0
	}

	// Wrap mode: rewrite an existing named server in place. No direct path to it is left.
	if *server != "" {
		if err := register.Wrap(*cfgPath, *server, allow); err != nil {
			fmt.Fprintf(stderr, "register: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrapped %q through herkos in %s%s\n", *server, *cfgPath, bak)
		return 0
	}

	// Standalone mode: add a herkos broker entry for the given upstream.
	upstream := fs.Args()
	if len(upstream) == 0 {
		fmt.Fprintln(stderr, "register: missing upstream command (or use --server NAME to wrap an existing server)")
		fmt.Fprintln(stderr, "usage: herkos register --config PATH --server NAME [--allow-tool NAME]...")
		fmt.Fprintln(stderr, "   or: herkos register --config PATH [--allow-tool NAME]... -- CMD [ARGS...]")
		return 2
	}
	if err := register.Register(*cfgPath, buildServeArgs(allow, upstream)); err != nil {
		fmt.Fprintf(stderr, "register: %v\n", err)
		return 1
	}
	if existed {
		fmt.Fprintf(stdout, "registered herkos in %s%s\n", *cfgPath, bak)
	} else {
		fmt.Fprintf(stdout, "registered herkos in %s (new file created)\n", *cfgPath)
	}
	fmt.Fprintf(stderr, "note: any server already in %s is left as-is and can still be called directly, bypassing Herkos; to gate one with no bypass, use: register --config %s --server <name>\n", *cfgPath, *cfgPath)
	return 0
}

// unregisterCmd removes Herkos's entry from an MCP config. It is idempotent: removing an
// absent entry is a no-op, not an error.
func unregisterCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unregister", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "path to the MCP config JSON to modify")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" {
		fmt.Fprintln(stderr, "unregister: -config is required")
		return 2
	}
	if err := register.Unregister(*cfgPath); err != nil {
		fmt.Fprintf(stderr, "unregister: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "unregistered herkos from %s\n", *cfgPath)
	return 0
}

// buildServeArgs assembles the `serve` arguments recorded in the config entry: each
// allowed tool as a --allow-tool flag, then -- and the upstream command.
func buildServeArgs(allow stringList, upstream []string) []string {
	args := make([]string, 0, len(allow)*2+1+len(upstream))
	for _, t := range allow {
		args = append(args, "--allow-tool", t)
	}
	args = append(args, "--")
	return append(args, upstream...)
}
