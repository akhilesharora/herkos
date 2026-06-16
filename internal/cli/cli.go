// Package cli implements the `herkos` command surface using only the standard library
// (no external CLI framework, to keep the dependency supply chain minimal).
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/akhilesharora/herkos/pkg/receipt"
)

// Version is the build version, overridable via -ldflags at release.
var Version = "dev"

// Main runs the CLI and returns a process exit code. stdin is the agent-side MCP stream,
// used by `serve`; the other commands ignore it.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "status":
		return status(args[1:], stdout)
	case "receipt":
		return receiptCmd(args[1:], stdout, stderr)
	case "verify":
		return verifyCmd(args[1:], stdout, stderr)
	case "serve":
		return serveCmd(args[1:], stdin, stdout, stderr)
	case "index":
		return indexCmd(args[1:], stdout, stderr)
	case "select":
		return selectCmd(args[1:], stdout, stderr)
	case "scan":
		return scanCmd(args[1:], stdout, stderr)
	case "register":
		return registerCmd(args[1:], stdout, stderr)
	case "unregister":
		return unregisterCmd(args[1:], stdout, stderr)
	case "init":
		fmt.Fprintln(stdout, "init: wire Herkos into your agent with:")
		fmt.Fprintln(stdout, "  herkos register --config <mcp.json> --allow-tool <tool> -- <upstream cmd>")
		return 0
	case "keygen":
		return keygenCmd(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "herkos: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, "usage: herkos <serve|index|select|register|unregister|scan|status|receipt|verify|keygen|init> [flags]\n")
}

func status(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *asJSON {
		b, _ := json.Marshal(map[string]string{"name": "herkos", "version": Version, "status": "ok"})
		fmt.Fprintln(w, string(b))
		return 0
	}
	fmt.Fprintf(w, "herkos %s (ok)\n", Version)
	return 0
}

func receiptCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receipt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "path to a receipt JSON file to summarize")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(stderr, "receipt: -file is required")
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(stderr, "receipt: %v\n", err)
		return 1
	}
	var r receipt.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		fmt.Fprintf(stderr, "receipt: invalid receipt JSON: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "receipt root=%s enforcement=%s spans=%d\n", r.Root, r.Enforcement, len(r.Leaves))
	return 0
}
