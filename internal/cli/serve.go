package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/akhilesharora/herkos/internal/keys"
	"github.com/akhilesharora/herkos/internal/receiptlog"
	"github.com/akhilesharora/herkos/internal/serve"
)

// stringList is a repeatable string flag, e.g. --allow-tool a --allow-tool b.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// agentEOFReader cancels the session when the agent's stream ends. A disconnecting agent
// must tear down the upstream child; cancelling makes exec.CommandContext kill it, which
// closes its stdout and unblocks the upstream->agent pump (a blocking read on a live child
// is not ctx-cancellable on its own).
type agentEOFReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (a agentEOFReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if errors.Is(err, io.EOF) {
		a.cancel()
	}
	return n, err
}

// serveCmd runs Herkos as an in-path MCP broker. It speaks MCP to the agent over
// stdin/stdout and proxies to an upstream MCP server (given after `--`), enforcing a
// deny-by-default tool allowlist on the agent->upstream direction.
//
// Usage: herkos serve [--allow-tool NAME]... [--key PATH] -- CMD [ARGS...]
func serveCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var allow stringList
	fs.Var(&allow, "allow-tool", "tool the agent may call upstream (repeatable); none = deny all tools/call")
	var servedSpans stringList
	fs.Var(&servedSpans, "served-span", "served span FILE:START-END (repeatable); arms the content gate, needs --index")
	indexPath := fs.String("index", "", "code-graph index path (with --served-span, arms the egress content gate)")
	root := fs.String("root", ".", "repo root the index's file paths are relative to")
	keyPath := fs.String("key", defaultKeyPath(), "signing key path")
	receiptsDir := fs.String("receipts", "", "write a signed, tamper-evident audit log of brokered tool calls to this dir (opt-in)")
	isolate := fs.Bool("isolate", false, "run the upstream in a network namespace with no egress of its own (Linux; for servers that only need stdio to Herkos)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	upstream := fs.Args()
	if len(upstream) == 0 {
		fmt.Fprintln(stderr, "serve: missing upstream command")
		fmt.Fprintln(stderr, "usage: herkos serve [--allow-tool NAME]... [--key PATH] -- CMD [ARGS...]")
		return 2
	}

	// Load (or create) the local signing key and announce its public half so a verifier can
	// check receipts Herkos emits. The private key never leaves the machine.
	priv, err := keys.LoadOrCreate(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "serve: key: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "herkos serve: signing key %s\n", keys.PublicHex(priv))
	fmt.Fprintf(stderr, "herkos serve: allowed tools %v; upstream %v\n", []string(allow), upstream)

	// Opt-in: arm the dual-use content gate when a served set is pinned. Without
	// --served-span the gate stays inert and serve enforces the tool-name allowlist only.
	cfg := serve.Config{AllowedTools: allow}
	if len(servedSpans) > 0 {
		if *indexPath == "" {
			fmt.Fprintln(stderr, "serve: --served-span needs --index (the gate fingerprints repo content from the index)")
			return 2
		}
		binding, lex, unreadable, err := buildContentGate(*indexPath, *root, servedSpans)
		if err != nil {
			fmt.Fprintf(stderr, "serve: content gate: %v\n", err)
			return 1
		}
		cfg.ServedBinding = binding
		cfg.Lexicon = lex
		fmt.Fprintf(stderr, "herkos serve: content gate armed - %d served span(s), %d repo line(s) fingerprinted",
			len(servedSpans), lex.Size())
		if unreadable > 0 {
			fmt.Fprintf(stderr, ", %d indexed file(s) unreadable (not gated)", unreadable)
		}
		fmt.Fprintln(stderr, " [userspace tripwire, not airtight]")
	}

	// Opt-in audit log: a signed, hash-chained, fail-closed record of every brokered tool
	// call, in a fresh per-session file. Sealed (and its tip announced) on shutdown so the
	// user can anchor it and later detect truncation.
	if *receiptsDir != "" {
		if err := os.MkdirAll(*receiptsDir, 0o700); err != nil {
			fmt.Fprintf(stderr, "serve: receipts dir: %v\n", err)
			return 1
		}
		logPath := filepath.Join(*receiptsDir, fmt.Sprintf("%d.jsonl", time.Now().UnixNano()))
		chain, err := receiptlog.Open(logPath, priv)
		if err != nil {
			fmt.Fprintf(stderr, "serve: audit log: %v\n", err)
			return 1
		}
		cfg.Recorder = chain
		fmt.Fprintf(stderr, "herkos serve: audit log -> %s\n", logPath)
		defer func() {
			_ = chain.Close()
			fmt.Fprintf(stderr, "herkos serve: audit sealed - session %s, %d call(s), tip %s\n",
				chain.Session(), chain.Calls(), chain.Tip())
		}()
	}

	// Cancel on SIGINT/SIGTERM. exec.CommandContext then kills the child on cancel, closing
	// its stdout and unblocking the upstream->agent pump.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, upstream[0], upstream[1:]...)
	cmd.Stderr = stderr // surface the upstream server's own logs
	if *isolate {
		if err := applyIsolation(cmd); err != nil {
			fmt.Fprintf(stderr, "serve: %v\n", err)
			return 2
		}
		fmt.Fprintln(stderr, "herkos serve: upstream isolated - no network of its own [Linux netns]")
	}
	upW, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(stderr, "serve: upstream stdin: %v\n", err)
		return 1
	}
	upR, err := cmd.StdoutPipe()
	if err != nil {
		_ = upW.Close() // cmd.Start never runs to own this pipe's cleanup
		fmt.Fprintf(stderr, "serve: upstream stdout: %v\n", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "serve: start upstream: %v\n", err)
		return 1
	}
	// If the upstream exits on its own, cancel so serve stops too.
	go func() { _ = cmd.Wait(); cancel() }()

	runDone := make(chan error, 1)
	agent := agentEOFReader{r: stdin, cancel: cancel}
	go func() { runDone <- serve.Run(ctx, cfg, agent, stdout, upR, upW) }()

	// Stop on the first of: both directions closing (clean), the upstream exiting, or a
	// signal. On the cancel path, give the broker a bounded moment to unwind (the killed
	// child closes its stdout, so the upstream->agent pump sees EOF and returns) so we do
	// not return while a pump is still writing. A pump left blocked on an uncancellable
	// stdin read is reclaimed at process exit rather than waited on.
	var runErr error
	select {
	case runErr = <-runDone:
	case <-ctx.Done():
		select {
		case runErr = <-runDone:
		case <-time.After(2 * time.Second):
		}
	}
	if runErr != nil {
		fmt.Fprintf(stderr, "serve: %v\n", runErr)
		return 1
	}
	return 0
}
