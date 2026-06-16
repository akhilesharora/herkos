// Package demo runs a deterministic SpanGate walkthrough that shows the dual-use binding in
// action: ONE binding plays three roles - it is the model's context, it is the deny-by-default
// egress allowlist, and its spans are the leaves of an offline-verifiable receipt. It composes
// the real adapters the product uses. See DUAL-USE-BINDING.md.
package demo

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"sort"

	"github.com/akhilesharora/herkos/internal/adapters/egress/userspace"
	"github.com/akhilesharora/herkos/internal/adapters/graph/mockgraph"
	"github.com/akhilesharora/herkos/internal/adapters/pool"
	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/core/spanselect"
	"github.com/akhilesharora/herkos/internal/spangate"
)

// fileLines is the whole-file size of each fixture file (the file-dump baseline).
var fileLines = map[string]int{"auth.go": 200, "db.go": 300, "util.go": 500}

// Run executes the demo and writes a human-readable, deterministic walkthrough to w.
func Run(w io.Writer) error {
	ctx := context.Background()
	g := mockgraph.New([]spanselect.Node{
		{Symbol: "Authenticate", Span: core.Span{File: "auth.go", StartLine: 10, EndLine: 30}, Edges: []int{1}},
		{Symbol: "Query", Span: core.Span{File: "db.go", StartLine: 5, EndLine: 25}, Edges: []int{0}},
		{Symbol: "Helper", Span: core.Span{File: "util.go", StartLine: 100, EndLine: 110}},
	})
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	otherPub, _, err := ed25519.GenerateKey(nil) // a third party's key, to show a wrong key fails
	if err != nil {
		return err
	}

	pl := spangate.New(g, pool.New(), priv, userspace.EnforcementLabel)
	read := func(s core.Span) []byte { return []byte(fmt.Sprintf("// %s\n", s.String())) }

	// Serve produces the single Binding (context) and the signed receipt from one computation.
	binding, rcpt, err := pl.Serve(ctx, core.Query{Anchors: []string{"Authenticate"}, LineBudget: 100}, read)
	if err != nil {
		return err
	}

	spans := binding.SpanSet().Spans()
	sort.Slice(spans, func(i, j int) bool { return spans[i].String() < spans[j].String() })

	// Role 1 metric: served lines vs a whole-file dump of the files we touched.
	served := binding.SpanSet().TotalLines()
	touched := map[string]bool{}
	for _, s := range spans {
		touched[s.File] = true
	}
	files := make([]string, 0, len(touched))
	baseline := 0
	for f := range touched {
		files = append(files, f)
		baseline += fileLines[f]
	}
	sort.Strings(files)
	savedPct := 0
	if baseline > 0 {
		savedPct = 100 * (baseline - served) / baseline
	}

	// Role 2: the SAME binding authorizes egress. An in-set payload is allowed; an out-of-set
	// exfil of code that was never served is denied.
	eg := userspace.New()
	inSet := core.EgressRequest{
		Server:      "upstream",
		Payload:     []byte("derived from auth.go"),
		SourceSpans: []core.Span{{File: "auth.go", StartLine: 12, EndLine: 18}}, // inside auth.go:10-30
	}
	allowed := eg.Authorize(ctx, binding, inSet).Allowed()
	leak := core.EgressRequest{
		Server:      "evil-mcp",
		Payload:     make([]byte, 256),
		SourceSpans: []core.Span{{File: "util.go", StartLine: 100, EndLine: 110}}, // never served
	}
	blocked := 0
	if !eg.Authorize(ctx, binding, leak).Allowed() {
		blocked = len(leak.Payload)
	}

	// Role 3: the receipt verifies offline under the signer's key and fails under any other.
	good := "FAILED"
	if rcpt.Verify(pub) == nil {
		good = "VERIFIED"
	}
	bad := "VERIFIED (BUG)"
	if rcpt.Verify(otherPub) != nil {
		bad = "FAILED (signature invalid)"
	}

	fmt.Fprintln(w, "Herkos SpanGate demo - one binding, three roles  (see docs/DUAL-USE-BINDING.md)")
	fmt.Fprintln(w, `  query: anchor "Authenticate", line budget 100`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[1] CONTEXT  - the local code graph selected a minimal span set:")
	for _, s := range spans {
		fmt.Fprintf(w, "        %s\n", s.String())
	}
	fmt.Fprintf(w, "      served %d / %d lines across %d files  ->  %d%% fewer tokens than a whole-file dump\n", served, baseline, len(files), savedPct)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[2] EGRESS   - the SAME span set is the deny-by-default allowlist:")
	fmt.Fprintf(w, "        allow  auth.go:12-18    (inside the served set)   -> %v\n", allowed)
	fmt.Fprintf(w, "        deny   util.go:100-110  (never served)            -> blocked %d bytes  [enforcement=%s]\n", blocked, eg.Enforcement())
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[3] RECEIPT  - the served spans are the leaves of an offline-verifiable receipt:")
	fmt.Fprintf(w, "        root %s\n", rcpt.Root)
	fmt.Fprintf(w, "        verify with the signer's public key  -> %s\n", good)
	fmt.Fprintf(w, "        verify with a different key          -> %s\n", bad)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  One object served the context, bounded the egress, and signed the manifest.")
	fmt.Fprintln(w, "  That is the dual-use binding. Honest limits are in DUAL-USE-BINDING.md.")
	return nil
}
