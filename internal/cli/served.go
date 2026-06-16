package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/akhilesharora/herkos/internal/adapters/egress/spanguard"
	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/index"
)

// parseSpanSpec parses a "FILE:START-END" served-span spec (end exclusive, exactly the form
// `herkos select` prints) into a core.Span. The range is split after the last colon so file
// paths are unrestricted; START-END is split on the first hyphen so the range bound parses
// even though paths may contain hyphens.
func parseSpanSpec(spec string) (core.Span, error) {
	spec = strings.TrimSpace(spec)
	i := strings.LastIndex(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return core.Span{}, fmt.Errorf("served-span %q: want FILE:START-END", spec)
	}
	file, rng := spec[:i], spec[i+1:]
	j := strings.Index(rng, "-")
	if j <= 0 || j == len(rng)-1 {
		return core.Span{}, fmt.Errorf("served-span %q: want FILE:START-END", spec)
	}
	start, err1 := strconv.Atoi(rng[:j])
	end, err2 := strconv.Atoi(rng[j+1:])
	if err1 != nil || err2 != nil {
		return core.Span{}, fmt.Errorf("served-span %q: start/end must be integers", spec)
	}
	s := core.Span{File: file, StartLine: start, EndLine: end}
	if !s.Valid() {
		return core.Span{}, fmt.Errorf("served-span %q: invalid range (need start>=1, end>start)", spec)
	}
	return s, nil
}

// buildContentGate arms the dual-use egress content gate: it loads the code-graph index,
// fingerprints EVERY indexed span's lines into a lexicon (so any repo line can be
// recognized), and builds the served Binding from the operator's span specs (so only those
// spans are authorized to leave). Files the index points at that can no longer be read are
// skipped - the gate can only fingerprint content it can see - and that count is returned
// so the caller can report it. specs must be non-empty; indexPath must exist.
func buildContentGate(indexPath, root string, specs []string) (b core.Binding, lex *spanguard.Lexicon, unreadable int, err error) {
	nodes, err := index.Load(indexPath)
	if err != nil {
		return core.Binding{}, nil, 0, err
	}
	lex = spanguard.NewLexicon(0)
	bodies := make(map[string]string)
	for _, n := range nodes {
		body, seen := bodies[n.Span.File]
		if !seen {
			raw, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(n.Span.File)))
			if rerr != nil {
				bodies[n.Span.File] = "" // mark unreadable so we count it once
				unreadable++
				continue
			}
			body = string(raw)
			bodies[n.Span.File] = body
		}
		if body == "" {
			continue
		}
		lex.AddSpan(n.Span, body)
	}

	spans := make([]core.Span, 0, len(specs))
	for _, spec := range specs {
		s, perr := parseSpanSpec(spec)
		if perr != nil {
			return core.Binding{}, nil, 0, perr
		}
		spans = append(spans, s)
	}
	ss, err := core.NewSpanSet(spans...)
	if err != nil {
		return core.Binding{}, nil, 0, err
	}
	return core.NewBinding(ss), lex, unreadable, nil
}
