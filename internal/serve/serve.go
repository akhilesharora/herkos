// Package serve is Herkos's production data path: it wires the in-path egress broker
// between an agent and an upstream MCP server over byte streams. The agent's MCP client
// talks to Herkos over (agentR, agentW); Herkos proxies to the upstream server over
// (upR, upW), enforcing a deny-by-default tool allowlist on the agent-to-upstream
// direction while passing upstream-to-agent traffic verbatim.
//
// Run is transport-agnostic - the CLI points the agent streams at os.Stdin/os.Stdout and
// the upstream streams at a child process's stdout/stdin, while tests use in-memory pipes.
package serve

import (
	"context"
	"io"

	"github.com/akhilesharora/herkos/internal/adapters/egress/mcpguard"
	"github.com/akhilesharora/herkos/internal/adapters/egress/spanguard"
	"github.com/akhilesharora/herkos/internal/adapters/egress/toolfilter"
	"github.com/akhilesharora/herkos/internal/adapters/transport/mcpstdio"
	"github.com/akhilesharora/herkos/internal/broker"
	"github.com/akhilesharora/herkos/internal/core"
)

// Config is the serve-time policy. The zero value (no allowed tools) denies every
// tools/call - deny-by-default.
type Config struct {
	// AllowedTools is the set of MCP tool names the agent may call on the upstream server.
	AllowedTools []string

	// ServedBinding and Lexicon arm the content-aware egress gate (SpanGate's dual-use
	// invariant, live on the wire): a tools/call argument carrying a verbatim repo line
	// whose every containing span is outside ServedBinding is blocked. The gate is opt-in
	// and inert unless Lexicon is non-nil and non-empty, so the default path (tool-name
	// allowlist only) is unchanged. It is a userspace tripwire on verbatim content, not an
	// airtight boundary - see internal/adapters/egress/spanguard.
	ServedBinding core.Binding
	Lexicon       *spanguard.Lexicon

	// Recorder, if set, is the audit sink: the broker hands it every tools/call with the
	// allow/deny decision, and fails closed if a receipt cannot be written. Opt-in (nil = no
	// audit log). The CLI passes a receiptlog.Chain here.
	Recorder broker.Recorder
}

// guard composes the egress guards in order: the tool-name allowlist (mcpguard) first,
// then the content gate (spanguard). A message is forwarded only if every guard allows it;
// the first to deny answers the agent. This keeps each guard single-responsibility while
// the broker still sees one Guard.
type guard struct {
	guards []broker.Guard
}

func (g guard) Check(msg []byte) (bool, []byte) {
	for _, gg := range g.guards {
		if allow, reply := gg.Check(msg); !allow {
			return false, reply
		}
	}
	return true, nil
}

// Run brokers between the agent streams and the upstream streams until ctx is cancelled or
// either side closes its stream. Agent-to-upstream tools/call traffic must pass the tool
// allowlist (and, when armed, the content gate); everything upstream-to-agent is forwarded
// verbatim. Run does not close any of the streams - the caller owns their lifecycle.
func Run(ctx context.Context, cfg Config, agentR io.Reader, agentW io.Writer, upR io.Reader, upW io.Writer) error {
	agent := mcpstdio.NewTransport(agentR, agentW)
	upstream := mcpstdio.NewTransport(upR, upW)
	g := guard{guards: []broker.Guard{mcpguard.New(cfg.AllowedTools...)}}
	if cfg.Lexicon != nil && cfg.Lexicon.Size() > 0 {
		g.guards = append(g.guards, spanguard.New(cfg.ServedBinding, cfg.Lexicon))
	}
	b := broker.NewGuarded(agent, upstream, g)
	// Trim the agent's view of tools/list to the allowlist so it never loads the schema of a
	// tool it could not call, cutting tool-catalog tokens at session start. Only when a tool
	// allowlist is set; deny-all (no AllowedTools) leaves the list untouched.
	if len(cfg.AllowedTools) > 0 {
		b.SetResponseFilter(toolfilter.New(cfg.AllowedTools...))
	}
	if cfg.Recorder != nil {
		b.SetRecorder(cfg.Recorder)
	}
	return b.Run(ctx)
}
