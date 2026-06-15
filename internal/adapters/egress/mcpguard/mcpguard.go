// Package mcpguard enforces a deny-by-default tool allowlist over MCP JSON-RPC. It is
// the broker's egress Guard for the agent-to-upstream direction: a tools/call to a tool
// that is not on the allowlist is blocked and answered with a JSON-RPC error, and anything
// unparseable (including a JSON-RPC batch array) fails closed.
//
// Scope, stated plainly so nothing is inferred as safe that isn't: ONLY the tools/call
// method is gated, and only by its tool NAME. Every other method - resources/read,
// resources/list, prompts/get, and all MCP control/handshake traffic - passes through
// UNGUARDED in v1, and the tool's parameters are never inspected. So an allowed tool can
// still carry arbitrary data in its arguments, and a resources/read reaches the upstream
// unfiltered. This is the v1 (server, tool-name) allowlist model: decidable and honest.
// It does NOT tie an outbound payload's bytes to the served span set - that boundary is
// core.Binding.AuthorizePayload via a separate EgressPort, not wired into the broker here.
package mcpguard

import (
	"encoding/json"
	"fmt"
	"strings"
)

// denyCode is the JSON-RPC error code returned for a policy denial. -32000 sits in the
// JSON-RPC reserved "server error" range, which MCP uses for application-level errors.
const denyCode = -32000

// Guard authorizes outbound MCP messages against a fixed set of allowed tool names.
// The zero value denies every tools/call; use New.
type Guard struct {
	allowed map[string]struct{}
}

// New returns a Guard that allows exactly the named tools. With no names every tools/call
// is denied (deny-by-default). Empty names are dropped so a blank config line cannot widen
// the allowlist; an empty tool name is denied unconditionally in Check regardless.
func New(tools ...string) *Guard {
	m := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		if t == "" {
			continue
		}
		m[t] = struct{}{}
	}
	return &Guard{allowed: m}
}

// Check implements the broker's Guard contract. It returns (true, nil) to forward the
// message, or (false, reply) to block it and have the broker answer the agent with reply.
//
// The tool-call method is matched case-insensitively and trimmed, so the guard - not the
// upstream's case handling - owns the deny decision and a "Tools/Call" variant cannot slip
// past as control traffic. Any well-formed non-tool-call method (initialize, tools/list,
// ping, notifications, resources/*, prompts/*, ...) is allowed by design - that is the
// larger pass-through surface, wider than just the parse-failure path. A message that does
// not parse as a JSON-RPC object (including a JSON-RPC batch array) fails closed, and an
// empty tool name is denied unconditionally.
func (g *Guard) Check(msg []byte) (bool, []byte) {
	var req struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return false, denyReply(nil, "herkos: egress denied: unparseable JSON-RPC")
	}
	if !strings.EqualFold(strings.TrimSpace(req.Method), "tools/call") {
		return true, nil
	}
	if req.Params.Name == "" {
		return false, denyReply(req.ID, "herkos: egress denied: empty tool name")
	}
	if _, ok := g.allowed[req.Params.Name]; ok {
		return true, nil
	}
	return false, denyReply(req.ID, fmt.Sprintf("herkos: egress denied by policy: tool %q not in allowlist", req.Params.Name))
}

// denyReply builds a JSON-RPC error response echoing id verbatim (or null when the
// request had no id, e.g. a notification or an unparseable frame). It marshals through
// typed structs so the message is escaped and the result is always valid JSON.
func denyReply(id json.RawMessage, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	type rpcResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcErr          `json:"error"`
	}
	b, err := json.Marshal(rpcResp{JSONRPC: "2.0", ID: id, Error: rpcErr{Code: denyCode, Message: message}})
	if err != nil {
		// Unreachable for these types; fall back to a static, valid error frame.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"herkos: egress denied"}}`)
	}
	return b
}
