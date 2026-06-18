// Package toolfilter trims an MCP tools/list response down to a tool-name
// allowlist before it reaches the agent. The broker already blocks a disallowed
// tools/call; filtering the LIST as well means the agent never loads the schema
// of a tool it could not call anyway. That cuts the tokens every connected
// server spends on its tool catalog at session start, and removes disallowed
// tools from the agent's surface entirely.
//
// It is a token and surface optimization, not a security boundary: filtering is
// fail-open. Any message it cannot parse, or that carries no result.tools array,
// passes through byte-for-byte unchanged, because the deny-by-default egress
// guard - not this filter - is what actually blocks a call.
package toolfilter

import "encoding/json"

// Filter holds the allowed tool names. The zero value (no names) trims every
// tool out of a list; use New.
type Filter struct {
	allowed map[string]struct{}
}

// New returns a Filter that keeps exactly the named tools in a tools/list
// response. Empty names are dropped so a blank entry cannot widen the set.
func New(tools ...string) *Filter {
	m := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		if t != "" {
			m[t] = struct{}{}
		}
	}
	return &Filter{allowed: m}
}

// Filter returns msg with any result.tools array trimmed to the allowed set. A
// message that does not parse as a JSON-RPC response carrying a result.tools
// array is returned unchanged.
func (f *Filter) Filter(msg []byte) []byte {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(msg, &top); err != nil {
		return msg
	}
	resultRaw, ok := top["result"]
	if !ok {
		return msg
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return msg
	}
	toolsRaw, ok := result["tools"]
	if !ok {
		return msg
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return msg
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &named) == nil {
			if _, ok := f.allowed[named.Name]; ok {
				kept = append(kept, t)
			}
		}
	}
	newTools, err := json.Marshal(kept)
	if err != nil {
		return msg
	}
	result["tools"] = newTools
	newResult, err := json.Marshal(result)
	if err != nil {
		return msg
	}
	top["result"] = newResult
	out, err := json.Marshal(top)
	if err != nil {
		return msg
	}
	return out
}
