// Package register adds and removes Herkos's broker entry in a Claude Code
// style MCP configuration file.
//
// The config is JSON whose top-level "mcpServers" object maps a server name to
// a launch spec of the form {"command": ..., "args": [...]}. Registering Herkos
// means inserting mcpServers["herkos"] = {"command":"herkos","args":["serve", ...]}
// (the caller's serve arguments follow "serve") so an agent host launches the
// Herkos broker as one of its MCP servers.
//
// The file is treated as an opaque JSON object: it is unmarshalled into a
// generic map, only the mcpServers sub-map is touched, and everything else
// (unknown top-level keys, other servers, formatting-independent content) is
// preserved on round-trip. Both [Register] and [Unregister] are idempotent, and
// [Register] writes a ".bak" copy of the prior file before overwriting it.
package register

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
)

// serverName is the key under mcpServers that identifies Herkos's broker.
const serverName = "herkos"

// mcpServersKey is the top-level field holding the name -> launch-spec map.
const mcpServersKey = "mcpServers"

// backupSuffix is appended to the config path to name the pre-write backup.
const backupSuffix = ".bak"

// configPerm is the mode used when creating a config or backup file that does
// not already exist.
const configPerm fs.FileMode = 0o600

// herkosEntry returns the launch spec written under mcpServers["herkos"]: the herkos
// command running `serve` followed by the caller's serve arguments (allowlist, upstream).
// It is rebuilt on each call so callers cannot alias and mutate a shared map.
func herkosEntry(serveArgs []string) map[string]any {
	args := make([]any, 0, len(serveArgs)+1)
	args = append(args, "serve")
	for _, a := range serveArgs {
		args = append(args, a)
	}
	return map[string]any{
		"command": serverName,
		"args":    args,
	}
}

// Register idempotently adds mcpServers["herkos"] = {"command":"herkos",
// "args":["serve", serveArgs...]} to the config at configPath, creating the file and the
// mcpServers map if they are absent. Unrelated servers and unknown top-level fields are
// preserved. Before writing, the prior file contents are copied to configPath+".bak";
// registering an already-registered config with the same serveArgs reproduces the same
// bytes. A missing config file is treated as an empty object, not an error.
func Register(configPath string, serveArgs []string) error {
	root, err := load(configPath)
	if err != nil {
		return err
	}

	servers, key, err := serversMap(root)
	if err != nil {
		return err
	}
	servers[serverName] = herkosEntry(serveArgs)
	root[key] = servers

	return save(configPath, root)
}

// Wrap rewrites mcpServers[name] in place so the agent launches that upstream THROUGH the
// Herkos broker instead of directly: the existing entry's command and args become the
// upstream of `herkos serve --allow-tool ... -- <command> <args>`, written back under the
// SAME key. Unlike [Register], it leaves no direct, un-brokered path to the upstream, which
// is what a real deployment needs - an agent that can still reach the upstream directly is
// not gated at all. Wrap is idempotent: wrapping an already-wrapped entry re-reads the inner
// upstream and re-applies the allowlist rather than nesting brokers. An absent or non-object
// server entry is an error.
func Wrap(configPath, name string, allow []string) error {
	root, err := load(configPath)
	if err != nil {
		return err
	}
	servers, key, err := serversMap(root)
	if err != nil {
		return err
	}
	raw, ok := servers[name]
	if !ok || raw == nil {
		return fmt.Errorf("register: server %q not found in %s", name, configPath)
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("register: server %q is %T, want an object", name, raw)
	}
	wrapped, err := wrapEntry(entry, allow)
	if err != nil {
		return err
	}
	servers[name] = wrapped
	root[key] = servers
	return save(configPath, root)
}

// wrapEntry rewrites one server entry so its upstream runs through `herkos serve` with the
// given allowlist. It unwraps a prior herkos wrap first (so re-wrapping is idempotent) and
// preserves any extra fields (e.g. "env") - the herkos process inherits them and the child
// upstream inherits from herkos, so dropping them would break a server that needs its
// environment.
func wrapEntry(entry map[string]any, allow []string) (map[string]any, error) {
	cmd, cmdArgs, err := upstreamOf(entry)
	if err != nil {
		return nil, err
	}
	serveArgs := make([]string, 0, len(allow)*2+2+len(cmdArgs))
	for _, t := range allow {
		serveArgs = append(serveArgs, "--allow-tool", t)
	}
	serveArgs = append(serveArgs, "--", cmd)
	serveArgs = append(serveArgs, cmdArgs...)
	wrapped := herkosEntry(serveArgs)
	for k, v := range entry {
		if k == "command" || k == "args" {
			continue
		}
		wrapped[k] = v
	}
	return wrapped, nil
}

// Discoverer returns the tool names a server currently exposes. [WrapAll] uses it to pin each
// wrapped server's allowlist to the tools present today, so a tool added later (the backdoored-
// update vector) is denied by default rather than silently callable.
type Discoverer func(command string, args []string) ([]string, error)

// WrapResult records what [WrapAll] did with one server: it was Wrapped (with the Tools that
// were pinned as its allowlist), or it was left alone for the reason in Skip.
type WrapResult struct {
	Name    string
	Wrapped bool
	Tools   []string
	Skip    string
}

// WrapAll brokers every local stdio server in the config in place, pinning each to the tools it
// currently exposes (discovered via discover). It deliberately leaves some servers alone, each
// with a reason in WrapResult.Skip: a remote server (a URL with no local command - an stdio
// broker cannot sit in front of it), an already-brokered server, and any server whose tools
// cannot be discovered (wrapping it with an empty allowlist would deny every tool and break it).
// The config is written once, and only if at least one server was wrapped, so a run that wraps
// nothing leaves the file (and its backup) untouched.
func WrapAll(configPath string, discover Discoverer) ([]WrapResult, error) {
	root, err := load(configPath)
	if err != nil {
		return nil, err
	}
	servers, key, err := serversMap(root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]WrapResult, 0, len(names))
	wrappedAny := false
	for _, name := range names {
		entry, ok := servers[name].(map[string]any)
		if !ok {
			results = append(results, WrapResult{Name: name, Skip: "entry is not an object"})
			continue
		}
		if isHerkosWrapped(entry) {
			results = append(results, WrapResult{Name: name, Skip: "already brokered"})
			continue
		}
		if cmd, _ := entry["command"].(string); cmd == "" {
			results = append(results, WrapResult{Name: name, Skip: "remote server (a URL, no local command); the stdio broker cannot mediate it"})
			continue
		}
		cmd, args, err := upstreamOf(entry)
		if err != nil {
			results = append(results, WrapResult{Name: name, Skip: err.Error()})
			continue
		}
		tools, err := discover(cmd, args)
		if err != nil {
			results = append(results, WrapResult{Name: name, Skip: "could not discover tools: " + err.Error()})
			continue
		}
		if len(tools) == 0 {
			results = append(results, WrapResult{Name: name, Skip: "server advertised no tools"})
			continue
		}
		wrapped, err := wrapEntry(entry, tools)
		if err != nil {
			results = append(results, WrapResult{Name: name, Skip: err.Error()})
			continue
		}
		servers[name] = wrapped
		wrappedAny = true
		results = append(results, WrapResult{Name: name, Wrapped: true, Tools: tools})
	}
	if wrappedAny {
		root[key] = servers
		if err := save(configPath, root); err != nil {
			return results, err
		}
	}
	return results, nil
}

// isHerkosWrapped reports whether a server entry is one Herkos produced: command "herkos"
// whose first arg is "serve".
func isHerkosWrapped(entry map[string]any) bool {
	if cmd, _ := entry["command"].(string); cmd != serverName {
		return false
	}
	args, _ := entry["args"].([]any)
	return len(args) > 0 && args[0] == "serve"
}

// upstreamOf returns the real upstream command and args for a server entry, unwrapping a
// prior Herkos wrapping so re-wrapping stays idempotent. A Herkos-wrapped entry has
// command=="herkos" and args==["serve", ...flags, "--", <cmd>, <args>...]; its real upstream
// is everything after the "--". Any other entry is returned as-is.
func upstreamOf(entry map[string]any) (cmd string, args []string, err error) {
	cmdRaw, _ := entry["command"].(string)
	if cmdRaw == "" {
		return "", nil, fmt.Errorf("register: server entry has no string %q", "command")
	}
	rawArgs, _ := entry["args"].([]any)
	strArgs := make([]string, 0, len(rawArgs))
	for _, a := range rawArgs {
		s, ok := a.(string)
		if !ok {
			return "", nil, fmt.Errorf("register: server entry %q must be strings, got %T", "args", a)
		}
		strArgs = append(strArgs, s)
	}
	// Already wrapped by Herkos: unwrap to the inner upstream after "--".
	if cmdRaw == serverName && len(strArgs) > 0 && strArgs[0] == "serve" {
		for i, a := range strArgs {
			if a == "--" {
				inner := strArgs[i+1:]
				if len(inner) == 0 {
					return "", nil, fmt.Errorf("register: wrapped entry has no upstream after %q", "--")
				}
				return inner[0], inner[1:], nil
			}
		}
		return "", nil, fmt.Errorf("register: wrapped entry has no %q separator", "--")
	}
	return cmdRaw, strArgs, nil
}

// Unregister idempotently removes mcpServers["herkos"] from the config at
// configPath. A missing herkos entry, a missing mcpServers map, or a missing
// config file are all no-ops rather than errors. As with [Register], the prior
// file is backed up to configPath+".bak" before the rewrite, and unrelated
// servers and unknown top-level fields are preserved.
func Unregister(configPath string) error {
	root, err := load(configPath)
	if err != nil {
		return err
	}

	servers, key, err := serversMap(root)
	if err != nil {
		return err
	}
	delete(servers, serverName) // remove a standalone broker entry (add-mode)

	// Restore any in-place wrapped server to its original upstream, so register --server /
	// unregister is a lossless round-trip ("restore the original launch line").
	for name, raw := range servers {
		entry, ok := raw.(map[string]any)
		if !ok || !isHerkosWrapped(entry) {
			continue
		}
		cmd, args, err := upstreamOf(entry)
		if err != nil {
			continue // malformed wrap: leave it rather than corrupt the config
		}
		restored := map[string]any{"command": cmd}
		if len(args) > 0 {
			anyArgs := make([]any, len(args))
			for i, a := range args {
				anyArgs[i] = a
			}
			restored["args"] = anyArgs
		}
		for k, v := range entry { // carry back preserved extras (e.g. "env")
			if k == "command" || k == "args" {
				continue
			}
			restored[k] = v
		}
		servers[name] = restored
	}
	root[key] = servers

	return save(configPath, root)
}

// load reads and parses configPath into a generic JSON object. A nonexistent
// file yields an empty object so callers can treat first-time registration the
// same as editing an existing config. The top-level JSON value must be an
// object; anything else is rejected.
func load(configPath string) (map[string]any, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}

	root := map[string]any{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configPath, err)
	}
	return root, nil
}

// serversMap returns the mutable server map from root and the top-level key it lives under:
// "mcpServers" (Claude Code, Cursor, Cline, Windsurf) or "servers" (VS Code, GitHub Copilot).
// It prefers mcpServers when both exist, falls back to a "servers" object, and defaults to
// mcpServers for a new or empty config so first-time registration writes the common key. A
// present-but-non-object value is an error rather than something to silently overwrite.
func serversMap(root map[string]any) (map[string]any, string, error) {
	key := mcpServersKey
	if _, ok := root[mcpServersKey]; !ok {
		if v, ok := root["servers"]; ok {
			if _, isObject := v.(map[string]any); isObject {
				key = "servers"
			}
		}
	}
	raw, ok := root[key]
	if !ok || raw == nil {
		return map[string]any{}, key, nil
	}
	servers, ok := raw.(map[string]any)
	if !ok {
		return nil, key, fmt.Errorf("config field %q is %T, want object", key, raw)
	}
	return servers, key, nil
}

// save backs up the current configPath (if any) to configPath+".bak" and then
// writes root as indented JSON. The backup captures the pre-write bytes so a
// caller can recover the previous config; on first-time creation there is
// nothing to back up and that step is skipped.
func save(configPath string, root map[string]any) error {
	if err := backup(configPath); err != nil {
		return err
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(configPath, out, configPerm); err != nil {
		return fmt.Errorf("write config %s: %w", configPath, err)
	}
	return nil
}

// backup copies the current contents of configPath to configPath+".bak". If
// configPath does not yet exist there is nothing to preserve and backup is a
// no-op; any other read error is reported.
func backup(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config %s for backup: %w", configPath, err)
	}

	bakPath := configPath + backupSuffix
	if err := os.WriteFile(bakPath, data, configPerm); err != nil {
		return fmt.Errorf("write backup %s: %w", bakPath, err)
	}
	return nil
}
