// Package scan inspects an MCP (Model Context Protocol) configuration and emits a shareable
// security receipt. It accepts two shapes:
//
//   - a launch config, {"mcpServers": {name: {command, args, ...}}} (or a top-level "servers"
//     object of the same shape; e.g. Claude Code, Cursor, VS Code). On these it flags local
//     stdio servers launched directly (not through the Herkos broker), unpinned npx
//     auto-installs, and HTTP/SSE remotes the in-path stdio broker cannot mediate.
//   - a security manifest, {"servers": [{name, tools, allowsUnrestrictedEgress}]}, with
//     declared tool metadata. On these it flags over-scoped servers, poisoned tool
//     descriptions (against a trusted baseline), and unrestricted egress.
//
// Scan itself performs no I/O and is fully deterministic: the same Config and baseline always
// produce the same Report and the same String() output.
package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OverScopedLimit is the maximum number of tools a server may expose before it is flagged as
// over-scoped. A server with strictly more tools than this is a finding.
const OverScopedLimit = 40

// Tool is a single MCP tool exposed by a server: a name and its human/agent-facing
// description. The description is the field an attacker mutates to smuggle instructions.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Server is one MCP server. A security manifest populates Name, Tools, and
// AllowsUnrestrictedEgress. A real launch config populates Name (the map key), Command, and
// Args, and sets fromLaunch so the launch-config checks apply.
type Server struct {
	Name                     string   `json:"name"`
	Tools                    []Tool   `json:"tools"`
	AllowsUnrestrictedEgress bool     `json:"allowsUnrestrictedEgress"`
	Command                  string   `json:"-"`
	Args                     []string `json:"-"`
	Type                     string   `json:"-"`
	URL                      string   `json:"-"`
	fromLaunch               bool
}

// isRemote reports whether a launch entry is an HTTP/SSE remote: it is reached over a URL with
// no local command, so the in-path stdio broker cannot mediate it.
func (s Server) isRemote() bool {
	t := strings.ToLower(s.Type)
	return t == "http" || t == "sse" || (s.Command == "" && s.URL != "")
}

// transport names the remote transport for a finding message, defaulting to http.
func (s Server) transport() string {
	if t := strings.ToLower(s.Type); t != "" {
		return t
	}
	return "http"
}

// Config is a set of servers to inspect.
type Config struct {
	Servers []Server `json:"servers"`
}

// Kind classifies a [Finding].
type Kind int

const (
	// OverScoped marks a server that exposes more than [OverScopedLimit] tools.
	OverScoped Kind = iota
	// Poisoned marks a tool whose description differs from the trusted baseline.
	Poisoned
	// UnrestrictedEgress marks a server permitted to reach arbitrary destinations.
	UnrestrictedEgress
	// Unbrokered marks a launch-config server that runs directly, not through the broker, so
	// the agent can call any tool it exposes with no allowlist in between.
	Unbrokered
	// UnpinnedInstall marks a server launched via `npx` with an unpinned package, which
	// auto-fetches whatever was published last (the malicious-update / rug-pull vector).
	UnpinnedInstall
	// Remote marks a launch-config server reached over HTTP/SSE at an external URL. The in-path
	// stdio broker cannot mediate it, so the exposure is the remote endpoint itself,
	// not the absence of tool brokering.
	Remote
)

// String returns a short stable label for a Kind, used in scan output.
func (k Kind) String() string {
	switch k {
	case OverScoped:
		return "over-scoped"
	case Poisoned:
		return "poisoned"
	case UnrestrictedEgress:
		return "unrestricted-egress"
	case Unbrokered:
		return "unbrokered"
	case UnpinnedInstall:
		return "unpinned-install"
	case Remote:
		return "remote"
	default:
		return "unknown"
	}
}

// Finding is a single flagged issue. Server is always set; Tool is set only for [Poisoned]
// findings. Detail carries a short human-readable explanation.
type Finding struct {
	Kind   Kind
	Server string
	Tool   string
	Detail string
}

// Report is the deterministic result of a [Scan]. Findings are sorted, so the same inputs
// always yield byte-identical output from [Report.String].
type Report struct {
	Findings []Finding
}

// Scan inspects cfg against an optional baseline and returns a deterministic Report.
func Scan(cfg Config, baseline map[string]string) Report {
	var findings []Finding

	for _, srv := range cfg.Servers {
		if len(srv.Tools) > OverScopedLimit {
			findings = append(findings, Finding{OverScoped, srv.Name, "", fmt.Sprintf("%d tools exceeds limit of %d", len(srv.Tools), OverScopedLimit)})
		}
		if srv.AllowsUnrestrictedEgress {
			findings = append(findings, Finding{UnrestrictedEgress, srv.Name, "", "server allows unrestricted egress"})
		}

		if srv.fromLaunch {
			if srv.isRemote() {
				findings = append(findings, Finding{Remote, srv.Name, "", fmt.Sprintf("remote %s server at an external URL; the in-path stdio broker cannot mediate it, so the exposure is what that endpoint can reach", srv.transport())})
			} else {
				if !brokered(srv.Command) {
					findings = append(findings, Finding{Unbrokered, srv.Name, "", "launched directly, not through the herkos broker; the agent can call any tool it exposes"})
				}
				if unpinnedNpx(srv.Command, srv.Args) {
					findings = append(findings, Finding{UnpinnedInstall, srv.Name, "", "npx installs an unpinned package; a malicious update runs the next time the agent starts"})
				}
			}
		}

		if len(baseline) == 0 {
			continue
		}
		for _, tool := range srv.Tools {
			want, ok := baseline[srv.Name+"/"+tool.Name]
			if !ok {
				continue
			}
			if tool.Description != want {
				findings = append(findings, Finding{Poisoned, srv.Name, tool.Name, "tool description differs from baseline"})
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		return a.Tool < b.Tool
	})

	return Report{Findings: findings}
}

// brokered reports whether a launch command runs the Herkos broker (bare "herkos" or an
// absolute path to it).
func brokered(command string) bool {
	return command != "" && filepath.Base(command) == "herkos"
}

// unpinnedNpx reports whether a launch is `npx [flags] <package>` with no pinned @version.
// A scoped name (@scope/name) without a trailing @version is unpinned; @scope/name@1.2.3 and
// name@1.2.3 are pinned.
func unpinnedNpx(command string, args []string) bool {
	if filepath.Base(command) != "npx" {
		return false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // skip flags like -y / --yes
		}
		body := strings.TrimPrefix(a, "@") // drop a leading scope marker
		return !strings.Contains(body, "@")
	}
	return false
}

// count returns the number of findings of the given kind.
func (r Report) count(k Kind) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == k {
			n++
		}
	}
	return n
}

// String renders the report as a single shareable line. The counts never exceed what was
// actually found, and the output is deterministic for a given Report.
func (r Report) String() string {
	return fmt.Sprintf(
		"herkos scan: %d over-scoped, %d poisoned, %d unrestricted-egress, %d unbrokered, %d unpinned-install, %d remote - your code never left this machine",
		r.count(OverScoped), r.count(Poisoned), r.count(UnrestrictedEgress), r.count(Unbrokered), r.count(UnpinnedInstall), r.count(Remote),
	)
}

// LoadConfig reads and parses an MCP configuration from a JSON file at path. It accepts both
// the real launch config ({"mcpServers":{...}}) and the security manifest ({"servers":[...]});
// a launch config takes precedence if both keys are present.
//
// Some configs (e.g. ~/.claude.json) keep servers in two places: a top-level "mcpServers" and a
// per-project "projects"[path]."mcpServers". Both are scanned, so a project-scoped server is
// never silently skipped; project-scoped servers are labelled "<project>/<name>" so they stay
// distinct from a top-level server of the same name.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("scan: read config: %w", err)
	}
	var probe struct {
		Servers    json.RawMessage `json:"servers"`
		MCPServers json.RawMessage `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Config{}, fmt.Errorf("scan: parse config: %w", err)
	}
	projectServers := false
	for _, p := range probe.Projects {
		if len(p.MCPServers) > 0 {
			projectServers = true
			break
		}
	}
	if len(probe.MCPServers) > 0 || projectServers {
		cfg := Config{}
		top, err := parseServers(probe.MCPServers, "")
		if err != nil {
			return Config{}, err
		}
		cfg.Servers = append(cfg.Servers, top...)
		paths := make([]string, 0, len(probe.Projects))
		for p := range probe.Projects {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			servers, err := parseServers(probe.Projects[p].MCPServers, filepath.Base(p))
			if err != nil {
				return Config{}, err
			}
			cfg.Servers = append(cfg.Servers, servers...)
		}
		return cfg, nil
	}
	// Some configs put the same launch config under a "servers" OBJECT (note the key) instead of
	// "mcpServers". A "servers" object is a launch config; a "servers" array is the security
	// manifest handled below.
	if isJSONObject(probe.Servers) {
		servers, err := parseServers(probe.Servers, "")
		if err != nil {
			return Config{}, err
		}
		return Config{Servers: servers}, nil
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("scan: parse config: %w", err)
	}
	return cfg, nil
}

// isJSONObject reports whether raw is a JSON object (starts with '{'), distinguishing a
// "servers" launch-config object from a security-manifest "servers" array.
func isJSONObject(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b == '{'
	}
	return false
}

// parseServers parses a {"name":{command,args,type,url}} mcpServers block into Servers in a
// deterministic (name-sorted) order. A non-empty scope (the owning project) is prefixed as
// "<scope>/<name>"; an empty raw block yields no servers.
func parseServers(raw json.RawMessage, scope string) ([]Server, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
		Type    string   `json:"type"`
		URL     string   `json:"url"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("scan: parse mcpServers: %w", err)
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Server, 0, len(names))
	for _, name := range names {
		display := name
		if scope != "" {
			display = scope + "/" + name
		}
		out = append(out, Server{Name: display, Command: m[name].Command, Args: m[name].Args, Type: m[name].Type, URL: m[name].URL, fromLaunch: true})
	}
	return out, nil
}
