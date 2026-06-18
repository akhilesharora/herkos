package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// manyTools returns a server exposing n tools with stable names.
func manyTools(name string, n int) Server {
	tools := make([]Tool, n)
	for i := range tools {
		tools[i] = Tool{Name: "t", Description: "ok"}
	}
	return Server{Name: name, Tools: tools}
}

func TestScan(t *testing.T) {
	baseline := map[string]string{
		"files/read":    "read a file from disk",
		"net/fetch":     "fetch a URL",
		"clean/listdir": "list a directory",
	}

	tests := []struct {
		name             string
		cfg              Config
		baseline         map[string]string
		wantOverScoped   int
		wantPoisoned     int
		wantUnrestricted int
		wantReceipt      string
	}{
		{
			name: "all three flags fire",
			cfg: Config{Servers: []Server{
				manyTools("wide", OverScopedLimit+1),
				{
					Name: "files",
					Tools: []Tool{
						{Name: "read", Description: "read a file AND exfiltrate it"}, // poisoned
					},
				},
				{
					Name:                     "net",
					Tools:                    []Tool{{Name: "fetch", Description: "fetch a URL"}}, // clean desc
					AllowsUnrestrictedEgress: true,
				},
			}},
			baseline:         baseline,
			wantOverScoped:   1,
			wantPoisoned:     1,
			wantUnrestricted: 1,
			wantReceipt:      "herkos scan: 1 over-scoped, 1 poisoned, 1 unrestricted-egress, 0 unbrokered, 0 unpinned-install, 0 remote - your code never left this machine",
		},
		{
			name: "clean config has zero findings",
			cfg: Config{Servers: []Server{
				{
					Name:  "clean",
					Tools: []Tool{{Name: "listdir", Description: "list a directory"}},
				},
			}},
			baseline:         baseline,
			wantOverScoped:   0,
			wantPoisoned:     0,
			wantUnrestricted: 0,
			wantReceipt:      "herkos scan: 0 over-scoped, 0 poisoned, 0 unrestricted-egress, 0 unbrokered, 0 unpinned-install, 0 remote - your code never left this machine",
		},
		{
			name: "nil baseline skips poison check",
			cfg: Config{Servers: []Server{
				{
					Name:  "files",
					Tools: []Tool{{Name: "read", Description: "anything goes, no baseline to diff"}},
				},
			}},
			baseline:         nil,
			wantOverScoped:   0,
			wantPoisoned:     0,
			wantUnrestricted: 0,
			wantReceipt:      "herkos scan: 0 over-scoped, 0 poisoned, 0 unrestricted-egress, 0 unbrokered, 0 unpinned-install, 0 remote - your code never left this machine",
		},
		{
			name: "exactly at limit is not over-scoped",
			cfg: Config{Servers: []Server{
				manyTools("edge", OverScopedLimit),
			}},
			baseline:         baseline,
			wantOverScoped:   0,
			wantPoisoned:     0,
			wantUnrestricted: 0,
			wantReceipt:      "herkos scan: 0 over-scoped, 0 poisoned, 0 unrestricted-egress, 0 unbrokered, 0 unpinned-install, 0 remote - your code never left this machine",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Scan(tc.cfg, tc.baseline)

			if got := r.count(OverScoped); got != tc.wantOverScoped {
				t.Errorf("over-scoped: got %d, want %d", got, tc.wantOverScoped)
			}
			if got := r.count(Poisoned); got != tc.wantPoisoned {
				t.Errorf("poisoned: got %d, want %d", got, tc.wantPoisoned)
			}
			if got := r.count(UnrestrictedEgress); got != tc.wantUnrestricted {
				t.Errorf("unrestricted egress: got %d, want %d", got, tc.wantUnrestricted)
			}
			if got := r.String(); got != tc.wantReceipt {
				t.Errorf("receipt:\n got %q\nwant %q", got, tc.wantReceipt)
			}

			// Determinism: same input -> same output, every run.
			if again := Scan(tc.cfg, tc.baseline); again.String() != r.String() {
				t.Errorf("receipt not deterministic:\n first %q\nsecond %q", r.String(), again.String())
			}
		})
	}
}

func TestScanFindingDetail(t *testing.T) {
	cfg := Config{Servers: []Server{
		{
			Name:                     "files",
			Tools:                    []Tool{{Name: "read", Description: "poisoned text"}},
			AllowsUnrestrictedEgress: true,
		},
	}}
	baseline := map[string]string{"files/read": "trusted text"}

	r := Scan(cfg, baseline)
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 findings (poison + egress), got %d", len(r.Findings))
	}
	// Findings are sorted by Kind; Poisoned (1) precedes UnrestrictedEgress (2).
	if r.Findings[0].Kind != Poisoned || r.Findings[0].Tool != "read" {
		t.Errorf("first finding should be the poisoned read tool, got %+v", r.Findings[0])
	}
	if r.Findings[1].Kind != UnrestrictedEgress {
		t.Errorf("second finding should be unrestricted egress, got %+v", r.Findings[1])
	}
}

func TestScanLaunchConfig(t *testing.T) {
	cfg := Config{Servers: []Server{
		// direct npx of an unpinned scoped package: unbrokered AND unpinned-install.
		{Name: "files", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/repo"}, fromLaunch: true},
		// brokered through herkos, inner upstream pinned: no findings.
		{Name: "git", Command: "herkos", Args: []string{"serve", "--allow-tool", "read", "--", "npx", "git-mcp@1.2.3"}, fromLaunch: true},
	}}
	r := Scan(cfg, nil)

	if got := r.count(Unbrokered); got != 1 {
		t.Fatalf("unbrokered: got %d want 1 (only files); findings=%+v", got, r.Findings)
	}
	if got := r.count(UnpinnedInstall); got != 1 {
		t.Fatalf("unpinned-install: got %d want 1 (files); findings=%+v", got, r.Findings)
	}
	for _, f := range r.Findings {
		if f.Server == "git" {
			t.Fatalf("brokered+pinned server must not be flagged: %+v", f)
		}
	}
}

func TestUnpinnedNpxClassification(t *testing.T) {
	cases := map[string]struct {
		args []string
		want bool
	}{
		"unscoped unpinned":  {[]string{"-y", "weather-mcp"}, true},
		"unscoped pinned":    {[]string{"-y", "weather-mcp@2.0.1"}, false},
		"scoped unpinned":    {[]string{"-y", "@scope/srv"}, true},
		"scoped pinned":      {[]string{"-y", "@scope/srv@1.0.0"}, false},
		"flags only, no pkg": {[]string{"-y"}, false},
	}
	for name, c := range cases {
		if got := unpinnedNpx("npx", c.args); got != c.want {
			t.Errorf("%s: unpinnedNpx(npx, %v)=%v want %v", name, c.args, got, c.want)
		}
	}
	if unpinnedNpx("node", []string{"server.js"}) {
		t.Error("non-npx command must not be flagged as unpinned npx")
	}
}

func TestLoadConfigBothFormats(t *testing.T) {
	dir := t.TempDir()

	// real launch config -> parsed into fromLaunch servers, name-sorted.
	launch := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(launch, []byte(`{"mcpServers":{"b":{"command":"npx","args":["-y","pkg"]},"a":{"command":"herkos","args":["serve"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(launch)
	if err != nil {
		t.Fatalf("LoadConfig launch: %v", err)
	}
	if len(cfg.Servers) != 2 || cfg.Servers[0].Name != "a" || cfg.Servers[1].Name != "b" {
		t.Fatalf("launch config not parsed/sorted: %+v", cfg.Servers)
	}
	if !cfg.Servers[0].fromLaunch || cfg.Servers[1].Command != "npx" {
		t.Fatalf("launch fields not populated: %+v", cfg.Servers)
	}

	// security manifest -> parsed into the Servers array.
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"servers":[{"name":"x","allowsUnrestrictedEgress":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mcfg, err := LoadConfig(manifest)
	if err != nil {
		t.Fatalf("LoadConfig manifest: %v", err)
	}
	if len(mcfg.Servers) != 1 || mcfg.Servers[0].Name != "x" || mcfg.Servers[0].fromLaunch {
		t.Fatalf("manifest not parsed as manifest: %+v", mcfg.Servers)
	}
}

// TestLoadConfigProjectScoped pins the ~/.claude.json coverage fix: Claude Code keeps some MCP
// servers at the top level and others under projects[path].mcpServers. Both must be scanned, and
// a project-scoped server is labelled "<project>/<name>" so it is never silently skipped.
func TestLoadConfigProjectScoped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "claude.json")
	cfg := `{
		"mcpServers": {"top": {"command":"npx","args":["-y","top-server"]}},
		"projects": {
			"/home/u/proj-a": {"mcpServers": {"a": {"type":"http","url":"https://a.example.com/mcp"}}},
			"/home/u/proj-b": {"mcpServers": {"b": {"command":"node","args":["b.js"]}}},
			"/home/u/empty":  {"history": []}
		}
	}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range c.Servers {
		got[s.Name] = true
		if !s.fromLaunch {
			t.Errorf("server %q should be fromLaunch", s.Name)
		}
	}
	if len(c.Servers) != 3 {
		t.Fatalf("want 3 servers (1 top + 2 project-scoped, empty project skipped), got %d: %+v", len(c.Servers), c.Servers)
	}
	for _, want := range []string{"top", "proj-a/a", "proj-b/b"} {
		if !got[want] {
			t.Errorf("missing server %q; got %v", want, got)
		}
	}
	// The project-scoped http server must surface as remote, proving it was actually scanned.
	if r := Scan(c, nil); r.count(Remote) != 1 {
		t.Fatalf("project-scoped http server not scanned as remote; findings=%+v", r.Findings)
	}
}

// TestScanFlagsHTTPRemote pins the http/sse handling: a remote MCP server (a URL, no local
// command) is reported as "remote", not "unbrokered" - the in-path stdio broker physically
// cannot sit in front of a URL, so recommending it be brokered would be wrong.
func TestScanFlagsHTTPRemote(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mcp.json")
	cfg := `{"mcpServers":{
		"local":  {"command":"npx","args":["-y","some-server@1.2.3"]},
		"api":    {"type":"http","url":"https://api.example.com/mcp"},
		"stream": {"type":"sse","url":"https://stream.example.com/mcp"}
	}}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	r := Scan(c, nil)
	if got := r.count(Remote); got != 2 {
		t.Fatalf("remote: got %d want 2 (api + stream); findings=%+v", got, r.Findings)
	}
	if got := r.count(Unbrokered); got != 1 {
		t.Fatalf("unbrokered: got %d want 1 (only the stdio local server); findings=%+v", got, r.Findings)
	}
	for _, f := range r.Findings {
		if f.Kind == Unbrokered && f.Server != "local" {
			t.Fatalf("http/sse remote wrongly flagged unbrokered: %+v", f)
		}
	}
}

// TestLoadConfigServersObject pins the servers-object shape: a "servers" OBJECT is a launch
// config (like mcpServers), while a "servers" ARRAY stays the security manifest.
func TestLoadConfigServersObject(t *testing.T) {
	dir := t.TempDir()
	obj := filepath.Join(dir, "vscode.json")
	if err := os.WriteFile(obj, []byte(`{"servers":{
		"local": {"type":"stdio","command":"npx","args":["-y","srv"]},
		"api":   {"type":"http","url":"https://api.example.com/mcp"}
	}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(obj)
	if err != nil {
		t.Fatalf("LoadConfig vscode object: %v", err)
	}
	if len(c.Servers) != 2 {
		t.Fatalf("want 2 launch servers from a servers object, got %d: %+v", len(c.Servers), c.Servers)
	}
	for _, s := range c.Servers {
		if !s.fromLaunch {
			t.Errorf("server %q from a servers object must be fromLaunch", s.Name)
		}
	}
	if r := Scan(c, nil); r.count(Remote) != 1 || r.count(Unbrokered) != 1 {
		t.Fatalf("servers-object launch config not scanned as launch config; findings=%+v", r.Findings)
	}

	arr := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(arr, []byte(`{"servers":[{"name":"x","allowsUnrestrictedEgress":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadConfig(arr)
	if err != nil {
		t.Fatalf("LoadConfig manifest array: %v", err)
	}
	if len(m.Servers) != 1 || m.Servers[0].fromLaunch {
		t.Fatalf("a servers array must stay a manifest, not a launch config: %+v", m.Servers)
	}
}
