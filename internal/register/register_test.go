package register

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// sampleConfig is the seed config every test writes into its temp file. It has
// one unrelated server (weather) and one unknown top-level field
// (schemaVersion) so the preservation assertions have something to protect.
const sampleConfig = `{
  "schemaVersion": 2,
  "mcpServers": {
    "weather": {
      "command": "weather-mcp",
      "args": ["--units", "metric"]
    }
  }
}
`

// seed writes content to a fresh file under t.TempDir and returns its path. The
// temp dir is removed automatically, so tests never touch a real config.
func seed(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "claude.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return path
}

// readConfig parses the JSON file at path into a generic map for inspection.
func readConfig(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config %s: %v", path, err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse config %s: %v", path, err)
	}
	return root
}

// servers returns the mcpServers sub-map, failing the test if it is absent or
// not an object.
func servers(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	raw, ok := root[mcpServersKey]
	if !ok {
		t.Fatalf("config has no %q field", mcpServersKey)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%q is %T, want object", mcpServersKey, raw)
	}
	return m
}

// testServeArgs is a representative serve invocation: an allowlisted tool and an upstream
// command after the -- separator.
var testServeArgs = []string{"--allow-tool", "read_file", "--", "npx", "weather-mcp"}

func TestRegisterAddsHerkosEntry(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := servers(t, readConfig(t, path))[serverName]
	want := map[string]any{
		"command": "herkos",
		"args":    []any{"serve", "--allow-tool", "read_file", "--", "npx", "weather-mcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("herkos entry = %#v, want %#v", got, want)
	}
}

func TestRegisterIsIdempotent(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	first := readConfig(t, path)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("second Register: %v", err)
	}
	second := readConfig(t, path)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("second Register changed config:\n first = %#v\nsecond = %#v", first, second)
	}
}

func TestRegisterWritesBackup(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("Register: %v", err)
	}

	bak, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	// The backup must hold the pre-write bytes, i.e. the original seed config
	// before the herkos entry was inserted.
	if string(bak) != sampleConfig {
		t.Fatalf("backup = %q, want original seed config %q", bak, sampleConfig)
	}
}

func TestRegisterCreatesMissingFile(t *testing.T) {
	// A path that does not exist yet: Register must create it with just the
	// herkos entry, not error out.
	path := filepath.Join(t.TempDir(), "new.json")

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("Register on missing file: %v", err)
	}

	got := servers(t, readConfig(t, path))
	if _, ok := got[serverName]; !ok {
		t.Fatalf("herkos entry missing after Register on new file: %#v", got)
	}
}

func TestUnregisterRemovesEntry(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Unregister(path); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	got := servers(t, readConfig(t, path))
	if _, ok := got[serverName]; ok {
		t.Fatalf("herkos entry still present after Unregister: %#v", got)
	}
	// Unrelated server must survive the removal.
	if _, ok := got["weather"]; !ok {
		t.Fatalf("weather server lost during Unregister: %#v", got)
	}
}

func TestUnregisterIsIdempotent(t *testing.T) {
	path := seed(t, sampleConfig)

	// Unregister when herkos was never added: a no-op, not an error.
	if err := Unregister(path); err != nil {
		t.Fatalf("Unregister on absent entry: %v", err)
	}
	first := readConfig(t, path)

	if err := Unregister(path); err != nil {
		t.Fatalf("second Unregister: %v", err)
	}
	second := readConfig(t, path)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("second Unregister changed config:\n first = %#v\nsecond = %#v", first, second)
	}
}

func TestRegisterPreservesUnrelatedContent(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Register(path, testServeArgs); err != nil {
		t.Fatalf("Register: %v", err)
	}
	root := readConfig(t, path)

	// Unknown top-level field survives the round-trip. JSON numbers decode to
	// float64, so 2 becomes 2.0.
	if v, ok := root["schemaVersion"]; !ok || v != float64(2) {
		t.Fatalf("schemaVersion = %#v (ok=%v), want 2", v, ok)
	}

	// Unrelated server and its nested launch spec survive unchanged.
	weather, ok := servers(t, root)["weather"].(map[string]any)
	if !ok {
		t.Fatalf("weather server missing or wrong type: %#v", servers(t, root)["weather"])
	}
	wantWeather := map[string]any{
		"command": "weather-mcp",
		"args":    []any{"--units", "metric"},
	}
	if !reflect.DeepEqual(weather, wantWeather) {
		t.Fatalf("weather server = %#v, want %#v", weather, wantWeather)
	}
}

func TestWrapReplacesServerInPlace(t *testing.T) {
	path := seed(t, sampleConfig)

	if err := Wrap(path, "weather", []string{"read_file"}); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	srv := servers(t, readConfig(t, path))
	got, ok := srv["weather"].(map[string]any)
	if !ok {
		t.Fatalf("weather entry missing or wrong type: %#v", srv["weather"])
	}
	// weather is now the brokered entry, under the SAME key, with its original command and
	// args moved after the -- separator.
	want := map[string]any{
		"command": "herkos",
		"args":    []any{"serve", "--allow-tool", "read_file", "--", "weather-mcp", "--units", "metric"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrapped weather = %#v, want %#v", got, want)
	}
	// No un-brokered path may remain: Wrap must not leave a separate "herkos" entry that
	// duplicates a direct route, and the original key must hold only the brokered spec.
	if _, dup := srv[serverName]; dup {
		t.Fatalf("Wrap must not add a separate %q entry; config: %#v", serverName, srv)
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	path := seed(t, sampleConfig)
	if err := Wrap(path, "weather", []string{"read_file"}); err != nil {
		t.Fatalf("first Wrap: %v", err)
	}
	first := readConfig(t, path)
	if err := Wrap(path, "weather", []string{"read_file"}); err != nil {
		t.Fatalf("second Wrap: %v", err)
	}
	if second := readConfig(t, path); !reflect.DeepEqual(first, second) {
		t.Fatalf("second Wrap changed config (nested broker?):\n first = %#v\nsecond = %#v", first, second)
	}
}

func TestWrapReappliesAllowlistWithoutNesting(t *testing.T) {
	path := seed(t, sampleConfig)
	if err := Wrap(path, "weather", []string{"read_file"}); err != nil {
		t.Fatalf("first Wrap: %v", err)
	}
	// Re-wrapping with a different allowlist preserves the inner upstream and replaces the
	// allowlist rather than nesting a second broker.
	if err := Wrap(path, "weather", []string{"list_dir"}); err != nil {
		t.Fatalf("re-Wrap: %v", err)
	}
	got, ok := servers(t, readConfig(t, path))["weather"].(map[string]any)
	if !ok {
		t.Fatalf("weather entry missing after re-wrap")
	}
	want := map[string]any{
		"command": "herkos",
		"args":    []any{"serve", "--allow-tool", "list_dir", "--", "weather-mcp", "--units", "metric"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("re-wrapped weather = %#v, want %#v", got, want)
	}
}

func TestWrapUnknownServerErrors(t *testing.T) {
	path := seed(t, sampleConfig)
	if err := Wrap(path, "nope", []string{"read_file"}); err == nil {
		t.Fatal("Wrap on a server that is not in the config must error")
	}
}

func TestWrapAll(t *testing.T) {
	path := seed(t, `{"mcpServers":{
		"local":   {"command":"npx","args":["-y","srv","--flag"]},
		"remote":  {"type":"http","url":"https://api.example.com/mcp"},
		"already": {"command":"herkos","args":["serve","--allow-tool","x","--","node","s.js"]}
	}}`)
	// Stub discoverer: the local server "exposes" two tools; no real process is launched.
	discover := func(command string, args []string) ([]string, error) {
		if command != "npx" {
			t.Errorf("discover called with unexpected upstream %q %v", command, args)
		}
		return []string{"read", "write"}, nil
	}
	results, err := WrapAll(path, discover)
	if err != nil {
		t.Fatalf("WrapAll: %v", err)
	}
	byName := map[string]WrapResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	if !byName["local"].Wrapped || !reflect.DeepEqual(byName["local"].Tools, []string{"read", "write"}) {
		t.Fatalf("local must be wrapped with the discovered tools: %+v", byName["local"])
	}
	if byName["remote"].Wrapped || !strings.Contains(byName["remote"].Skip, "remote") {
		t.Fatalf("remote must be skipped as remote: %+v", byName["remote"])
	}
	if byName["already"].Wrapped || !strings.Contains(byName["already"].Skip, "already") {
		t.Fatalf("already-brokered must be skipped: %+v", byName["already"])
	}
	// The written config must broker local through herkos with the pinned (discovered) allowlist.
	local, ok := servers(t, readConfig(t, path))["local"].(map[string]any)
	if !ok {
		t.Fatal("local entry missing after WrapAll")
	}
	want := map[string]any{
		"command": "herkos",
		"args":    []any{"serve", "--allow-tool", "read", "--allow-tool", "write", "--", "npx", "-y", "srv", "--flag"},
	}
	if !reflect.DeepEqual(local, want) {
		t.Fatalf("wrapped local = %#v, want %#v", local, want)
	}
}

func TestWrapAllServersKey(t *testing.T) {
	// VS Code / GitHub Copilot store servers under "servers", not "mcpServers".
	path := seed(t, `{"servers":{"local":{"type":"stdio","command":"npx","args":["-y","srv"]}}}`)
	discover := func(string, []string) ([]string, error) { return []string{"read"}, nil }
	results, err := WrapAll(path, discover)
	if err != nil {
		t.Fatalf("WrapAll: %v", err)
	}
	if len(results) != 1 || !results[0].Wrapped {
		t.Fatalf("the servers-key local server must be wrapped: %+v", results)
	}
	root := readConfig(t, path)
	if _, ok := root["mcpServers"]; ok {
		t.Fatal("WrapAll must write back under the original key, not move a servers config to mcpServers")
	}
	servers, ok := root["servers"].(map[string]any)
	if !ok {
		t.Fatalf("servers key missing or not an object after wrap: %#v", root)
	}
	e, _ := servers["local"].(map[string]any)
	if cmd, _ := e["command"].(string); cmd != "herkos" {
		t.Fatalf("local not brokered under the servers key: %#v", e)
	}
	if e["type"] != "stdio" {
		t.Errorf("the 'type' field must be preserved on the wrapped entry: %#v", e)
	}
}
