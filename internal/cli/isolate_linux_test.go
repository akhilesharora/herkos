//go:build linux

package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// TestIsolateGivesChildNoNetwork proves the serve --isolate primitive: a child started with
// applyIsolation lives in a fresh network namespace with no interface of its own (only
// loopback), so it cannot open a socket to any external host. It skips where the environment
// forbids unprivileged user+net namespaces or lacks the `ip` tool.
func TestIsolateGivesChildNoNetwork(t *testing.T) {
	cmd := exec.Command("ip", "-o", "link", "show")
	if err := applyIsolation(cmd); err != nil {
		t.Skip(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("unprivileged netns or `ip` unavailable here: %v (%s)", err, out)
	}
	s := string(out)
	for _, real := range []string{"eth", "ens", "enp", "wl", "docker", "veth"} {
		if strings.Contains(s, real) {
			t.Fatalf("isolated child must have no real network interface, saw %q in:\n%s", real, s)
		}
	}
	if !strings.Contains(s, "lo") {
		t.Fatalf("isolated child should still have loopback, got:\n%s", s)
	}
}
