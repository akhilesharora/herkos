//go:build linux

package cli

import (
	"os/exec"
	"syscall"
)

// applyIsolation makes cmd start its child in a fresh user + network namespace, so the child
// has no network interface of its own (only loopback) and cannot open a socket to any external
// host. It is unprivileged: CLONE_NEWUSER lets an ordinary user create the network namespace.
// The caller's uid is not mapped into the namespace (the child runs as nobody) because mapping
// is often blocked in restricted environments and is not needed for egress isolation. stdio -
// the MCP transport between Herkos and the server - is unaffected, since it is not network.
func applyIsolation(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
	}
	return nil
}
