//go:build !linux

package cli

import (
	"errors"
	"os/exec"
)

// applyIsolation is unsupported off Linux: network-namespace isolation is a Linux feature.
func applyIsolation(_ *exec.Cmd) error {
	return errors.New("serve --isolate (network isolation) is only supported on Linux")
}
