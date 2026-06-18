package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/akhilesharora/herkos/internal/keys"
)

func keygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("key", defaultKeyPath(), "signing key path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	priv, err := keys.LoadOrCreate(*path)
	if err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "key ready at %s\npublic: %s\n", *path, keys.PublicHex(priv))
	return 0
}

func defaultKeyPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "herkos", "key")
	}
	return filepath.Join(os.TempDir(), "herkos-key")
}
