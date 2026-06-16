// Command herkos-demo runs the deterministic SpanGate walkthrough (tokens saved, bytes
// blocked, verifiable receipt). Run it with `make demo`.
package main

import (
	"fmt"
	"os"

	"github.com/akhilesharora/herkos/internal/demo"
)

func main() {
	if err := demo.Run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "herkos-demo:", err)
		os.Exit(1)
	}
}
