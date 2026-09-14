package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/swarm-deploy/dockauthz/internal/pki"
	"os"
)

func main() {
	if err := pki.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
