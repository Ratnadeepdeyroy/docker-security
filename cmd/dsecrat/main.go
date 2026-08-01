// Command dsecrat is the docker-security CLI entrypoint.
package main

import (
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
