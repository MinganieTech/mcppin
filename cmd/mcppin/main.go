package main

import (
	"os"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

func main() {
	os.Exit(mcppin.Main(os.Args[1:], os.Stdout, os.Stderr))
}
