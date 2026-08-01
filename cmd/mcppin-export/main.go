// Command mcppin-export captures the tool surface of the stdio MCP servers a
// client configuration declares, and writes the manifest mcppin verifies.
//
// It is a second binary on purpose. mcppin compares two files and speaks to
// nobody; this one runs other people's programs and reads what they say. The
// thing that decides whether a surface is approved should not also be the
// thing an untrusted server gets to answer.
package main

import (
	"os"

	"github.com/MinganieTech/mcppin/internal/mcpexport"
)

func main() {
	os.Exit(mcpexport.Main(os.Args[1:], os.Stdout, os.Stderr))
}
