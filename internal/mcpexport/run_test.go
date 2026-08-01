package mcpexport

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

const helperEnv = "MCPPIN_EXPORT_HELPER"

// TestHelperProcessServer is not a test. It is the MCP server the export test
// runs, hosted in this binary so the end-to-end path - spawn a process, speak
// the protocol over its pipes, write a manifest - is exercised without a
// fixture nobody can read.
func TestHelperProcessServer(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("this is the fake server the export test spawns, not a test")
	}
	if err := serve(readWriter{os.Stdin, os.Stdout}, [][]string{
		{`{"name":"stripe.refund","description":"Refund a charge.","inputSchema":{"type":"object"}}`},
		{`{"name":"stripe.charge","description":"Charge a card.","inputSchema":{"type":"object"}}`},
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

type readWriter struct {
	io.Reader
	io.Writer
}

func configFor(t *testing.T, id string, args ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp.json")
	document := fmt.Sprintf(`{"mcpServers": {%q: {"command": %q, "args": %s, "env": {%q: "1"}}}}`,
		id, os.Args[0], jsonStrings(args), helperEnv)
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func jsonStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func TestTheCapturedManifestIsOneMcppinReads(t *testing.T) {
	config := configFor(t, "billing", "-test.run=TestHelperProcessServer")
	manifestPath := filepath.Join(filepath.Dir(config), "manifest.json")

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"-config", config, "-o", manifestPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exited %d\n%s", code, stderr.String())
	}

	manifest, err := mcppin.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("the manifest does not read back: %v", err)
	}
	if manifest.SchemaVersion != mcppin.ManifestSchemaVersion {
		t.Errorf("schema version %d", manifest.SchemaVersion)
	}
	if !manifest.Complete || !manifest.CompleteStated {
		t.Error("both pages were read, so the capture says it is complete")
	}
	if manifest.CapturedBy == "" || manifest.CapturedAt == "" {
		t.Error("the capture should carry its own provenance")
	}
	if len(manifest.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(manifest.Servers))
	}
	server := manifest.Servers[0]
	if server.ID != "billing" {
		t.Errorf("the identity is the configuration key, got %q", server.ID)
	}
	if server.ReportedName != "fake-mcp" {
		t.Errorf("what the server calls itself is recorded beside it, got %q", server.ReportedName)
	}
	if len(server.Tools) != 2 {
		t.Fatalf("want the tools of both pages, got %d", len(server.Tools))
	}

	// And the whole point: the manifest can be pinned and verified.
	lock, err := mcppin.BuildLock(manifest)
	if err != nil {
		t.Fatalf("BuildLock: %v", err)
	}
	result, err := mcppin.Verify(manifest, lock)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("a capture verifies against its own lockfile: %+v", result.Findings)
	}
}

func TestAServerThatCannotBeReachedFailsTheWholeCapture(t *testing.T) {
	config := configFor(t, "billing", "-test.run=TestThisDoesNotExist")
	var stdout, stderr bytes.Buffer
	code := Main([]string{"-config", config, "-timeout", "5s"}, &stdout, &stderr)
	if code != exitUnreachable {
		t.Fatalf("exited %d\n%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("a manifest missing a whole server must not be written:\n%s", stdout.String())
	}
}

func TestAConfigurationThisExporterCannotCaptureIsRefused(t *testing.T) {
	cases := map[string]string{
		"a remote server":   `{"mcpServers": {"billing": {"url": "https://example.test/mcp"}}}`,
		"no command":        `{"mcpServers": {"billing": {"args": ["x"]}}}`,
		"no mcpServers":     `{"servers": {}}`,
		"no server at all":  `{"mcpServers": {}}`,
		"an argument array": `{"mcpServers": {"billing": {"command": "x", "args": [1]}}}`,
	}
	for what, document := range cases {
		path := filepath.Join(t.TempDir(), "mcp.json")
		if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(path); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}
