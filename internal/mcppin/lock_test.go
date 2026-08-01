package mcppin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The lockfile is the approved record. Every document here has two readings,
// and a security artifact that picks one silently is worse than one that
// refuses the file.
func TestAnAmbiguousLockfileIsRefused(t *testing.T) {
	cases := map[string]string{
		"no server at all": `{"schema_version": 1, "servers": []}`,
		"one server twice": `{"schema_version": 1, "servers": [
			{"name": "billing", "tools": []},
			{"name": "billing", "tools": [{"name": "refund", "digest": "sha256:` + strings.Repeat("a", 64) + `"}]}]}`,
		"one tool twice": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "sha256:` + strings.Repeat("a", 64) + `"},
			{"name": "refund", "digest": "sha256:` + strings.Repeat("b", 64) + `"}]}]}`,
		"an unknown algorithm": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "md5:` + strings.Repeat("a", 32) + `"}]}]}`,
		"a truncated digest": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "sha256:` + strings.Repeat("a", 63) + `"}]}]}`,
		"a digest in capitals": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "sha256:` + strings.Repeat("A", 64) + `"}]}]}`,
		"a pin with no digest": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund"}]}]}`,
		"a pin with both": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "sha256:` + strings.Repeat("a", 64) + `",
			 "undecidable_literals": ["1e999"]}]}]}`,
		"an empty undecidable list": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "undecidable_literals": []}]}]}`,
		"a second document": `{"schema_version": 1, "servers": [{"name": "billing", "tools": [
			{"name": "refund", "digest": "sha256:` + strings.Repeat("a", 64) + `"}]}]} {"schema_version": 1}`,
		"a version this build does not read": `{"schema_version": 2, "servers": [{"name": "billing", "tools": []}]}`,
	}
	for name, document := range cases {
		if _, err := ReadLock(strings.NewReader(document)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestALockfileSurvivesARoundTripWithAnUndecidablePin(t *testing.T) {
	imprecise := `{
      "schema_version": 1,
      "servers": [{"name": "ledger", "tools": [
        {"name": "ledger.post", "description": "Post.", "inputSchema": {"maximum": 9007199254740993}}
      ]}]
    }`
	manifest := manifestOf(t, imprecise)
	lock := lockOf(t, manifest)
	if len(lock.Servers[0].Tools[0].Undecidable) != 1 {
		t.Fatalf("the tool should be pinned as undecidable: %+v", lock.Servers[0].Tools[0])
	}
	if lock.Servers[0].Tools[0].Digest != "" {
		t.Error("an undecidable tool must not carry a digest that covers its neighbours")
	}

	var buffer bytes.Buffer
	if err := WriteLock(&buffer, lock); err != nil {
		t.Fatalf("WriteLock: %v", err)
	}
	reloaded, err := ReadLock(&buffer)
	if err != nil {
		t.Fatalf("ReadLock: %v", err)
	}

	// The pin proves nothing either way, so the tool is reported as
	// undecidable and never as matching.
	result := verifyOf(t, manifest, reloaded)
	if len(result.Findings) != 0 {
		t.Errorf("an undecidable pin cannot prove a departure: %+v", result.Findings)
	}
	if len(result.Unstable) != 1 || result.Unstable[0].Where != "both" {
		t.Errorf("want one entry seen on both sides, got %+v", result.Unstable)
	}
}

func TestWritingALockfileLeavesNothingHalfWritten(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "mcp.lock.json")
	if err := os.WriteFile(path, []byte("previous baseline"), 0o644); err != nil {
		t.Fatal(err)
	}

	lock := lockOf(t, manifestOf(t, approvedSurface))
	if err := WriteLockFile(path, lock); err != nil {
		t.Fatalf("WriteLockFile: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLock(bytes.NewReader(written)); err != nil {
		t.Fatalf("the lockfile on disk does not read back: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the temporary file was left behind: %+v", entries)
	}
}
