package mcppin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ManifestSchemaVersion is the manifest version this build reads and writes.
//
// Version 1 is refused rather than read. It had no way to say whether the
// capture held every tool, so reading one would mean deciding on its behalf
// that it did - and a removal "proven" against a capture of unknown
// completeness is not proven. Unlike a lockfile, a manifest costs nothing to
// produce again: capture the surface once more rather than assume something
// about the last capture.
const ManifestSchemaVersion = 2

// Server is one MCP server and the tools it offers.
//
// ID is what the surface is keyed by, and it comes from the configuration that
// declared the server, not from the server itself. ReportedName is what the
// server calls itself, which MCP does not guarantee to be unique and which the
// server can change between two captures - it is evidence, not identity.
//
// A tool is kept as the raw object it arrived as: the digest covers everything
// the server said about it, not the subset this build happens to understand.
type Server struct {
	ID           string
	ReportedName string
	// ProtocolVersion is the revision this server negotiated, which two
	// servers in one capture are free to disagree about.
	ProtocolVersion string
	Tools           []map[string]any
}

// Manifest is the tool surface exposed to an agent, across every server.
type Manifest struct {
	SchemaVersion   int
	ProtocolVersion string
	// Complete says whether the capture holds every tool the servers offered,
	// as one surface. A capture that stopped early, or whose passes disagreed,
	// cannot support any statement about absence.
	Complete   bool
	CapturedAt string
	CapturedBy string
	Servers    []Server
}

// LoadManifest reads a manifest from a file.
func LoadManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	manifest, err := ReadManifest(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return manifest, nil
}

// ReadManifest decodes a manifest, keeping every number as its literal text so
// that the canonical form is computed from what the server actually sent.
func ReadManifest(r io.Reader) (*Manifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	root, err := DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("manifest cannot be read: %w", err)
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("manifest must be a JSON object")
	}

	version, err := intField(object, "schema_version")
	if err != nil {
		return nil, err
	}
	if version == 1 {
		return nil, errors.New("this is a version 1 manifest, which could not say whether the " +
			"capture held every tool; capture the surface again with a version 2 exporter")
	}
	if version != ManifestSchemaVersion {
		return nil, fmt.Errorf("schema_version is %d, this build reads version %d",
			version, ManifestSchemaVersion)
	}

	manifest := &Manifest{SchemaVersion: version}
	if err := readCapture(object, manifest); err != nil {
		return nil, err
	}

	rawServers, ok := object["servers"].([]any)
	if !ok {
		return nil, errors.New("manifest has no servers array")
	}
	ids := newNameSet()
	for i, rawServer := range rawServers {
		server, err := readServer(rawServer, i)
		if err != nil {
			return nil, err
		}
		if other, ok := ids.add(server.ID); !ok {
			if other == server.ID {
				return nil, fmt.Errorf("server %q is declared twice", server.ID)
			}
			return nil, fmt.Errorf("servers %q and %q are one identity in two spellings", other, server.ID)
		}
		manifest.Servers = append(manifest.Servers, server)
	}
	if len(manifest.Servers) == 0 {
		return nil, errors.New("the manifest declares no server")
	}
	return manifest, nil
}

// readCapture reads what a version 2 manifest says about its own capture. It
// is required rather than optional: a surface with no provenance cannot be
// told apart from a surface somebody typed, and "complete" is the difference
// between proving a tool was removed and noticing it was not captured.
func readCapture(object map[string]any, manifest *Manifest) error {
	protocol, ok := object["protocol_version"].(string)
	if !ok || protocol == "" {
		return errors.New("protocol_version is missing; it is the protocol the surface was captured over")
	}
	manifest.ProtocolVersion = protocol

	complete, ok := object["complete"].(bool)
	if !ok {
		return errors.New("complete is missing; a capture has to say whether it holds every tool")
	}
	manifest.Complete = complete

	if raw, present := object["captured_at"]; present {
		at, ok := raw.(string)
		if !ok {
			return errors.New("captured_at is not a string")
		}
		if _, err := time.Parse(time.RFC3339, at); err != nil {
			return fmt.Errorf("captured_at is not an RFC 3339 timestamp: %w", err)
		}
		manifest.CapturedAt = at
	}
	if raw, present := object["captured_by"]; present {
		by, ok := raw.(string)
		if !ok {
			return errors.New("captured_by is not a string")
		}
		manifest.CapturedBy = by
	}
	return nil
}

func readServer(raw any, index int) (Server, error) {
	entry, ok := raw.(map[string]any)
	if !ok {
		return Server{}, fmt.Errorf("server %d is not an object", index+1)
	}

	server := Server{}
	id, _ := entry["id"].(string)
	if id == "" {
		return Server{}, fmt.Errorf("server %d has no id", index+1)
	}
	server.ID = id
	server.ReportedName, _ = entry["reported_name"].(string)
	// What the server negotiated is kept: a surface approved over one protocol
	// revision was not approved over another, and a build that dropped this on
	// the floor could not say so.
	server.ProtocolVersion, _ = entry["protocol_version"].(string)

	rawTools, ok := entry["tools"].([]any)
	if !ok {
		return Server{}, fmt.Errorf("server %q has no tools array", server.ID)
	}
	names := newNameSet()
	for i, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			return Server{}, fmt.Errorf("server %q tool %d is not an object", server.ID, i+1)
		}
		name, _ := tool["name"].(string)
		if name == "" {
			return Server{}, fmt.Errorf("server %q tool %d has no name", server.ID, i+1)
		}
		if other, ok := names.add(name); !ok {
			if other == name {
				return Server{}, fmt.Errorf("server %q offers %q twice", server.ID, name)
			}
			return Server{}, fmt.Errorf("server %q offers %q and %q, one name in two spellings",
				server.ID, other, name)
		}
		server.Tools = append(server.Tools, tool)
	}
	return server, nil
}

func intField(object map[string]any, key string) (int, error) {
	number, ok := object[key].(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s is missing or not a number", key)
	}
	value, err := number.Int64()
	if err != nil {
		return 0, fmt.Errorf("%s is not an integer: %w", key, err)
	}
	return int(value), nil
}

func toolName(tool map[string]any) string {
	name, _ := tool["name"].(string)
	return name
}
