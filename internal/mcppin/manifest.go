package mcppin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ManifestSchemaVersion is the manifest version this build writes. Version 1
// is still read: a build that could only read what it writes would force every
// existing baseline to be re-approved, and re-approving a surface you have not
// compared is the one thing this tool exists to prevent.
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
	Tools        []map[string]any
}

// Manifest is the tool surface exposed to an agent, across every server.
type Manifest struct {
	SchemaVersion   int
	ProtocolVersion string
	// Complete says whether the capture holds every tool the servers offered.
	// A capture that stopped early cannot support any statement about absence.
	Complete bool
	// CompleteStated is false for a version 1 manifest, which had no way to
	// say. Such a manifest is read as complete, because that was the contract
	// it was written under, and the run says so rather than assuming quietly.
	CompleteStated bool
	CapturedAt     string
	CapturedBy     string
	Servers        []Server
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
	if version != 1 && version != ManifestSchemaVersion {
		return nil, fmt.Errorf("schema_version is %d, this build reads versions 1 and %d",
			version, ManifestSchemaVersion)
	}

	manifest := &Manifest{SchemaVersion: version, Complete: true}
	if version >= 2 {
		if err := readCapture(object, manifest); err != nil {
			return nil, err
		}
	}

	rawServers, ok := object["servers"].([]any)
	if !ok {
		return nil, errors.New("manifest has no servers array")
	}
	ids := newNameSet()
	for i, rawServer := range rawServers {
		server, err := readServer(rawServer, i, version)
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
	manifest.CompleteStated = true

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

func readServer(raw any, index, version int) (Server, error) {
	entry, ok := raw.(map[string]any)
	if !ok {
		return Server{}, fmt.Errorf("server %d is not an object", index+1)
	}

	server := Server{}
	if version == 1 {
		// Version 1 had one name doing two jobs. It becomes the identity and
		// nothing else: it was never a statement about what the server called
		// itself, and reading it as one would make the first version 2 capture
		// look like a rename.
		name, _ := entry["name"].(string)
		if name == "" {
			return Server{}, fmt.Errorf("server %d has no name", index+1)
		}
		server.ID = name
	} else {
		id, _ := entry["id"].(string)
		if id == "" {
			return Server{}, fmt.Errorf("server %d has no id", index+1)
		}
		server.ID = id
		server.ReportedName, _ = entry["reported_name"].(string)
	}

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
