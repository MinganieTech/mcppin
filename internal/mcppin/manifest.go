package mcppin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ManifestSchemaVersion is the manifest version this build reads.
const ManifestSchemaVersion = 1

// Server is one MCP server and the tools it offers. A tool is kept as the raw
// object it arrived as: the digest covers everything the server said about it,
// not the subset this build happens to understand.
type Server struct {
	Name  string
	Tools []map[string]any
}

// Manifest is the tool surface exposed to an agent, across every server.
type Manifest struct {
	SchemaVersion int
	Servers       []Server
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
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("manifest must be a JSON object")
	}

	version, err := intField(object, "schema_version")
	if err != nil {
		return nil, err
	}
	if version != ManifestSchemaVersion {
		return nil, fmt.Errorf("schema_version is %d, this build reads version %d",
			version, ManifestSchemaVersion)
	}

	rawServers, ok := object["servers"].([]any)
	if !ok {
		return nil, errors.New("manifest has no servers array")
	}
	manifest := &Manifest{SchemaVersion: version}
	seen := make(map[string]bool)
	for i, rawServer := range rawServers {
		entry, ok := rawServer.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("server %d is not an object", i+1)
		}
		name, _ := entry["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("server %d has no name", i+1)
		}
		if seen[name] {
			return nil, fmt.Errorf("server %q is declared twice", name)
		}
		seen[name] = true

		rawTools, ok := entry["tools"].([]any)
		if !ok {
			return nil, fmt.Errorf("server %q has no tools array", name)
		}
		server := Server{Name: name}
		toolSeen := make(map[string]bool)
		for j, rawTool := range rawTools {
			tool, ok := rawTool.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("server %q tool %d is not an object", name, j+1)
			}
			toolName, _ := tool["name"].(string)
			if toolName == "" {
				return nil, fmt.Errorf("server %q tool %d has no name", name, j+1)
			}
			if toolSeen[toolName] {
				return nil, fmt.Errorf("server %q offers %q twice", name, toolName)
			}
			toolSeen[toolName] = true
			server.Tools = append(server.Tools, tool)
		}
		manifest.Servers = append(manifest.Servers, server)
	}
	if len(manifest.Servers) == 0 {
		return nil, errors.New("the manifest declares no server")
	}
	return manifest, nil
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

func toolDescription(tool map[string]any) string {
	description, _ := tool["description"].(string)
	return description
}
