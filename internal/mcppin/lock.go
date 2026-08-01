package mcppin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// LockSchemaVersion is the lockfile version this build reads and writes.
const LockSchemaVersion = 1

// LockedTool is one tool as it stood when it was approved.
type LockedTool struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// LockedServer groups the tools of one server.
type LockedServer struct {
	Name  string       `json:"name"`
	Tools []LockedTool `json:"tools"`
}

// Lock is the approved tool surface. It is the record a later run is compared
// against - the point of the tool is that approving a description once does
// not approve whatever replaces it.
type Lock struct {
	SchemaVersion int            `json:"schema_version"`
	Servers       []LockedServer `json:"servers"`
}

// LoadLock reads a lockfile.
func LoadLock(path string) (*Lock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lock, err := ReadLock(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lock, nil
}

// ReadLock decodes a lockfile.
func ReadLock(r io.Reader) (*Lock, error) {
	var lock Lock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("lockfile is not valid JSON: %w", err)
	}
	if lock.SchemaVersion != LockSchemaVersion {
		return nil, fmt.Errorf("schema_version is %d, this build reads version %d",
			lock.SchemaVersion, LockSchemaVersion)
	}
	for _, server := range lock.Servers {
		if server.Name == "" {
			return nil, fmt.Errorf("a locked server has no name")
		}
		for _, tool := range server.Tools {
			if tool.Name == "" || tool.Digest == "" {
				return nil, fmt.Errorf("server %q has a locked tool without a name or a digest", server.Name)
			}
		}
	}
	return &lock, nil
}

// BuildLock computes the digest of every tool in a manifest.
func BuildLock(manifest *Manifest) (*Lock, error) {
	lock := &Lock{SchemaVersion: LockSchemaVersion}
	for _, server := range manifest.Servers {
		locked := LockedServer{Name: server.Name}
		for _, tool := range server.Tools {
			digest, err := Digest(tool)
			if err != nil {
				return nil, fmt.Errorf("server %q tool %q: %w", server.Name, toolName(tool), err)
			}
			locked.Tools = append(locked.Tools, LockedTool{Name: toolName(tool), Digest: digest})
		}
		sort.Slice(locked.Tools, func(i, j int) bool { return locked.Tools[i].Name < locked.Tools[j].Name })
		lock.Servers = append(lock.Servers, locked)
	}
	sort.Slice(lock.Servers, func(i, j int) bool { return lock.Servers[i].Name < lock.Servers[j].Name })
	return lock, nil
}

// WriteLock emits a lockfile.
func WriteLock(w io.Writer, lock *Lock) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(lock)
}

func (l *Lock) index() map[string]map[string]string {
	index := make(map[string]map[string]string, len(l.Servers))
	for _, server := range l.Servers {
		tools := make(map[string]string, len(server.Tools))
		for _, tool := range server.Tools {
			tools[tool.Name] = tool.Digest
		}
		index[server.Name] = tools
	}
	return index
}
