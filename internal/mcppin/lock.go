package mcppin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LockSchemaVersion is the lockfile version this build writes. Version 1 is
// still read so an existing baseline can be verified before it is rewritten:
// re-approving a surface you have not compared would approve whatever drifted
// into it.
const LockSchemaVersion = 2

// digestAlgorithm prefixes every digest so a second algorithm can be added
// without breaking the files written today.
const digestAlgorithm = "sha256:"

// digestHexLength is the length of a SHA-256 digest in hexadecimal.
const digestHexLength = 64

// LockedTool is one tool as it stood when it was approved.
//
// Approved holds the tool object itself, not only its digest. Two digests tell
// a reviewer that something changed; they never say what, and a lockfile whose
// diff is unreadable is a lockfile nobody reviews - which is how a description
// gets approved in the first place. Exactly one of Digest and Undecidable is
// set.
type LockedTool struct {
	Name        string         `json:"name"`
	Digest      string         `json:"digest,omitempty"`
	Undecidable []string       `json:"undecidable_literals,omitempty"`
	Approved    map[string]any `json:"approved,omitempty"`
}

// LockedServer groups the tools of one server. ID is the identity, from the
// configuration; ReportedName is what the server called itself when it was
// approved, kept so that a server renaming itself can be seen.
type LockedServer struct {
	ID              string       `json:"id"`
	ReportedName    string       `json:"reported_name,omitempty"`
	ProtocolVersion string       `json:"protocol_version,omitempty"`
	Tools           []LockedTool `json:"tools"`
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
//
// The lockfile is the approved record, so anything ambiguous in it is refused
// rather than resolved: two servers of the same identity, one tool pinned
// twice, a digest in an algorithm this build does not know or of the wrong
// length, a pin that is neither a digest nor an admission that no digest is
// possible. Whichever way such a file were read, the reading would be this
// build's choice and not the approver's statement.
//
// A version 2 lockfile also has to agree with itself: every digest is
// recomputed from the approved object stored beside it. A lockfile whose
// digest and content disagree has been edited by something that did not
// understand it, and there is no way to tell which half was the approval.
func ReadLock(r io.Reader) (*Lock, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	root, err := DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("lockfile cannot be read: %w", err)
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("lockfile must be a JSON object")
	}

	version, err := intField(object, "schema_version")
	if err != nil {
		return nil, err
	}
	if version != 1 && version != LockSchemaVersion {
		return nil, fmt.Errorf("schema_version is %d, this build reads versions 1 and %d",
			version, LockSchemaVersion)
	}

	rawServers, ok := object["servers"].([]any)
	if !ok {
		return nil, errors.New("lockfile has no servers array")
	}
	lock := &Lock{SchemaVersion: version}
	ids := newNameSet()
	for i, rawServer := range rawServers {
		server, err := readLockedServer(rawServer, i, version)
		if err != nil {
			return nil, err
		}
		if other, ok := ids.add(server.ID); !ok {
			if other == server.ID {
				return nil, fmt.Errorf("server %q is locked twice", server.ID)
			}
			return nil, fmt.Errorf("servers %q and %q are one identity in two spellings", other, server.ID)
		}
		lock.Servers = append(lock.Servers, server)
	}
	// An empty lockfile approves nothing, and comparing against nothing is the
	// one case where every tool being offered looks unapproved and no tool can
	// be found to have changed. It is far more likely to be a truncated file.
	if len(lock.Servers) == 0 {
		return nil, errors.New("the lockfile pins no server")
	}
	return lock, nil
}

func readLockedServer(raw any, index, version int) (LockedServer, error) {
	entry, ok := raw.(map[string]any)
	if !ok {
		return LockedServer{}, fmt.Errorf("locked server %d is not an object", index+1)
	}

	server := LockedServer{}
	if version == 1 {
		name, _ := entry["name"].(string)
		if name == "" {
			return LockedServer{}, fmt.Errorf("locked server %d has no name", index+1)
		}
		// Version 1 had one name doing two jobs. It becomes the identity and
		// nothing else: what the server called itself was never recorded, and
		// inventing it here would make the first version 2 capture look like a
		// rename.
		server.ID = name
	} else {
		id, _ := entry["id"].(string)
		if id == "" {
			return LockedServer{}, fmt.Errorf("locked server %d has no id", index+1)
		}
		server.ID = id
		server.ReportedName, _ = entry["reported_name"].(string)
		server.ProtocolVersion, _ = entry["protocol_version"].(string)
	}

	rawTools, ok := entry["tools"].([]any)
	if !ok {
		return LockedServer{}, fmt.Errorf("locked server %q has no tools array", server.ID)
	}
	names := newNameSet()
	for i, rawTool := range rawTools {
		tool, err := readLockedTool(rawTool, server.ID, i, version)
		if err != nil {
			return LockedServer{}, err
		}
		if other, ok := names.add(tool.Name); !ok {
			if other == tool.Name {
				return LockedServer{}, fmt.Errorf("server %q pins %q twice", server.ID, tool.Name)
			}
			return LockedServer{}, fmt.Errorf("server %q pins %q and %q, one name in two spellings",
				server.ID, other, tool.Name)
		}
		server.Tools = append(server.Tools, tool)
	}
	return server, nil
}

func readLockedTool(raw any, server string, index, version int) (LockedTool, error) {
	entry, ok := raw.(map[string]any)
	if !ok {
		return LockedTool{}, fmt.Errorf("server %q locked tool %d is not an object", server, index+1)
	}
	name, _ := entry["name"].(string)
	if name == "" {
		return LockedTool{}, fmt.Errorf("server %q locked tool %d has no name", server, index+1)
	}

	tool := LockedTool{Name: name}
	if raw, present := entry["digest"]; present {
		digest, ok := raw.(string)
		if !ok {
			return LockedTool{}, fmt.Errorf("server %q tool %q has a digest that is not a string", server, name)
		}
		if err := checkDigest(digest); err != nil {
			return LockedTool{}, fmt.Errorf("server %q tool %q: %w", server, name, err)
		}
		tool.Digest = digest
	}
	if raw, present := entry["undecidable_literals"]; present {
		literals, ok := raw.([]any)
		if !ok || len(literals) == 0 {
			return LockedTool{}, fmt.Errorf("server %q tool %q has an empty or malformed undecidable_literals", server, name)
		}
		for _, rawLiteral := range literals {
			literal, ok := rawLiteral.(string)
			if !ok || literal == "" {
				return LockedTool{}, fmt.Errorf("server %q tool %q lists an undecidable literal that is not a string", server, name)
			}
			tool.Undecidable = append(tool.Undecidable, literal)
		}
	}
	if (tool.Digest == "") == (len(tool.Undecidable) == 0) {
		return LockedTool{}, fmt.Errorf(
			"server %q tool %q must carry either a digest or undecidable_literals, not both and not neither", server, name)
	}

	if version == 1 {
		return tool, nil // version 1 pinned digests and kept no content
	}
	approved, ok := entry["approved"].(map[string]any)
	if !ok {
		return LockedTool{}, fmt.Errorf("server %q tool %q has no approved object", server, name)
	}
	if toolName(approved) != name {
		return LockedTool{}, fmt.Errorf("server %q pins %q around an approved object named %q",
			server, name, toolName(approved))
	}
	tool.Approved = approved
	if err := checkAgreement(tool); err != nil {
		return LockedTool{}, fmt.Errorf("server %q tool %q: %w", server, name, err)
	}
	return tool, nil
}

// checkAgreement recomputes the pin from the approved object beside it.
func checkAgreement(tool LockedTool) error {
	literals := UnstableNumbers(tool.Approved)
	if len(tool.Undecidable) > 0 {
		if strings.Join(literals, ",") != strings.Join(tool.Undecidable, ",") {
			return fmt.Errorf("the approved object carries %v, not the %v the pin lists",
				literals, tool.Undecidable)
		}
		return nil
	}
	if len(literals) > 0 {
		return fmt.Errorf("the approved object carries %v, which has no reproducible digest, "+
			"yet the pin is a digest", literals)
	}
	digest, err := Digest(tool.Approved)
	if err != nil {
		return err
	}
	if digest != tool.Digest {
		return fmt.Errorf("the digest is %s and the approved object hashes to %s", tool.Digest, digest)
	}
	return nil
}

func checkDigest(digest string) error {
	hex, found := strings.CutPrefix(digest, digestAlgorithm)
	if !found {
		return fmt.Errorf("the digest %q is not in an algorithm this build knows", digest)
	}
	if len(hex) != digestHexLength {
		return fmt.Errorf("the digest %q is %d hexadecimal characters, a SHA-256 digest is %d",
			digest, len(hex), digestHexLength)
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("the digest %q is not lower-case hexadecimal", digest)
		}
	}
	return nil
}

// BuildLock computes the digest of every tool in a manifest and keeps the tool
// beside it. A tool carrying a number the canonical form does not identify is
// pinned as undecidable instead of being given a digest that would cover its
// neighbours too.
func BuildLock(manifest *Manifest) (*Lock, error) {
	lock := &Lock{SchemaVersion: LockSchemaVersion}
	for _, server := range manifest.Servers {
		locked := LockedServer{
			ID:              server.ID,
			ReportedName:    server.ReportedName,
			ProtocolVersion: server.ProtocolVersion,
			Tools:           []LockedTool{},
		}
		for _, tool := range server.Tools {
			name := toolName(tool)
			pinned := LockedTool{Name: name, Approved: tool}
			if literals := UnstableNumbers(tool); len(literals) > 0 {
				pinned.Undecidable = literals
			} else {
				digest, err := Digest(tool)
				if err != nil {
					return nil, fmt.Errorf("server %q tool %q: %w", server.ID, name, err)
				}
				pinned.Digest = digest
			}
			locked.Tools = append(locked.Tools, pinned)
		}
		sort.Slice(locked.Tools, func(i, j int) bool { return locked.Tools[i].Name < locked.Tools[j].Name })
		lock.Servers = append(lock.Servers, locked)
	}
	sort.Slice(lock.Servers, func(i, j int) bool { return lock.Servers[i].ID < lock.Servers[j].ID })
	return lock, nil
}

// WriteLock emits a lockfile. HTML escaping is off: this file is meant to be
// read in a review, and a description turned into < is one a reviewer
// cannot compare with what the server sent.
func WriteLock(w io.Writer, lock *Lock) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(lock)
}

// WriteLockFile writes a lockfile at path without ever leaving a half-written
// one behind.
func WriteLockFile(path string, lock *Lock) error {
	return WriteFileAtomically(path, func(w io.Writer) error { return WriteLock(w, lock) })
}

// WriteFileAtomically writes what emit produces to path, or leaves whatever
// was already there untouched. Truncating the approved baseline and then
// failing to write the new one would destroy the only record of what was
// approved, so the bytes go to a temporary file in the same directory and take
// the name by rename, which either happens or does not.
func WriteFileAtomically(path string, emit func(io.Writer) error) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".mcppin-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	written := func() error {
		if err := emit(temporary); err != nil {
			return err
		}
		if err := temporary.Sync(); err != nil {
			return err
		}
		return temporary.Close() // reported: a buffered write can fail here
	}()
	if written != nil {
		temporary.Close()
		os.Remove(name)
		return written
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (l *Lock) index() map[string]map[string]LockedTool {
	index := make(map[string]map[string]LockedTool, len(l.Servers))
	for _, server := range l.Servers {
		tools := make(map[string]LockedTool, len(server.Tools))
		for _, tool := range server.Tools {
			tools[tool.Name] = tool
		}
		index[server.ID] = tools
	}
	return index
}

func (l *Lock) servers() map[string]LockedServer {
	byID := make(map[string]LockedServer, len(l.Servers))
	for _, server := range l.Servers {
		byID[server.ID] = server
	}
	return byID
}
