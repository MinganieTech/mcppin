package mcppin

import (
	"fmt"
	"sort"
)

// Policy names. Each one is a property the tool surface must exhibit.
const (
	// PolicyToolChanged fires when an approved tool no longer hashes to what
	// was approved. This is the whole point: approving a description once does
	// not approve whatever replaces it later.
	PolicyToolChanged = "tool-changed"
	// PolicyToolAdded fires when a server offers a tool nobody approved.
	PolicyToolAdded = "tool-added"
	// PolicyToolRemoved fires when an approved tool is no longer offered.
	PolicyToolRemoved = "tool-removed"
	// PolicyNameCollision fires when two servers offer the same tool name and
	// the agent has no way to say which one it meant.
	PolicyNameCollision = "name-collision"
	// PolicyHiddenCharacters fires on text that occupies no visible space.
	PolicyHiddenCharacters = "hidden-characters"
	// PolicyMixedScriptName fires on a tool name drawing on several writing
	// systems.
	PolicyMixedScriptName = "mixed-script-name"
	// PolicyInvalidToolName fires on a tool name outside A-Za-z0-9._-.
	PolicyInvalidToolName = "invalid-tool-name"
	// PolicyServerRenamed fires when a server no longer calls itself what it
	// called itself when it was approved. The identity is the one the
	// configuration gave it, so this is the server changing its own story, not
	// a second server.
	PolicyServerRenamed = "server-renamed"
	// PolicyProtocolChanged fires when a server negotiates a different
	// protocol revision than the one the surface was approved over. It is
	// reported and not gated by default: the revision depends on what the
	// exporter asked for as much as on the server, so a changed exporter flag
	// would otherwise read as drift.
	PolicyProtocolChanged = "protocol-changed"
)

// Policies lists every policy name accepted by -fail-on.
func Policies() []string {
	return []string{
		PolicyToolChanged,
		PolicyToolAdded,
		PolicyToolRemoved,
		PolicyNameCollision,
		PolicyHiddenCharacters,
		PolicyMixedScriptName,
		PolicyInvalidToolName,
		PolicyServerRenamed,
		PolicyProtocolChanged,
	}
}

// DefaultPolicies is the gate a verify without -fail-on holds to. Drift is the
// question the tool exists to answer, so answering it and exiting 0 anyway
// would be the one failure mode a pinning tool cannot have. The inspection
// policies are left out of the default because they describe the manifest
// rather than a departure from the approved surface, and a surface can be
// approved with a name collision already in it.
func DefaultPolicies() []string {
	return []string{PolicyToolChanged, PolicyToolAdded, PolicyToolRemoved, PolicyServerRenamed}
}

func validPolicy(name string) bool {
	for _, p := range Policies() {
		if p == name {
			return true
		}
	}
	return false
}

// Finding is one proven departure from the approved surface. Server is the
// identity the configuration gave the server, never the name the server
// reports for itself.
type Finding struct {
	Policy  string   `json:"policy"`
	Server  string   `json:"server"`
	Tool    string   `json:"tool"`
	Detail  string   `json:"detail"`
	Changes []Change `json:"changes,omitempty"`
}

// UnstableTool is a tool that has no digest worth comparing, because it
// carries a number the canonical form does not identify. Where says which side
// of the comparison it was found on: "manifest", "lockfile", or "both".
type UnstableTool struct {
	Server   string   `json:"server"`
	Tool     string   `json:"tool"`
	Where    string   `json:"where"`
	Literals []string `json:"literals"`
}

// UnseenTool is an approved tool that a capture which admits it is incomplete
// did not carry. It cannot be told from a tool that was removed, so it is not
// reported as one.
type UnseenTool struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}

// Result is the outcome of an inspection or a verification.
type Result struct {
	// CaptureComplete carries what the manifest said about itself. A capture
	// that stopped early supports no statement about absence, and a run that
	// hid that behind a clean exit would be reassuring about a surface it had
	// only partly seen.
	CaptureComplete bool `json:"capture_complete"`
	// SignedBy is the fingerprint of the trusted key that vouches for the
	// lockfile, empty when the run was not told to ask. It is reported rather
	// than assumed: "the lockfile was signed" and "the signature was checked
	// against a key you named" are different statements.
	SignedBy string         `json:"signed_by,omitempty"`
	Findings []Finding      `json:"findings"`
	Unstable []UnstableTool `json:"unstable_digests"`
	Unseen   []UnseenTool   `json:"unseen_tools"`
}

// FindingsFor returns every finding of the named policy.
func (r Result) FindingsFor(policy string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Policy == policy {
			out = append(out, f)
		}
	}
	return out
}

// Inspect reports what can be seen in the manifest alone: hidden characters,
// mixed-script names, colliding names across servers, and tools whose digest
// would not be reproducible.
func Inspect(manifest *Manifest) Result {
	result := Result{
		CaptureComplete: manifest.Complete,
		Findings:        []Finding{},
		Unstable:        []UnstableTool{},
		Unseen:          []UnseenTool{},
	}

	// Tools are grouped by the name two names have to differ in to be
	// different names. Two servers offering one name in two Unicode spellings
	// collide exactly as much as two offering the same bytes, and rather more
	// interestingly, so the grouping is on the normalised form and the
	// spellings are reported.
	offeredBy := make(map[string][]string)
	spellings := make(map[string][]string)
	for _, server := range manifest.Servers {
		for _, tool := range server.Tools {
			name := toolName(tool)
			folded := foldName(name)
			offeredBy[folded] = append(offeredBy[folded], server.ID)
			if !contains(spellings[folded], name) {
				spellings[folded] = append(spellings[folded], name)
			}
			result.Findings = append(result.Findings, inspectTool(server.ID, tool)...)
			if literals := UnstableNumbers(tool); len(literals) > 0 {
				result.Unstable = append(result.Unstable, UnstableTool{
					Server: server.ID, Tool: name, Where: "manifest", Literals: literals,
				})
			}
		}
	}

	for _, folded := range sortedKeys(offeredBy) {
		servers := offeredBy[folded]
		if len(servers) < 2 {
			continue
		}
		sort.Strings(servers)
		written := spellings[folded]
		sort.Strings(written)
		detail := fmt.Sprintf("%s is offered by %d servers: %v", written[0], len(servers), servers)
		if len(written) > 1 {
			detail = fmt.Sprintf("%s is offered by %d servers: %v, in %d spellings of one name: %v",
				written[0], len(servers), servers, len(written), written)
		}
		result.Findings = append(result.Findings, Finding{
			Policy: PolicyNameCollision,
			Tool:   written[0],
			Detail: detail,
		})
	}

	sortResult(&result)
	return result
}

// Verify adds drift against an approved lockfile to what Inspect finds.
func Verify(manifest *Manifest, lock *Lock) (Result, error) {
	result := Inspect(manifest)

	type offering struct {
		digest string // empty when the tool has no digest worth comparing
		tool   map[string]any
	}
	current := make(map[string]map[string]offering, len(manifest.Servers))
	for _, server := range manifest.Servers {
		tools := make(map[string]offering, len(server.Tools))
		for _, tool := range server.Tools {
			name := toolName(tool)
			// A tool Inspect already called undecidable gets no digest here:
			// computing one would either fail on a value float64 cannot hold or
			// produce a digest that covers the neighbouring values too.
			if len(UnstableNumbers(tool)) > 0 {
				tools[name] = offering{tool: tool}
				continue
			}
			digest, err := Digest(tool)
			if err != nil {
				return Result{}, fmt.Errorf("server %q tool %q: %w", server.ID, name, err)
			}
			tools[name] = offering{digest: digest, tool: tool}
		}
		current[server.ID] = tools
	}
	approved := lock.index()
	result.Findings = append(result.Findings, changedServers(manifest, lock)...)

	for _, server := range sortedKeys(approved) {
		for _, tool := range sortedKeys(approved[server]) {
			was := approved[server][tool]
			now, offered := current[server][tool]
			switch {
			case !offered && !manifest.Complete:
				// The capture admits it stopped early, so this tool being
				// absent from it is not evidence that it was withdrawn.
				result.Unseen = append(result.Unseen, UnseenTool{Server: server, Tool: tool})
			case !offered:
				result.Findings = append(result.Findings, Finding{
					Policy: PolicyToolRemoved, Server: server, Tool: tool,
					Detail: fmt.Sprintf("%s was approved and is no longer offered", tool),
				})
			case len(was.Undecidable) > 0:
				// The approved side has no digest to compare against, so
				// nothing about this tool is proven either way.
				result.Unstable = append(result.Unstable, UnstableTool{
					Server: server, Tool: tool, Where: "lockfile", Literals: was.Undecidable,
				})
			case now.digest == "":
				// The offered side is undecidable; Inspect has already said so.
			case now.digest != was.Digest:
				result.Findings = append(result.Findings,
					changedTool(server, tool, was, now.tool, now.digest))
			}
		}
	}
	for _, server := range sortedKeys(current) {
		for _, tool := range sortedKeys(current[server]) {
			if _, approvedTool := approved[server][tool]; !approvedTool {
				result.Findings = append(result.Findings, Finding{
					Policy: PolicyToolAdded, Server: server, Tool: tool,
					Detail: fmt.Sprintf("%s is offered and was never approved", tool),
				})
			}
		}
	}

	mergeUnstable(&result)
	sortResult(&result)
	return result, nil
}

// changedTool builds the finding for a tool that no longer hashes to what was
// approved. When the lockfile kept the approved object, the finding says what
// changed; when it is a version 1 lockfile that kept only digests, the two
// digests are all there is to report.
func changedTool(server, tool string, was LockedTool, now map[string]any, digest string) Finding {
	if was.Approved == nil {
		return Finding{
			Policy: PolicyToolChanged, Server: server, Tool: tool,
			Detail: fmt.Sprintf("%s changed since approval: %s is now %s", tool, was.Digest, digest),
		}
	}
	changes := DiffValues(was.Approved, now)
	return Finding{
		Policy: PolicyToolChanged, Server: server, Tool: tool,
		Detail:  fmt.Sprintf("%s changed since approval, in %d place(s)", tool, len(changes)),
		Changes: changes,
	}
}

// changedServers reports what a server says about itself that no longer
// matches what it said when it was approved.
//
// A name that has gone missing counts. A server that stops naming itself has
// changed what it says as surely as one that renames itself, and treating
// silence as "no change" would make the drift disappear by removing the field
// that carried it. What the approval did not record is another matter: a
// version 1 lockfile never held a reported name, and reading its absence as a
// change would fire on every first run after an upgrade.
func changedServers(manifest *Manifest, lock *Lock) []Finding {
	approved := lock.servers()
	var findings []Finding
	for _, server := range manifest.Servers {
		was, locked := approved[server.ID]
		if !locked {
			continue
		}
		if was.ReportedName != "" && was.ReportedName != server.ReportedName {
			detail := fmt.Sprintf("the server approved as %q now calls itself %q",
				was.ReportedName, server.ReportedName)
			if server.ReportedName == "" {
				detail = fmt.Sprintf("the server approved as %q no longer says what it calls itself",
					was.ReportedName)
			}
			findings = append(findings, Finding{
				Policy: PolicyServerRenamed, Server: server.ID, Detail: detail,
			})
		}
		if was.ProtocolVersion != "" && server.ProtocolVersion != "" &&
			was.ProtocolVersion != server.ProtocolVersion {
			findings = append(findings, Finding{
				Policy: PolicyProtocolChanged, Server: server.ID,
				Detail: fmt.Sprintf("the surface was approved over protocol %s and is now served over %s",
					was.ProtocolVersion, server.ProtocolVersion),
			})
		}
	}
	return findings
}

// mergeUnstable folds the two sides of one tool into a single entry, so a tool
// that carries the same unpinnable number before and after is reported once.
func mergeUnstable(result *Result) {
	merged := make([]UnstableTool, 0, len(result.Unstable))
	at := make(map[string]int, len(result.Unstable))
	for _, unstable := range result.Unstable {
		key := unstable.Server + "\x00" + unstable.Tool
		index, seen := at[key]
		if !seen {
			at[key] = len(merged)
			merged = append(merged, unstable)
			continue
		}
		if merged[index].Where != unstable.Where {
			merged[index].Where = "both"
		}
		merged[index].Literals = union(merged[index].Literals, unstable.Literals)
	}
	result.Unstable = merged
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortResult(result *Result) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Policy != b.Policy {
			return a.Policy < b.Policy
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.Detail < b.Detail
	})
	sort.SliceStable(result.Unstable, func(i, j int) bool {
		a, b := result.Unstable[i], result.Unstable[j]
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		return a.Tool < b.Tool
	})
	sort.SliceStable(result.Unseen, func(i, j int) bool {
		a, b := result.Unseen[i], result.Unseen[j]
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		return a.Tool < b.Tool
	})
}
