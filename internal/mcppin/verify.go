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
	}
}

func validPolicy(name string) bool {
	for _, p := range Policies() {
		if p == name {
			return true
		}
	}
	return false
}

// Finding is one proven departure from the approved surface.
type Finding struct {
	Policy string `json:"policy"`
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Detail string `json:"detail"`
}

// UnstableTool is a tool whose digest cannot be trusted, because it carries a
// number float64 does not hold exactly.
type UnstableTool struct {
	Server   string   `json:"server"`
	Tool     string   `json:"tool"`
	Literals []string `json:"literals"`
}

// Result is the outcome of an inspection or a verification.
type Result struct {
	Findings []Finding      `json:"findings"`
	Unstable []UnstableTool `json:"unstable_digests"`
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
	result := Result{Findings: []Finding{}, Unstable: []UnstableTool{}}

	offeredBy := make(map[string][]string)
	for _, server := range manifest.Servers {
		for _, tool := range server.Tools {
			name := toolName(tool)
			offeredBy[name] = append(offeredBy[name], server.Name)
			result.Findings = append(result.Findings, inspectTool(server.Name, tool)...)
			if literals := UnstableNumbers(tool); len(literals) > 0 {
				result.Unstable = append(result.Unstable, UnstableTool{
					Server: server.Name, Tool: name, Literals: literals,
				})
			}
		}
	}

	names := make([]string, 0, len(offeredBy))
	for name := range offeredBy {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		servers := offeredBy[name]
		if len(servers) < 2 {
			continue
		}
		sort.Strings(servers)
		result.Findings = append(result.Findings, Finding{
			Policy: PolicyNameCollision,
			Tool:   name,
			Detail: fmt.Sprintf("%s is offered by %d servers: %v", name, len(servers), servers),
		})
	}

	sortResult(&result)
	return result
}

// Verify adds drift against an approved lockfile to what Inspect finds.
func Verify(manifest *Manifest, lock *Lock) (Result, error) {
	result := Inspect(manifest)

	current := make(map[string]map[string]string, len(manifest.Servers))
	for _, server := range manifest.Servers {
		tools := make(map[string]string, len(server.Tools))
		for _, tool := range server.Tools {
			digest, err := Digest(tool)
			if err != nil {
				return Result{}, fmt.Errorf("server %q tool %q: %w", server.Name, toolName(tool), err)
			}
			tools[toolName(tool)] = digest
		}
		current[server.Name] = tools
	}
	approved := lock.index()

	for _, server := range sortedKeys(approved) {
		for _, tool := range sortedKeys(approved[server]) {
			was := approved[server][tool]
			now, offered := current[server][tool]
			switch {
			case !offered:
				result.Findings = append(result.Findings, Finding{
					Policy: PolicyToolRemoved, Server: server, Tool: tool,
					Detail: fmt.Sprintf("%s was approved and is no longer offered", tool),
				})
			case now != was:
				result.Findings = append(result.Findings, Finding{
					Policy: PolicyToolChanged, Server: server, Tool: tool,
					Detail: fmt.Sprintf("%s changed since approval: %s is now %s", tool, was, now),
				})
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

	sortResult(&result)
	return result, nil
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
}
