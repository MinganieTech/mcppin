package mcppin

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// hiddenRunes lists the characters that occupy no visible space, or none a
// reviewer would notice: format controls, private use, and the control block
// beyond the three whitespace characters a description may legitimately use.
//
// These are what let a tool description carry text a human approver never saw.
func hiddenRunes(s string) []string {
	seen := make(map[rune]bool)
	var found []string
	for _, r := range s {
		if seen[r] {
			continue
		}
		hidden := unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r)
		if !hidden && unicode.Is(unicode.Cc, r) && r != '\n' && r != '\r' && r != '\t' {
			hidden = true
		}
		if hidden {
			seen[r] = true
			found = append(found, fmt.Sprintf("U+%04X", r))
		}
	}
	sort.Strings(found)
	return found
}

// scriptsOf names the writing systems a string draws its letters from,
// ignoring the ones that belong to every script.
func scriptsOf(s string) []string {
	seen := make(map[string]bool)
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		for name, table := range unicode.Scripts {
			if name == "Common" || name == "Inherited" {
				continue
			}
			if unicode.Is(table, r) {
				seen[name] = true
				break
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// portableNameRunes lists the characters of a tool name that fall outside
// A-Za-z0-9, underscore, dot and hyphen. A name is what an agent is told to
// call, what a log records and what a reviewer reads; anything else in it is a
// chance for two names to look alike, or for one to read differently in the
// place it is displayed than in the place it is matched.
func portableNameRunes(name string) []string {
	seen := make(map[rune]bool)
	var found []string
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '.', r == '-':
			continue
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		found = append(found, fmt.Sprintf("U+%04X", r))
	}
	sort.Strings(found)
	return found
}

// pointerChild builds the JSON pointer, RFC 6901, of a member of the object at
// parent. A finding has to say where it is: a description hidden three levels
// down an input schema reaches the model exactly like the top-level one, and
// "somewhere in this tool" is not something a reviewer can act on.
func pointerChild(parent, token string) string {
	return parent + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(token)
}

// inspectTool reports what can be seen in a tool's own text, without judging
// what it says. No classifier, no scoring, no reading of intent: a description
// that asks an agent to do something outrageous in plain ASCII is a review
// problem, and this tool does not pretend to solve it.
func inspectTool(server string, tool map[string]any) []Finding {
	var findings []Finding
	name := toolName(tool)

	// Every string in the object is searched, not just the name and the
	// description. A title, an annotation and the description of a nested
	// schema property all reach the client and the model, so a character
	// hiding in one of them hides just as well.
	collectHidden(server, name, tool, "", &findings)

	// Only the name is checked for mixed writing systems. A description mixing
	// Latin and Han is ordinary prose; a tool name doing it is how one name is
	// made to look like another.
	if scripts := scriptsOf(name); len(scripts) > 1 {
		findings = append(findings, Finding{
			Policy: PolicyMixedScriptName,
			Server: server,
			Tool:   name,
			Detail: fmt.Sprintf("the name mixes writing systems: %s", strings.Join(scripts, ", ")),
		})
	}

	if outside := portableNameRunes(name); len(outside) > 0 {
		findings = append(findings, Finding{
			Policy: PolicyInvalidToolName,
			Server: server,
			Tool:   name,
			Detail: fmt.Sprintf("the name carries characters outside A-Za-z0-9._-: %s",
				strings.Join(outside, ", ")),
		})
	}

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Detail < findings[j].Detail })
	return findings
}

func collectHidden(server, tool string, value any, pointer string, findings *[]Finding) {
	switch v := value.(type) {
	case string:
		if hidden := hiddenRunes(v); len(hidden) > 0 {
			*findings = append(*findings, Finding{
				Policy: PolicyHiddenCharacters,
				Server: server,
				Tool:   tool,
				Detail: fmt.Sprintf("the text at %s carries characters that occupy no visible space: %s",
					pointerOf(pointer), strings.Join(hidden, ", ")),
			})
		}
	case []any:
		for i, item := range v {
			collectHidden(server, tool, item, pointerChild(pointer, strconv.Itoa(i)), findings)
		}
	case map[string]any:
		for _, key := range sortedKeys(v) {
			child := pointerChild(pointer, key)
			if hidden := hiddenRunes(key); len(hidden) > 0 {
				*findings = append(*findings, Finding{
					Policy: PolicyHiddenCharacters,
					Server: server,
					Tool:   tool,
					Detail: fmt.Sprintf("the member name at %s carries characters that occupy no visible space: %s",
						child, strings.Join(hidden, ", ")),
				})
			}
			collectHidden(server, tool, v[key], child, findings)
		}
	}
}

// pointerOf names the whole tool object rather than printing the empty pointer
// RFC 6901 uses for a document root.
func pointerOf(pointer string) string {
	if pointer == "" {
		return "the tool object"
	}
	return pointer
}
