package mcppin

import (
	"fmt"
	"sort"
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

// inspectTool reports what can be seen in a tool's own text, without judging
// what it says. No classifier, no scoring, no reading of intent: a description
// that asks an agent to do something outrageous in plain ASCII is a review
// problem, and this tool does not pretend to solve it.
func inspectTool(server string, tool map[string]any) []Finding {
	var findings []Finding
	name := toolName(tool)
	description := toolDescription(tool)

	for where, text := range map[string]string{"name": name, "description": description} {
		if text == "" {
			continue
		}
		if hidden := hiddenRunes(text); len(hidden) > 0 {
			findings = append(findings, Finding{
				Policy: PolicyHiddenCharacters,
				Server: server,
				Tool:   name,
				Detail: fmt.Sprintf("the %s carries characters that occupy no visible space: %s",
					where, strings.Join(hidden, ", ")),
			})
		}
	}

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

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Detail < findings[j].Detail })
	return findings
}
