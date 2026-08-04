package mcppin

import (
	"fmt"
	"sort"
)

// Change is one difference between the tool that was approved and the tool
// being served, addressed by its RFC 6901 pointer.
//
// Two digests prove that something changed and say nothing about what. A
// reviewer deciding whether to re-approve needs the sentence that was added,
// not the fact that a hash moved, and a lockfile nobody can review is how a
// description gets approved without being read in the first place.
type Change struct {
	Kind    string `json:"kind"` // added, removed or changed
	Pointer string `json:"pointer"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

const (
	changeAdded   = "added"
	changeRemoved = "removed"
	changeChanged = "changed"
)

// DiffValues lists what has to happen to before for it to become after.
func DiffValues(before, after any) []Change {
	var changes []Change
	collectChanges(before, after, "", &changes)
	return changes
}

func collectChanges(before, after any, pointer string, changes *[]Change) {
	beforeObject, beforeIsObject := before.(map[string]any)
	afterObject, afterIsObject := after.(map[string]any)
	if beforeIsObject && afterIsObject {
		for _, key := range unionKeys(beforeObject, afterObject) {
			child := pointerChild(pointer, key)
			beforeValue, inBefore := beforeObject[key]
			afterValue, inAfter := afterObject[key]
			switch {
			case !inAfter:
				*changes = append(*changes, Change{
					Kind: changeRemoved, Pointer: child, Before: renderValue(beforeValue)})
			case !inBefore:
				*changes = append(*changes, Change{
					Kind: changeAdded, Pointer: child, After: renderValue(afterValue)})
			default:
				collectChanges(beforeValue, afterValue, child, changes)
			}
		}
		return
	}

	beforeArray, beforeIsArray := before.([]any)
	afterArray, afterIsArray := after.([]any)
	if beforeIsArray && afterIsArray {
		shared := min(len(beforeArray), len(afterArray))
		for i := 0; i < shared; i++ {
			collectChanges(beforeArray[i], afterArray[i], pointerChild(pointer, fmt.Sprint(i)), changes)
		}
		for i := shared; i < len(beforeArray); i++ {
			*changes = append(*changes, Change{
				Kind: changeRemoved, Pointer: pointerChild(pointer, fmt.Sprint(i)),
				Before: renderValue(beforeArray[i])})
		}
		for i := shared; i < len(afterArray); i++ {
			*changes = append(*changes, Change{
				Kind: changeAdded, Pointer: pointerChild(pointer, fmt.Sprint(i)),
				After: renderValue(afterArray[i])})
		}
		return
	}

	from, to := renderValue(before), renderValue(after)
	if from != to || beforeIsObject != afterIsObject || beforeIsArray != afterIsArray {
		// The pointer stays a pointer, empty at the root as RFC 6901 has it.
		// Naming the root in prose belongs to whatever renders this, not to
		// the field a machine reads as a location.
		*changes = append(*changes, Change{
			Kind: changeChanged, Pointer: pointer, Before: from, After: to})
	}
}

func unionKeys(a, b map[string]any) []string {
	seen := make(map[string]bool, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for _, m := range []map[string]any{a, b} {
		for key := range m {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// renderValue turns a value into the text a diff shows. A string is shown as
// itself, because the string is what a reviewer compares; anything else is
// shown in its canonical form.
func renderValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if canonical, err := Canonicalize(value); err == nil {
		return string(canonical)
	}
	// A value with no canonical form is one of the numbers the tool already
	// refuses to pin. It is still shown, so the diff is not silently short.
	return fmt.Sprint(value)
}
