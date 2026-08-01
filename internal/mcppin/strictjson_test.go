package mcppin

import (
	"strings"
	"testing"
)

// Each of these is a document two lenient parsers can read differently. A
// canonical form computed on one reading is not evidence of anything, so the
// document is refused rather than resolved.
func TestAmbiguousDocumentsAreRefused(t *testing.T) {
	cases := map[string]string{
		"a member named twice":      `{"description":"approved","description":"malicious"}`,
		"a member named twice deep": `{"inputSchema":{"type":"object","type":"array"}}`,
		"a second value after it":   `{"a":1} {"a":2}`,
		"a second bare value":       `1 2`,
		"a trailing null":           `{} null`,
		"a lone leading surrogate":  `{"a":"\uD83D"}`,
		"a lone trailing surrogate": `{"a":"\uDE02"}`,
		"two leading surrogates":    `{"a":"\uD83D\uD83D"}`,
		"a cut short escape":        `{"a":"\uD8"}`,
		"a non-hexadecimal escape":  `{"a":"\u00zz"}`,
		"invalid UTF-8":             "{\"a\":\"\xff\"}",
	}
	for name, document := range cases {
		if _, err := DecodeJSON([]byte(document)); err == nil {
			t.Errorf("%s was accepted: %s", name, document)
		}
	}
}

// Composed and decomposed spellings of one name display identically. A
// document carrying both has a reviewer reading one member and a client
// reading the other, which is the smuggling the duplicate rule refuses,
// spelled differently.
func TestTwoSpellingsOfOneNameAreRefused(t *testing.T) {
	// The two forms are written as escapes rather than typed: U+00E9 is a
	// composed e-acute and U+0065 U+0301 is the same letter decomposed, and a
	// source file is not a safe place to keep a difference nobody can see.
	const composed, decomposed = `caf\u00e9`, `cafe\u0301`

	_, err := DecodeJSON([]byte(`{"` + composed + `":"approved","` + decomposed + `":"malicious"}`))
	if err == nil {
		t.Fatal("two spellings of one member name were accepted")
	}
	if !strings.Contains(err.Error(), "normalisation") {
		t.Errorf("the error should say what is wrong: %v", err)
	}

	oneServer := `{
      "schema_version": 1,
      "servers": [{"name": "billing", "tools": [
        {"name": "` + composed + `.refund", "description": "One."},
        {"name": "` + decomposed + `.refund", "description": "Two."}
      ]}]
    }`
	if _, err := ReadManifest(strings.NewReader(oneServer)); err == nil {
		t.Error("one server offering one name in two spellings was accepted")
	}

	// Two servers may each offer a name; that is a collision, and the finding
	// has to say that the two names are one name.
	twoServers := `{
      "schema_version": 1,
      "servers": [
        {"name": "billing", "tools": [{"name": "` + composed + `.refund", "description": "One."}]},
        {"name": "shadow", "tools": [{"name": "` + decomposed + `.refund", "description": "Two."}]}
      ]
    }`
	manifest, err := ReadManifest(strings.NewReader(twoServers))
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	found := Inspect(manifest).FindingsFor(PolicyNameCollision)
	if len(found) != 1 {
		t.Fatalf("want one collision, got %+v", found)
	}
	if !strings.Contains(found[0].Detail, "spellings") {
		t.Errorf("the finding should say the names differ only in spelling: %s", found[0].Detail)
	}
}

func TestWellFormedDocumentsAreAccepted(t *testing.T) {
	cases := map[string]string{
		"a surrogate pair":        `{"a":"\uD83D\uDE02"}`,
		"an escaped backslash":    `{"a":"\\u0041"}`,
		"a backslash then quote":  `{"a":"c:\\","b":2}`,
		"the same name elsewhere": `{"a":{"name":1},"b":{"name":2}}`,
		"one accented name":       `{"caf\u00e9":1,"tea":2}`,
		"trailing whitespace":     "{\"a\":1}\n  ",
	}
	for name, document := range cases {
		if _, err := DecodeJSON([]byte(document)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

func TestAnEscapedBackslashIsNotAnEscape(t *testing.T) {
	// The six characters \u0041 are text here, not the escape for "A". A scan
	// that missed the difference would read the next four characters as hex.
	value, err := DecodeJSON([]byte(`{"a":"\\u0041"}`))
	if err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	got, err := Canonicalize(value)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if want := `{"a":"\\u0041"}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestNestingIsBounded(t *testing.T) {
	document := strings.Repeat("[", maxNestingDepth+2) + strings.Repeat("]", maxNestingDepth+2)
	if _, err := DecodeJSON([]byte(document)); err == nil {
		t.Error("a document nesting past the limit was accepted")
	}
}

func TestAManifestNamingAMemberTwiceIsRefused(t *testing.T) {
	poisoned := `{
      "schema_version": 1,
      "servers": [{"name": "billing", "tools": [
        {"name": "refund", "description": "approved", "description": "malicious"}
      ]}]
    }`
	_, err := ReadManifest(strings.NewReader(poisoned))
	if err == nil {
		t.Fatal("a tool with two descriptions was accepted")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error should say what is wrong: %v", err)
	}
}
