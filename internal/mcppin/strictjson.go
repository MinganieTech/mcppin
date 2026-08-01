// Strict I-JSON decoding.
//
// RFC 8785 canonicalises I-JSON (RFC 7493), and I-JSON exists because ordinary
// JSON leaves several questions to the parser: which of two members of the same
// name wins, what an unpaired surrogate means, whether anything may follow the
// document. A canonical form computed on top of those answers is not evidence,
// because a second reader is free to answer them differently. Everything this
// file rejects is something two honest parsers can disagree about.
package mcppin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxNestingDepth bounds recursion over attacker-supplied input. No tool
// definition comes close; a document written to exhaust the stack does.
const maxNestingDepth = 256

// DecodeJSON decodes a document strictly, keeping every number as its literal
// text so the canonical form is computed from what the producer actually sent.
//
// It rejects what a lenient parser would silently resolve: a duplicate member
// name, an unpaired surrogate escape, invalid UTF-8, anything after the
// document, and nesting past maxNestingDepth.
func DecodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("the document is not valid UTF-8")
	}
	if err := checkEscapes(data); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the document is followed by a second value")
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxNestingDepth {
		return nil, fmt.Errorf("the document nests deeper than %d levels", maxNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil // nil, bool, string or json.Number
	}
	switch delim {
	case '{':
		return decodeObject(decoder, depth+1)
	case '[':
		return decodeArray(decoder, depth+1)
	default:
		return nil, fmt.Errorf("unexpected %q", delim)
	}
}

func decodeObject(decoder *json.Decoder, depth int) (any, error) {
	object := make(map[string]any)
	// A document naming the same member twice has two readings, and the one a
	// canonical form would keep is the parser's choice rather than the
	// producer's statement. Neither reading is evidence.
	names := newNameSet()
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("a member name is not a string: %v", token)
		}
		if other, ok := names.add(key); !ok {
			if other == key {
				return nil, fmt.Errorf("the member %q appears twice in the same object", key)
			}
			return nil, fmt.Errorf("the members %q and %q are the same name after Unicode normalisation",
				other, key)
		}
		value, err := decodeValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		object[key] = value
	}
	if _, err := decoder.Token(); err != nil { // the closing brace
		return nil, err
	}
	return object, nil
}

// nameSet holds names that have to be distinct, and treats two names as the
// same when they are the same after Unicode NFC normalisation.
//
// Two spellings of one name are not a subtlety: composed and decomposed forms
// display identically, so a reviewer reading one member and a client reading
// the other are looking at the same word and different data. Rejecting the
// document is the only reading that is not somebody's guess. The mcp-lock draft
// requires the same rule, and this is the one place mcppin takes a dependency
// to get it right - the alternative is a Unicode table written here, which is
// exactly the kind of code that must not be written twice.
type nameSet struct {
	byNFC map[string]string
}

func newNameSet() *nameSet { return &nameSet{byNFC: make(map[string]string)} }

// add records a name. It reports false when the name cannot stand beside one
// already recorded, and returns that one: equal to name for a plain duplicate,
// different from it when the two are one name in two spellings. The caller
// words the refusal, because "twice" and "the same after normalisation" are
// different things to have to fix.
func (s *nameSet) add(name string) (string, bool) {
	folded := name
	if !isASCII(name) {
		folded = norm.NFC.String(name)
	}
	if other, taken := s.byNFC[folded]; taken {
		return other, false
	}
	s.byNFC[folded] = name
	return name, true
}

// foldName is the key two names have to differ in to be different names.
func foldName(name string) string {
	if isASCII(name) {
		return name
	}
	return norm.NFC.String(name)
}

// isASCII is the fast path: an ASCII string is already in NFC, and almost
// every name in a tool definition is one.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func decodeArray(decoder *json.Decoder, depth int) (any, error) {
	array := []any{}
	for decoder.More() {
		value, err := decodeValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		array = append(array, value)
	}
	if _, err := decoder.Token(); err != nil { // the closing bracket
		return nil, err
	}
	return array, nil
}

// checkEscapes rejects unpaired surrogate escapes. A lenient decoder turns
// \uD800 into U+FFFD, so two documents that differ only there canonicalise to
// the same bytes and one digest covers both.
//
// It walks the raw document rather than the decoded value because the
// substitution has already happened by the time a value exists. Only string
// literals can carry a backslash, so tracking whether the scan stands inside
// one is enough; the decoder validates the grammar afterwards.
func checkEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			continue
		}
		switch data[i] {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return errors.New("a string ends on a backslash")
			}
			if data[i+1] != 'u' {
				i++ // an ordinary two-character escape
				continue
			}
			first, err := hexEscape(data, i)
			if err != nil {
				return err
			}
			if isLowSurrogate(first) {
				return fmt.Errorf("the escape \\u%04X is a trailing surrogate with nothing before it", first)
			}
			if !isHighSurrogate(first) {
				i += 5
				continue
			}
			if i+6 >= len(data) || data[i+6] != '\\' || i+7 >= len(data) || data[i+7] != 'u' {
				return fmt.Errorf("the escape \\u%04X is a leading surrogate with nothing after it", first)
			}
			second, err := hexEscape(data, i+6)
			if err != nil {
				return err
			}
			if !isLowSurrogate(second) {
				return fmt.Errorf("the escape \\u%04X is a leading surrogate followed by \\u%04X", first, second)
			}
			i += 11
		}
	}
	return nil
}

// hexEscape reads the four hex digits of the \u escape starting at start.
func hexEscape(data []byte, start int) (rune, error) {
	if start+6 > len(data) {
		return 0, errors.New("a \\u escape is cut short")
	}
	var value rune
	for _, digit := range data[start+2 : start+6] {
		switch {
		case digit >= '0' && digit <= '9':
			value = value<<4 | rune(digit-'0')
		case digit >= 'a' && digit <= 'f':
			value = value<<4 | rune(digit-'a'+10)
		case digit >= 'A' && digit <= 'F':
			value = value<<4 | rune(digit-'A'+10)
		default:
			return 0, fmt.Errorf("a \\u escape carries the non-hexadecimal byte %q", digit)
		}
	}
	return value, nil
}

func isHighSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }

func isLowSurrogate(r rune) bool { return r >= 0xDC00 && r <= 0xDFFF }
