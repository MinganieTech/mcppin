// JSON Canonicalization Scheme, RFC 8785.
//
// A digest is only worth pinning if two honest producers of the same tool
// definition arrive at the same bytes. Serialising with a general-purpose
// encoder does not give that: key order, number formatting and escaping all
// vary. JCS fixes each of them, so this file implements it rather than
// hashing whatever the encoder happened to emit.
package mcppin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize serialises a decoded JSON value per RFC 8785. Numbers must
// have been decoded as json.Number, which is what DecodeJSON does.
func Canonicalize(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Digest is the SHA-256 of the canonical form, prefixed with its algorithm so
// that a lockfile written today stays readable when a second algorithm is
// added.
func Digest(value any) (string, error) {
	canonical, err := Canonicalize(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// DecodeJSON decodes into any, keeping every number as its literal text.
func DecodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func writeValue(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, v)
	case json.Number:
		text, err := formatNumber(v)
		if err != nil {
			return err
		}
		buf.WriteString(text)
	case float64:
		text, err := formatFloat(v)
		if err != nil {
			return err
		}
		buf.WriteString(text)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, key)
			buf.WriteByte(':')
			if err := writeValue(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("a value of type %T has no canonical JSON form", value)
	}
	return nil
}

// lessUTF16 orders keys by UTF-16 code unit, which is what RFC 8785 requires
// and what byte order silently disagrees with above the basic plane.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func formatNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return "", fmt.Errorf("number %s cannot be read: %w", n.String(), err)
	}
	return formatFloat(f)
}

// formatFloat reproduces ECMAScript Number::toString, which is what RFC 8785
// defers to. Go's own shortest form agrees on the digits but disagrees on when
// to switch to exponential notation, so the switch is written out here.
func formatFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("NaN and Infinity have no JSON form")
	}
	if f == 0 {
		return "0", nil // also collapses negative zero
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}

	mantissa, exponent, found := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	if !found {
		return "", fmt.Errorf("unexpected float formatting for %v", f)
	}
	exp10, err := strconv.Atoi(exponent)
	if err != nil {
		return "", err
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	n := exp10 + 1 // the value is 0.<digits> x 10^n

	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	default:
		e := n - 1
		esign := "+"
		if e < 0 {
			esign = "-"
			e = -e
		}
		if k == 1 {
			return sign + digits + "e" + esign + strconv.Itoa(e), nil
		}
		return sign + digits[:1] + "." + digits[1:] + "e" + esign + strconv.Itoa(e), nil
	}
}

// UnstableNumbers lists the numeric literals a value carries that float64
// cannot hold exactly. A digest computed over one of them is not reproducible,
// so the tool refuses to present it as evidence.
func UnstableNumbers(value any) []string {
	var found []string
	collectUnstable(value, &found)
	sort.Strings(found)
	return found
}

func collectUnstable(value any, found *[]string) {
	switch v := value.(type) {
	case json.Number:
		if !exactAsFloat64(v.String()) {
			*found = append(*found, v.String())
		}
	case []any:
		for _, item := range v {
			collectUnstable(item, found)
		}
	case map[string]any:
		for _, item := range v {
			collectUnstable(item, found)
		}
	}
}

func exactAsFloat64(literal string) bool {
	if strings.ContainsAny(literal, ".eE") {
		return true // a decimal literal is read as the double it denotes
	}
	i, err := strconv.ParseInt(literal, 10, 64)
	if err != nil {
		return false // beyond int64, certainly beyond exact double
	}
	const maxExact = int64(1) << 53
	return i <= maxExact && i >= -maxExact
}
