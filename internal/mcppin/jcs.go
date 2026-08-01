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
	"math/big"
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

// UnstableNumbers lists the numeric literals a value carries whose identity
// the canonical form does not preserve. A digest computed over one of them
// covers a range of values rather than the one that was approved, so the tool
// refuses to present it as evidence.
func UnstableNumbers(value any) []string {
	seen := make(map[string]bool)
	var found []string
	collectUnstable(value, seen, &found)
	sort.Strings(found)
	return found
}

func collectUnstable(value any, seen map[string]bool, found *[]string) {
	switch v := value.(type) {
	case json.Number:
		literal := v.String()
		if !seen[literal] && !stableAsFloat64(literal) {
			seen[literal] = true
			*found = append(*found, literal)
		}
	case []any:
		for _, item := range v {
			collectUnstable(item, seen, found)
		}
	case map[string]any:
		for _, item := range v {
			collectUnstable(item, seen, found)
		}
	}
}

// maxExactInteger is 2^53, the largest integer above which float64 stops
// counting one at a time.
var maxExactInteger = new(big.Int).Lsh(big.NewInt(1), 53)

// A literal is turned into an exact rational to be measured, and an exponent
// is a cheap way to ask for a rational with a million digits. Both bounds sit
// far beyond anything float64 can hold, so a literal past them has no
// reproducible identity for that reason alone.
const (
	maxLiteralLength   = 1024
	maxDecimalExponent = 1024
)

// stableAsFloat64 says whether the double JCS canonicalises a literal through
// still identifies the value the producer wrote.
//
// Two cases lose that identity. An integral value beyond 2^53 shares its
// double with its neighbours, so 9007199254740993 and 9007199254740992 pin the
// same digest - and the notation makes no difference, which is why the test is
// on the value and not on whether the literal carries a point or an exponent.
// A value outside the range float64 holds at all collapses to an infinity or
// to zero, which is not the value either.
//
// Fractions are left alone. 0.1 is not exactly a double, but every reader
// converts it to the same double, and rejecting it would reject most schemas
// for a difference nobody can exploit.
func stableAsFloat64(literal string) bool {
	if len(literal) > maxLiteralLength {
		return false
	}
	if exponent, ok := decimalExponent(literal); !ok || exponent > maxDecimalExponent || exponent < -maxDecimalExponent {
		return false
	}
	value, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		return false // beyond the largest double, in either direction
	}
	exact, ok := new(big.Rat).SetString(literal)
	if !ok {
		return false // not a literal this build can reason about
	}
	if value == 0 {
		return exact.Sign() == 0 // a value too small to survive is not the zero it becomes
	}
	if !exact.IsInt() {
		return true
	}
	return new(big.Int).Abs(exact.Num()).Cmp(maxExactInteger) <= 0
}

// decimalExponent reads the exponent a literal carries, 0 when it carries
// none. It reports false when the exponent itself is beyond reading.
func decimalExponent(literal string) (int, bool) {
	_, exponent, found := strings.Cut(literal, "e")
	if !found {
		_, exponent, found = strings.Cut(literal, "E")
	}
	if !found {
		return 0, true
	}
	value, err := strconv.Atoi(exponent)
	if err != nil {
		return 0, false
	}
	return value, true
}
