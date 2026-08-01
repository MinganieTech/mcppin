package mcppin

import "testing"

// The number cases come from RFC 8785. They are the whole reason this file
// exists: Go's shortest form agrees on the digits and disagrees on when to
// switch to exponential notation.
func TestNumbersFollowTheEcmascriptForm(t *testing.T) {
	cases := map[string]string{
		`0`:                      `0`,
		`-0`:                     `0`,
		`1`:                      `1`,
		`1.0`:                    `1`,
		`-1.5`:                   `-1.5`,
		`100`:                    `100`,
		`0.5`:                    `0.5`,
		`1e21`:                   `1e+21`,
		`1e30`:                   `1e+30`,
		`1e-6`:                   `0.000001`,
		`1e-7`:                   `1e-7`,
		`0.000001`:               `0.000001`,
		`5e-324`:                 `5e-324`,
		`9007199254740992`:       `9007199254740992`,
		`1.7976931348623157e308`: `1.7976931348623157e+308`,
	}
	for literal, want := range cases {
		value, err := DecodeJSON([]byte(literal))
		if err != nil {
			t.Fatalf("%s: DecodeJSON: %v", literal, err)
		}
		got, err := Canonicalize(value)
		if err != nil {
			t.Fatalf("%s: Canonicalize: %v", literal, err)
		}
		if string(got) != want {
			t.Errorf("%s canonicalised to %s, want %s", literal, got, want)
		}
	}
}

func TestKeysAreOrderedByUtf16CodeUnit(t *testing.T) {
	// U+FFFF is a single code unit 0xFFFF; U+1F602 is the surrogate pair
	// 0xD83D 0xDE02. By code point the first sorts before the second, by
	// UTF-16 code unit the order reverses - which is what RFC 8785 requires
	// and what a byte-order sort gets wrong.
	value, err := DecodeJSON([]byte(`{"￿":1,"😂":2,"a":3}`))
	if err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	got, err := Canonicalize(value)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := "{\"a\":3,\"\U0001f602\":2,\"￿\":1}"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStringsEscapeOnlyWhatMustBeEscaped(t *testing.T) {
	value, err := DecodeJSON([]byte(`{"k":"a\"b\\c\ndeé"}`))
	if err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	got, err := Canonicalize(value)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"k":"a\"b\\c\nde` + "é" + `"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestSameToolTwoOrderingsOneDigest(t *testing.T) {
	first, err := DecodeJSON([]byte(`{"name":"refund","inputSchema":{"type":"object","required":["amount"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeJSON([]byte(`{"inputSchema":{"required":["amount"],"type":"object"},"name":"refund"}`))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Digest(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Digest(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("key order changed the digest: %s vs %s", a, b)
	}
}

func TestNumberBeyondExactDoubleIsReported(t *testing.T) {
	value, err := DecodeJSON([]byte(`{"a":9007199254740993,"b":1,"c":[12345678901234567890]}`))
	if err != nil {
		t.Fatal(err)
	}
	found := UnstableNumbers(value)
	if len(found) != 2 {
		t.Fatalf("want 2 unstable literals, got %v", found)
	}
}

// The notation is not the question. 9007199254740993 written with a point or
// an exponent is the same integer beyond 2^53, and a rule that only looked at
// plain integer literals would let the same value through in two spellings.
func TestNotationDoesNotHideAnInexactValue(t *testing.T) {
	unstable := []string{
		`9007199254740993`,
		`9007199254740993.0`,
		`9.007199254740993e15`,
		`1e30`,    // an integer far beyond 2^53, written short
		`-1e30`,   //
		`1e999`,   // beyond the range float64 holds at all
		`-1e999`,  //
		`1e-999`,  // below it, and not the zero it would canonicalise to
		`1.0e400`, //
	}
	for _, literal := range unstable {
		value, err := DecodeJSON([]byte(literal))
		if err != nil {
			t.Fatalf("%s: DecodeJSON: %v", literal, err)
		}
		if found := UnstableNumbers(value); len(found) != 1 {
			t.Errorf("%s should have no reproducible identity, got %v", literal, found)
		}
	}
}

func TestOrdinaryNumbersAreNotReportedUnstable(t *testing.T) {
	value, err := DecodeJSON([]byte(
		`{"a":9007199254740992,"b":-4500,"c":1.5,"d":1.5e10,"e":0.1,"f":1e-7,"g":5e-324}`))
	if err != nil {
		t.Fatal(err)
	}
	if found := UnstableNumbers(value); len(found) != 0 {
		t.Errorf("unexpected unstable literals %v", found)
	}
}
