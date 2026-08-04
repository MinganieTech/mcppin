package mcppin

import (
	"bytes"
	"testing"
)

// The canonical form has to be a fixed point: canonicalising it again must
// produce the same bytes, and it must be a document this build reads. If
// either fails, two honest readers can disagree about a digest, which is the
// one thing the whole tool rests on.
func FuzzDecodeAndCanonicalize(f *testing.F) {
	for _, seed := range []string{
		`{"name":"a","description":"b"}`,
		`{"a":1,"b":[1,2,{"c":null}],"d":true}`,
		`{"é":"café","z":1e-7,"y":9007199254740992}`,
		`[{"a":"😂"},"\t\n\\\"",-0]`,
		`{"a":{"b":{"c":{"d":[[[1]]]}}}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := DecodeJSON(data)
		if err != nil {
			return // refused, which is an answer
		}
		canonical, err := Canonicalize(value)
		if err != nil {
			// Only a number outside what a double holds has no canonical form,
			// and the tool has to be able to say which.
			if len(UnstableNumbers(value)) == 0 {
				t.Fatalf("no canonical form and no unpinnable number: %v", err)
			}
			return
		}

		again, err := DecodeJSON(canonical)
		if err != nil {
			t.Fatalf("the canonical form of %q is %q, which this build refuses: %v", data, canonical, err)
		}
		twice, err := Canonicalize(again)
		if err != nil {
			t.Fatalf("the canonical form of a canonical form has none: %v", err)
		}
		if !bytes.Equal(canonical, twice) {
			t.Fatalf("canonicalising is not a fixed point: %q then %q", canonical, twice)
		}

		first, err := Digest(value)
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		second, err := Digest(again)
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		if first != second {
			t.Fatalf("a value and its canonical form hash differently: %s vs %s", first, second)
		}
	})
}

// A manifest always verifies against the lockfile built from it. Anything else
// means the two sides read the same surface differently, and a run would
// report drift where nothing moved.
func FuzzReadManifest(f *testing.F) {
	f.Add([]byte(capturedSurface))
	f.Add([]byte(approvedSurface))
	f.Add([]byte(`{"schema_version":2,"protocol_version":"2025-11-25","complete":false,
		"servers":[{"id":"a","tools":[{"name":"t","description":"d","inputSchema":{}}]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := ReadManifest(bytes.NewReader(data))
		if err != nil {
			return // refused, which is an answer
		}
		// A manifest this build accepted is one it can always pin: the tools
		// carrying a number with no reproducible identity are pinned as
		// undecidable rather than refused.
		lock, err := BuildLock(manifest, 1)
		if err != nil {
			t.Fatalf("a readable manifest could not be pinned: %v", err)
		}
		result, err := Verify(manifest, lock)
		if err != nil {
			t.Fatalf("a manifest could not be compared against its own lockfile: %v", err)
		}
		for _, policy := range DefaultPolicies() {
			if found := result.FindingsFor(policy); len(found) > 0 {
				t.Fatalf("a surface drifted from its own approval: %+v", found)
			}
		}

		// And the lockfile it produces is one it reads back.
		var written bytes.Buffer
		if err := WriteLock(&written, lock); err != nil {
			t.Fatalf("WriteLock: %v", err)
		}
		if _, err := ReadLock(bytes.NewReader(written.Bytes())); err != nil {
			t.Fatalf("this build wrote a lockfile it refuses to read: %v", err)
		}
	})
}
