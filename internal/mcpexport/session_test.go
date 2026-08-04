package mcpexport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// page is one answer to tools/list. A cursor is handed out unless the page is
// the last one, and the empty string is a cursor like any other.
type page struct {
	tools  []string
	cursor string
	last   bool
	hangUp bool
}

// fake is a server that answers on one of the two wires. Each round is one
// full traversal of the tool list; the last round is repeated if the client
// traverses more often than the fake was given rounds, so a surface that
// changes between two passes is written by giving two different rounds.
type fake struct {
	era    string
	rounds [][]page
	round  int
	page   int
}

func (f *fake) next() page {
	round := f.rounds[min(f.round, len(f.rounds)-1)]
	answer := round[min(f.page, len(round)-1)]
	f.page++
	if answer.last || answer.hangUp {
		f.round++
		f.page = 0
	}
	return answer
}

func (f *fake) serve(connection io.ReadWriter) error {
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return nil
		}
		var incoming struct {
			ID     *json.Number   `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(line, &incoming); err != nil {
			return err
		}

		if f.era == EraModern {
			// The stateless wire carries the protocol version on every
			// request, and a server is required to refuse one that does not.
			meta, _ := incoming.Params["_meta"].(map[string]any)
			if version, _ := meta[metaProtocolVersion].(string); version == "" {
				fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,`+
					`"message":"no protocol version in _meta"}}`+"\n", incoming.ID)
				continue
			}
			if _, ok := meta[metaClientCapabilities]; !ok {
				fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32021,`+
					`"message":"no client capabilities in _meta"}}`+"\n", incoming.ID)
				continue
			}
		}

		switch incoming.Method {
		case "initialize":
			if f.era == EraModern {
				return fmt.Errorf("a stateless client sent initialize")
			}
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`+"\n")
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":9999,"result":{"ignored":true}}`+"\n")
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q,`+
				`"capabilities":{},"serverInfo":{"name":"fake-mcp","version":"1.0.0"}}}`+"\n",
				incoming.ID, LatestLegacyVersion)
		case "notifications/initialized":
		case "tools/list":
			answer := f.next()
			if answer.hangUp {
				return nil
			}
			cursor, meta := "", ""
			if !answer.last {
				cursor = fmt.Sprintf(`,"nextCursor":%q`, answer.cursor)
			}
			if f.era == EraModern {
				// The modern wire is how a server names itself: there is no
				// handshake to do it in.
				meta = `,"_meta":{"` + metaServerInfo + `":{"name":"fake-mcp","version":"1.0.0"}}`
			}
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete",`+
				`"tools":[%s]%s%s}}`+"\n", incoming.ID, strings.Join(answer.tools, ","), cursor, meta)
		default:
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`+"\n",
				incoming.ID)
		}
		if err != nil {
			return nil
		}
	}
}

func captureFrom(t *testing.T, server *fake, protocol string, passes int) (Capture, error) {
	t.Helper()
	client, remote := net.Pipe()
	// The fake outlives the call - it is still reading when the client hangs
	// up - so its failures come back on a channel. Reporting them with t from
	// inside the goroutine would panic if it lost the race with the end of the
	// test, which is a flake nobody could reproduce.
	failed := make(chan error, 1)
	go func() {
		defer remote.Close()
		failed <- server.serve(remote)
	}()
	t.Cleanup(func() {
		client.Close()
		if err := <-failed; err != nil {
			t.Errorf("the fake server failed: %v", err)
		}
	})

	session, err := NewSession(client, client, protocol, "test")
	if err != nil {
		return Capture{}, err
	}
	return CaptureSurface(session, passes)
}

func onePage(tools ...string) [][]page {
	return [][]page{{{tools: tools, last: true}}}
}

func TestACaptureFollowsTheCursorToTheEnd(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraLegacy, rounds: [][]page{{
		{tools: []string{`{"name":"a.one","description":"One."}`}, cursor: "page2"},
		{tools: []string{`{"name":"a.two","description":"Two."}`, `{"name":"a.three","description":"Three."}`}, last: true},
	}}}, LatestLegacyVersion, 2)
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if !capture.Complete {
		t.Error("both passes read both pages and agreed")
	}
	if len(capture.Tools) != 3 {
		t.Fatalf("want 3 tools, got %d", len(capture.Tools))
	}
	if capture.ReportedName != "fake-mcp" {
		t.Errorf("the server calls itself %q", capture.ReportedName)
	}
	if capture.ProtocolVersion != LatestLegacyVersion {
		t.Errorf("the manifest records what the server answered, got %q", capture.ProtocolVersion)
	}
}

// The specification is explicit: an empty string is a valid cursor and must
// not be read as the end of the results. A client that stopped on one would
// write a short surface and call it complete.
func TestAnEmptyCursorIsACursor(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraLegacy, rounds: [][]page{{
		{tools: []string{`{"name":"a.one","description":"One."}`}, cursor: ""},
		{tools: []string{`{"name":"a.two","description":"Two."}`}, last: true},
	}}}, LatestLegacyVersion, 1)
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if len(capture.Tools) != 2 {
		t.Fatalf("the second page was behind an empty cursor, got %d tool(s)", len(capture.Tools))
	}
}

// Reaching the last page says the traversal finished, not that the pages came
// from one state of the server.
func TestASurfaceThatMovesBetweenPassesIsNotComplete(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraLegacy, rounds: [][]page{
		{{tools: []string{`{"name":"a.one","description":"One."}`}, last: true}},
		{{tools: []string{
			`{"name":"a.one","description":"One."}`,
			`{"name":"a.two","description":"Added while nobody was looking."}`,
		}, last: true}},
	}}, LatestLegacyVersion, 2)
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if capture.Complete {
		t.Error("two readings saw different surfaces, so the capture is not complete")
	}
}

func TestTheStatelessWireNeedsNoHandshake(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraModern, rounds: onePage(
		`{"name":"a.one","description":"One."}`)}, FirstModernVersion, 2)
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if len(capture.Tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(capture.Tools))
	}
	// With no initialize to carry it, the name comes from the _meta of the
	// result, and the fake refuses any request whose _meta is short.
	if capture.ReportedName != "fake-mcp" {
		t.Errorf("the server names itself in every result, got %q", capture.ReportedName)
	}
}

func TestAProtocolThisBuildDoesNotSpeakIsRefused(t *testing.T) {
	if _, err := EraOf("2027-01-01"); err == nil {
		t.Error("a revision from the future was accepted")
	}
	if _, err := EraOf("2023-01-01"); err == nil {
		t.Error("a revision from before the first was accepted")
	}
	for version, want := range map[string]string{
		FirstKnownVersion:   EraLegacy,
		"2025-06-18":        EraLegacy,
		LatestLegacyVersion: EraLegacy,
		FirstModernVersion:  EraModern,
	} {
		if era, err := EraOf(version); err != nil || era != want {
			t.Errorf("%s is on the %s wire, got %q %v", version, want, era, err)
		}
	}
}

func TestAnAmbiguousToolListIsRefusedAtTheSource(t *testing.T) {
	_, err := captureFrom(t, &fake{era: EraLegacy, rounds: onePage(
		`{"name":"a.one","description":"approved","description":"malicious"}`)}, LatestLegacyVersion, 1)
	if err == nil {
		t.Fatal("a tool with two descriptions was captured")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error should say what is wrong: %v", err)
	}
}

func TestAToolListedTwiceIsNotASurface(t *testing.T) {
	_, err := captureFrom(t, &fake{era: EraLegacy, rounds: [][]page{{
		{tools: []string{`{"name":"a.one","description":"One."}`}, cursor: "page2"},
		{tools: []string{`{"name":"a.one","description":"One, again."}`}, last: true},
	}}}, LatestLegacyVersion, 1)
	if err == nil {
		t.Fatal("a tool listed on two pages was captured")
	}
}

// A tool carrying a number no digest can identify is still a tool. The
// capture's business is to record what the server said; deciding that it
// cannot be pinned is the verifier's, and an exporter that refused to capture
// it would leave the surface undescribed instead of undecidable.
func TestAToolWithAnUnpinnableNumberIsStillCaptured(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraLegacy, rounds: onePage(
		`{"name":"ledger.post","description":"Post.","inputSchema":{"maximum":1e999}}`)},
		LatestLegacyVersion, 2)
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if len(capture.Tools) != 1 {
		t.Fatalf("want the tool, got %d", len(capture.Tools))
	}
	if !capture.Complete {
		t.Error("both passes saw the same surface")
	}
}

func TestAToolWithNoNameIsRefused(t *testing.T) {
	if _, err := captureFrom(t, &fake{era: EraLegacy, rounds: onePage(`{"description":"nameless"}`)},
		LatestLegacyVersion, 1); err == nil {
		t.Fatal("a nameless tool was captured")
	}
}

func TestAServerThatStopsMidListDoesNotYieldACompleteCapture(t *testing.T) {
	capture, err := captureFrom(t, &fake{era: EraLegacy, rounds: [][]page{{
		{tools: []string{`{"name":"a.one","description":"One."}`}, cursor: "page2"},
		{hangUp: true},
	}}}, LatestLegacyVersion, 1)
	if err == nil {
		t.Fatal("a truncated list is an error")
	}
	if capture.Complete {
		t.Error("a capture that lost its connection is not complete")
	}
}

// The envelope is checked rather than assumed, because a client that reads a
// malformed answer as an answer is a client a server can steer.
func TestAMalformedEnvelopeIsRefused(t *testing.T) {
	cases := map[string]string{
		"another JSON-RPC version": `{"jsonrpc":"1.0","id":%s,"result":{"tools":[]}}`,
		"both a result and an error": `{"jsonrpc":"2.0","id":%s,"result":{"tools":[]},` +
			`"error":{"code":-1,"message":"also this"}}`,
		"neither":             `{"jsonrpc":"2.0","id":%s}`,
		"a result of no type": `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"input_required","tools":[]}}`,
		"a duplicated member": `{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"tools":[]}}`,
	}
	for name, answer := range cases {
		client, remote := net.Pipe()
		go func() {
			defer remote.Close()
			reader := bufio.NewReader(remote)
			for {
				line, err := reader.ReadBytes('\n')
				if len(line) == 0 && err != nil {
					return
				}
				var incoming struct {
					ID *json.Number `json:"id"`
				}
				json.Unmarshal(line, &incoming)
				fmt.Fprintf(remote, answer+"\n", incoming.ID)
				if err != nil {
					return
				}
			}
		}()
		session, err := NewSession(client, client, FirstModernVersion, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.ListTools(); err == nil {
			t.Errorf("%s was accepted", name)
		}
		client.Close()
	}
}
