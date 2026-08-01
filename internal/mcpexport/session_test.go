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

// serve answers one conversation the way a well-behaved server would, and
// takes the chance to be noisy about it: a log notification before the answer,
// and an answer to an id nobody asked for. A client that read the next line as
// its answer would be desynchronised by either.
func serve(connection io.ReadWriter, pages [][]string) error {
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return nil
		}
		var incoming struct {
			ID     *json.Number `json:"id"`
			Method string       `json:"method"`
		}
		if err := json.Unmarshal(line, &incoming); err != nil {
			return err
		}
		switch incoming.Method {
		case "initialize":
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`+"\n")
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":9999,"result":{"ignored":true}}`+"\n")
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2026-07-28",`+
				`"capabilities":{},"serverInfo":{"name":"fake-mcp","version":"1.0.0"}}}`+"\n", incoming.ID)
		case "notifications/initialized":
		case "tools/list":
			if len(pages) == 0 || pages[0] == nil {
				return nil // a nil page means the server hangs up mid-list
			}
			page := pages[0]
			pages = pages[1:]
			cursor := ""
			if len(pages) > 0 {
				cursor = fmt.Sprintf(`,"nextCursor":"page%d"`, len(pages))
			}
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[%s]%s}}`+"\n",
				incoming.ID, strings.Join(page, ","), cursor)
		default:
			fmt.Fprintf(connection, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`+"\n",
				incoming.ID)
		}
		if err != nil {
			return nil
		}
	}
}

func captureAgainst(t *testing.T, pages [][]string) (Capture, error) {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if err := serve(server, pages); err != nil {
			t.Errorf("the fake server failed: %v", err)
		}
	}()
	defer client.Close()
	return CaptureSurface(NewSession(client, client), "2026-07-28", "test")
}

func TestACaptureFollowsTheCursorToTheEnd(t *testing.T) {
	capture, err := captureAgainst(t, [][]string{
		{`{"name":"a.one","description":"One."}`},
		{`{"name":"a.two","description":"Two."}`, `{"name":"a.three","description":"Three."}`},
	})
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	if !capture.Complete {
		t.Error("every page was read, so the capture is complete")
	}
	if len(capture.Tools) != 3 {
		t.Fatalf("want 3 tools, got %d", len(capture.Tools))
	}
	if capture.ReportedName != "fake-mcp" {
		t.Errorf("the server calls itself %q", capture.ReportedName)
	}
	if capture.ProtocolVersion != "2026-07-28" {
		t.Errorf("the manifest records the version the server answered, got %q", capture.ProtocolVersion)
	}
}

// The capture is what every statement about absence rests on, so a page that
// never arrives has to make it false rather than shorten it quietly.
func TestAServerThatStopsMidListDoesNotYieldACompleteCapture(t *testing.T) {
	capture, err := captureAgainst(t, [][]string{
		{`{"name":"a.one","description":"One."}`},
		nil, // the server hangs up instead of answering the second page
	})
	if err == nil {
		t.Fatal("a truncated list is an error")
	}
	if capture.Complete {
		t.Error("a capture that lost its connection is not complete")
	}
}

func TestAnAmbiguousToolListIsRefusedAtTheSource(t *testing.T) {
	_, err := captureAgainst(t, [][]string{
		{`{"name":"a.one","description":"approved","description":"malicious"}`},
	})
	if err == nil {
		t.Fatal("a tool with two descriptions was captured")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error should say what is wrong: %v", err)
	}
}

func TestAToolWithNoNameIsRefused(t *testing.T) {
	if _, err := captureAgainst(t, [][]string{{`{"description":"nameless"}`}}); err == nil {
		t.Fatal("a nameless tool was captured")
	}
}
