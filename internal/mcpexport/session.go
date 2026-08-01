// JSON-RPC over the MCP stdio transport: one JSON message per line, no
// framing headers.
//
// This package is where mcppin speaks a protocol, and it is a separate package
// and a separate binary for that reason. The verifier compares two files and
// talks to nobody; putting a client inside it would mean the thing that says
// "this surface is approved" is also the thing an untrusted server gets to
// answer.
package mcpexport

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

// maxMessageBytes bounds one message from the server. A server that never
// sends a newline is a server that would otherwise fill this process's memory.
const maxMessageBytes = 16 << 20

// maxPages bounds the tools/list cursor loop. A server that always returns a
// cursor would otherwise capture forever; the capture is marked incomplete
// instead.
const maxPages = 1000

// Session is one conversation with a server over a pair of pipes.
type Session struct {
	to     io.Writer
	from   *bufio.Reader
	nextID int
}

// NewSession talks to a server through to and from.
func NewSession(to io.Writer, from io.Reader) *Session {
	return &Session{to: to, from: bufio.NewReaderSize(from, 64<<10)}
}

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type response struct {
	ID     *json.Number    `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Call sends a request and returns the result of the response carrying its id.
//
// Anything else on the way is skipped: a server may log through
// notifications/message or send requests of its own, and a client that treated
// the next line as its answer would be trivial to desynchronise.
func (s *Session) Call(method string, params any) (json.RawMessage, error) {
	s.nextID++
	id := s.nextID
	if err := s.send(request{JSONRPC: "2.0", ID: &id, Method: method, Params: params}); err != nil {
		return nil, err
	}
	for {
		message, err := s.receive()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		var answer response
		if err := json.Unmarshal(message, &answer); err != nil || answer.ID == nil {
			continue // a notification, or a request from the server
		}
		if answer.ID.String() != fmt.Sprint(id) {
			continue
		}
		if answer.Error != nil {
			return nil, fmt.Errorf("%s: the server answered %d: %s",
				method, answer.Error.Code, answer.Error.Message)
		}
		return answer.Result, nil
	}
}

// Notify sends a notification, which has no id and no answer.
func (s *Session) Notify(method string, params any) error {
	return s.send(request{JSONRPC: "2.0", Method: method, Params: params})
}

func (s *Session) send(message request) error {
	encoded, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := s.to.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *Session) receive() ([]byte, error) {
	var line []byte
	for {
		chunk, err := s.from.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxMessageBytes {
			return nil, fmt.Errorf("a message went past %d bytes without a newline", maxMessageBytes)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) == 0 {
				return nil, errors.New("the server closed the connection without answering")
			}
			if !errors.Is(err, io.EOF) {
				return nil, err
			}
		}
		if len(line) > 0 {
			return line, nil
		}
	}
}

// Capture is what one server said about itself and its tools.
type Capture struct {
	ProtocolVersion string
	ReportedName    string
	Tools           []map[string]any
	// Complete is false when the cursor loop did not reach the end. Every
	// statement mcppin makes about absence depends on this being true, so it is
	// set from what happened and never assumed.
	Complete bool
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name string `json:"name"`
	} `json:"serverInfo"`
}

// CaptureSurface runs the handshake and reads every page of tools/list.
func CaptureSurface(session *Session, protocolVersion, clientVersion string) (Capture, error) {
	var capture Capture

	raw, err := session.Call("initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcppin-export", "version": clientVersion},
	})
	if err != nil {
		return capture, err
	}
	var initialized initializeResult
	if err := json.Unmarshal(raw, &initialized); err != nil {
		return capture, fmt.Errorf("initialize: the result is not an object this build understands: %w", err)
	}
	capture.ProtocolVersion = initialized.ProtocolVersion
	if capture.ProtocolVersion == "" {
		return capture, errors.New("initialize: the server named no protocol version")
	}
	capture.ReportedName = initialized.ServerInfo.Name

	if err := session.Notify("notifications/initialized", map[string]any{}); err != nil {
		return capture, err
	}

	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, err := session.Call("tools/list", params)
		if err != nil {
			return capture, err
		}
		tools, next, err := readToolPage(raw)
		if err != nil {
			return capture, err
		}
		capture.Tools = append(capture.Tools, tools...)
		if next == "" {
			capture.Complete = true
			return capture, nil
		}
		if next == cursor {
			return capture, errors.New("tools/list: the server returned the same cursor twice")
		}
		cursor = next
	}
	return capture, fmt.Errorf("tools/list: stopped after %d pages", maxPages)
}

// readToolPage decodes one page strictly. The tools are kept as the objects
// they arrived as, because the digest covers everything the server said, and
// they are read by the same strict decoder the verifier uses: a server whose
// answer is ambiguous is caught where it is served rather than after it has
// been written into a manifest.
func readToolPage(raw json.RawMessage) ([]map[string]any, string, error) {
	value, err := mcppin.DecodeJSON(raw)
	if err != nil {
		return nil, "", fmt.Errorf("tools/list: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, "", errors.New("tools/list: the result is not an object")
	}
	rawTools, ok := object["tools"].([]any)
	if !ok {
		return nil, "", errors.New("tools/list: the result has no tools array")
	}
	tools := make([]map[string]any, 0, len(rawTools))
	for i, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("tools/list: tool %d is not an object", i+1)
		}
		if name, _ := tool["name"].(string); name == "" {
			return nil, "", fmt.Errorf("tools/list: tool %d has no name", i+1)
		}
		tools = append(tools, tool)
	}
	cursor, _ := object["nextCursor"].(string)
	return tools, cursor, nil
}
