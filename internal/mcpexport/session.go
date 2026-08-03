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
	"sort"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

// maxMessageBytes bounds one message from the server. A server that never
// sends a newline is a server that would otherwise fill this process's memory.
const maxMessageBytes = 16 << 20

// maxPages bounds the tools/list cursor loop. A server that always returns a
// cursor would otherwise capture forever.
const maxPages = 1000

// MCP has two wire eras, and which one a version belongs to decides whether a
// session opens with a handshake or carries its context on every request.
//
//   - legacy, 2024-10-07 through 2025-11-25: initialize, then
//     notifications/initialized, then requests.
//   - modern, from 2026-07-28: no handshake at all. The protocol version, the
//     client info and the client capabilities travel in _meta on every request,
//     and the server names itself in the _meta of every result.
const (
	EraLegacy = "legacy"
	EraModern = "modern"

	// LatestLegacyVersion is the last revision that opens with a handshake.
	LatestLegacyVersion = "2025-11-25"
	// FirstModernVersion is the first stateless revision.
	FirstModernVersion = "2026-07-28"
	// FirstKnownVersion is the oldest revision this build will speak to.
	FirstKnownVersion = "2024-10-07"
)

// Reserved _meta keys, from the specification.
const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// EraOf says how to speak a protocol version, and refuses the ones this build
// has not been written against. Guessing at a revision it does not know would
// produce a capture that looks like a surface and is an artefact of a wrong
// wire format.
func EraOf(version string) (string, error) {
	switch {
	case version == FirstModernVersion:
		return EraModern, nil
	case version >= FirstKnownVersion && version <= LatestLegacyVersion:
		// The revisions in this range share one wire behaviour, so a version
		// this build has not heard of but which falls inside it is safe to
		// speak to. Version strings are dates, so this is a date comparison.
		return EraLegacy, nil
	default:
		return "", fmt.Errorf("this build does not know protocol version %q; it speaks %s through %s and %s",
			version, FirstKnownVersion, LatestLegacyVersion, FirstModernVersion)
	}
}

// Session is one conversation with a server over a pair of pipes.
type Session struct {
	to            io.Writer
	from          *bufio.Reader
	nextID        int
	era           string
	protocol      string
	clientVersion string
	// reportedName is what the server called itself, from the initialize
	// result or from the _meta of any result. The specification says this is
	// self-reported and must not drive a security decision, which is exactly
	// why mcppin records it beside the identity rather than as it.
	reportedName string
}

// NewSession talks to a server through to and from.
func NewSession(to io.Writer, from io.Reader, protocol, clientVersion string) (*Session, error) {
	era, err := EraOf(protocol)
	if err != nil {
		return nil, err
	}
	return &Session{
		to:            to,
		from:          bufio.NewReaderSize(from, 64<<10),
		era:           era,
		protocol:      protocol,
		clientVersion: clientVersion,
	}, nil
}

// Era says which wire behaviour this session uses.
func (s *Session) Era() string { return s.era }

type request struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      *int           `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// Call sends a request and returns the result of the response carrying its id.
//
// Anything else on the way is skipped: a server may log through
// notifications/message or send requests of its own, and a client that treated
// the next line as its answer would be trivial to desynchronise. The envelope
// is checked rather than assumed - the version, the id, and exactly one of
// result and error - because a client that reads a malformed answer as an
// answer is a client a server can steer.
func (s *Session) Call(method string, params map[string]any) (map[string]any, error) {
	s.nextID++
	id := s.nextID
	if err := s.send(request{JSONRPC: "2.0", ID: &id, Method: method, Params: s.withMeta(params)}); err != nil {
		return nil, err
	}
	for {
		message, err := s.receive()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		// Decoded strictly: a response naming one member twice is one this
		// build refuses to read, here as everywhere else.
		decoded, err := mcppin.DecodeJSON(message)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		envelope, ok := decoded.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: a message is not a JSON object", method)
		}
		if version, _ := envelope["jsonrpc"].(string); version != "2.0" {
			return nil, fmt.Errorf("%s: a message is JSON-RPC %q, not 2.0", method, version)
		}
		if _, isRequest := envelope["method"]; isRequest {
			continue // a notification, or a request of the server's own
		}
		answerID, ok := envelope["id"].(json.Number)
		if !ok || answerID.String() != fmt.Sprint(id) {
			continue
		}

		_, hasResult := envelope["result"]
		rawError, hasError := envelope["error"]
		if hasResult == hasError {
			return nil, fmt.Errorf("%s: the answer carries %s", method,
				map[bool]string{true: "both a result and an error", false: "neither a result nor an error"}[hasResult])
		}
		if hasError {
			return nil, describeError(method, rawError)
		}
		result, ok := envelope["result"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: the result is not an object", method)
		}
		if err := s.readResult(result); err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		return result, nil
	}
}

// readResult checks what every result carries and harvests what the server
// says about itself.
func (s *Session) readResult(result map[string]any) error {
	// An absent resultType means a server on an earlier revision, where the
	// only outcome was completion. Anything else - a request for more input,
	// an extension's own type - is not a page of tools, and reading it as one
	// would capture a surface that was never served.
	if kind, present := result["resultType"]; present {
		text, ok := kind.(string)
		if !ok || text != "complete" {
			return fmt.Errorf("the result is of type %v, which this build cannot read as an answer", kind)
		}
	}
	meta, ok := result["_meta"].(map[string]any)
	if !ok {
		return nil
	}
	info, ok := meta[metaServerInfo].(map[string]any)
	if !ok {
		return nil
	}
	if name, ok := info["name"].(string); ok && name != "" {
		s.reportedName = name
	}
	return nil
}

// withMeta adds the per-request metadata a stateless session needs. On the
// legacy wire the same information was exchanged once, at initialize.
func (s *Session) withMeta(params map[string]any) map[string]any {
	if s.era != EraModern {
		return params
	}
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		metaProtocolVersion: s.protocol,
		metaClientInfo:      map[string]any{"name": "mcppin-export", "version": s.clientVersion},
		// Required, and empty on purpose: this client asks for tool
		// definitions and offers the server nothing to call back into.
		metaClientCapabilities: map[string]any{},
	}
	return params
}

func describeError(method string, raw any) error {
	failure, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: the server answered with a malformed error", method)
	}
	code, _ := failure["code"].(json.Number)
	message, _ := failure["message"].(string)
	// The message is the server's text and lands in a terminal, so it is
	// rendered rather than passed through.
	return fmt.Errorf("%s: the server answered %s: %s", method, code, mcppin.Printable(message))
}

// Notify sends a notification, which has no id and no answer.
func (s *Session) Notify(method string, params map[string]any) error {
	return s.send(request{JSONRPC: "2.0", Method: method, Params: s.withMeta(params)})
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
	// Complete is what every statement about absence rests on, so it is set
	// from what happened. It is false when two traversals of the tool list did
	// not see the same surface.
	Complete bool
	Passes   int
}

// Handshake opens the session, on the wires that have one.
func (s *Session) Handshake() error {
	if s.era == EraModern {
		// There is nothing to open. The protocol is stateless: every request
		// carries what initialize used to carry once.
		return nil
	}
	result, err := s.Call("initialize", map[string]any{
		"protocolVersion": s.protocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcppin-export", "version": s.clientVersion},
	})
	if err != nil {
		return err
	}
	negotiated, _ := result["protocolVersion"].(string)
	if negotiated == "" {
		return errors.New("initialize: the server named no protocol version")
	}
	if _, err := EraOf(negotiated); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	s.protocol = negotiated
	if info, ok := result["serverInfo"].(map[string]any); ok {
		if name, ok := info["name"].(string); ok {
			s.reportedName = name
		}
	}
	return s.Notify("notifications/initialized", map[string]any{})
}

// ListTools reads every page of tools/list.
func (s *Session) ListTools() ([]map[string]any, error) {
	var tools []map[string]any
	names := make(map[string]bool)
	requested := make(map[string]bool)
	cursor, first := "", true
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("tools/list: still paginating after %d pages", maxPages)
		}
		params := map[string]any{}
		if !first {
			// A cursor asked for twice is a loop, and the empty string is a
			// cursor like any other, so the guard is on what was requested and
			// not on the value.
			if requested[cursor] {
				return nil, errors.New("tools/list: the server gave back a cursor it had already given")
			}
			requested[cursor] = true
			params["cursor"] = cursor
		}
		first = false

		result, err := s.Call("tools/list", params)
		if err != nil {
			return nil, err
		}
		listed, next, present, err := readToolPage(result)
		if err != nil {
			return nil, err
		}
		for _, tool := range listed {
			name, _ := tool["name"].(string)
			// A name arriving twice means the pages did not come from one
			// state, or the server is repeating itself. Either way the list is
			// not a surface.
			if names[name] {
				return nil, fmt.Errorf("tools/list: %s was listed twice", mcppin.Printable(name))
			}
			names[name] = true
			tools = append(tools, tool)
		}
		if !present {
			return tools, nil
		}
		cursor = next
	}
}

// CaptureSurface runs the handshake and reads the tool list, twice by default.
//
// Reaching the last page proves that the traversal finished, and not that the
// pages came from one state: MCP does not promise that a list is a snapshot,
// so a server free to change between two requests can hide a tool at a page
// boundary. A second traversal that sees the same surface does not prove a
// snapshot either - a server can change and change back - but it is the
// difference between a claim nobody checked and one that survived being
// checked once.
func CaptureSurface(session *Session, passes int) (Capture, error) {
	capture := Capture{Passes: passes}
	if err := session.Handshake(); err != nil {
		return capture, err
	}

	previous := ""
	for pass := 0; pass < passes; pass++ {
		tools, err := session.ListTools()
		if err != nil {
			return capture, err
		}
		digest, err := surfaceDigest(tools)
		if err != nil {
			return capture, err
		}
		if pass == 0 {
			capture.Tools = tools
			previous = digest
			capture.Complete = true
			continue
		}
		if digest != previous {
			capture.Complete = false
			break
		}
	}
	capture.ProtocolVersion = session.protocol
	capture.ReportedName = session.reportedName
	return capture, nil
}

// surfaceDigest is the identity of a whole tool list, ordered by name so that
// two traversals which merely paginated differently still agree.
func surfaceDigest(tools []map[string]any) (string, error) {
	ordered := make([]any, 0, len(tools))
	for _, tool := range tools {
		ordered = append(ordered, tool)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, _ := ordered[i].(map[string]any)["name"].(string)
		right, _ := ordered[j].(map[string]any)["name"].(string)
		return left < right
	})
	return mcppin.Digest(ordered)
}

// readToolPage decodes one page. The tools are kept as the objects they
// arrived as, because the digest covers everything the server said.
//
// The cursor is returned with whether it was there at all: the specification
// is explicit that an empty string is a valid cursor and must not be read as
// the end of the results, and a client that stopped on one would write a
// truncated surface and call it complete.
func readToolPage(result map[string]any) (tools []map[string]any, cursor string, present bool, err error) {
	rawTools, ok := result["tools"].([]any)
	if !ok {
		return nil, "", false, errors.New("tools/list: the result has no tools array")
	}
	tools = make([]map[string]any, 0, len(rawTools))
	for i, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			return nil, "", false, fmt.Errorf("tools/list: tool %d is not an object", i+1)
		}
		if name, _ := tool["name"].(string); name == "" {
			return nil, "", false, fmt.Errorf("tools/list: tool %d has no name", i+1)
		}
		tools = append(tools, tool)
	}

	raw, exists := result["nextCursor"]
	if !exists || raw == nil {
		return tools, "", false, nil
	}
	cursor, ok = raw.(string)
	if !ok {
		return nil, "", false, errors.New("tools/list: nextCursor is not a string")
	}
	return tools, cursor, true, nil
}
