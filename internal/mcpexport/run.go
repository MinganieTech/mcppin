package mcpexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

// defaultProtocolVersion is what this build asks a server to speak.
//
// It is the last revision that opens with the initialize handshake, and not
// the newest revision, because that is what the servers in the field speak
// today. Ask for 2026-07-28 with -protocol and the session switches to the
// stateless wire; either way the manifest records what the server answered,
// not what was asked for.
const defaultProtocolVersion = LatestLegacyVersion

// defaultPasses is how many times the tool list is read.
//
// Reaching the last page proves the traversal finished, not that the pages
// came from one state of the server. Two traversals that see the same surface
// do not prove a snapshot either, but they are the difference between a claim
// nobody checked and one that survived a check.
const defaultPasses = 2

// Exit codes mirror mcppin's, so a pipeline branches the same way on both.
const (
	exitOK          = 0
	exitUsage       = 2
	exitIncomplete  = 3
	exitUnreachable = 4
)

// maxServerLogLines bounds what a server's own standard error is allowed to
// put in ours. Its diagnostics are useful when it fails to start and are not
// worth an unbounded log.
const maxServerLogLines = 40

type manifestDocument struct {
	SchemaVersion   int              `json:"schema_version"`
	ProtocolVersion string           `json:"protocol_version"`
	Complete        bool             `json:"complete"`
	CapturedAt      string           `json:"captured_at"`
	CapturedBy      string           `json:"captured_by"`
	Servers         []serverDocument `json:"servers"`
}

type serverDocument struct {
	ID string `json:"id"`
	// ReportedName is what the server called itself. It is recorded next to
	// the identity, never as it - the specification is explicit that this is
	// self-reported and must not drive a security decision.
	ReportedName string `json:"reported_name,omitempty"`
	// ProtocolVersion is what this server negotiated, which two servers in one
	// capture are free to disagree about.
	ProtocolVersion string `json:"protocol_version,omitempty"`
	// Passes is how many times the tool list was read and agreed with itself.
	Passes int              `json:"passes"`
	Tools  []map[string]any `json:"tools"`
}

func usage(stderr io.Writer) {
	fmt.Fprintf(stderr, "usage: mcppin-export -config mcp.json [flags]\n\n")
	fmt.Fprintf(stderr, "Capture the tool surface of the stdio servers a configuration declares,\n")
	fmt.Fprintf(stderr, "and write the manifest mcppin verifies.\n\n")
	fmt.Fprintf(stderr, "This runs the commands in that configuration. It is exactly as trusted as\n")
	fmt.Fprintf(stderr, "the client whose configuration it reads, and no more.\n\n")
	fmt.Fprintf(stderr, "exit codes: 0 captured, 2 usage, 3 captured but incomplete, 4 a server could\n")
	fmt.Fprintf(stderr, "not be reached\n\nflags:\n")
}

// Main runs the command line and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "the client configuration to read (required)")
	output := fs.String("o", "", "write the manifest here instead of standard output")
	only := fs.String("server", "", "capture only this server id")
	protocol := fs.String("protocol", defaultProtocolVersion, "the protocol version to ask for")
	passes := fs.Int("passes", defaultPasses, "how many times to read each tool list")
	timeout := fs.Duration("timeout", 30*time.Second, "how long one server has to answer")
	fs.Usage = func() {
		usage(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *configPath == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if *passes < 1 {
		fmt.Fprintf(stderr, "mcppin-export: -passes is %d; the list has to be read at least once\n", *passes)
		return exitUsage
	}
	era, err := EraOf(*protocol)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin-export: %v\n", err)
		return exitUsage
	}
	if *passes == 1 {
		fmt.Fprintf(stderr, "warning: one pass cannot see a tool list that changed while it was "+
			"being read; complete will say the traversal finished and no more\n")
	}

	servers, err := ReadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin-export: %v\n", err)
		return exitUnreachable
	}
	if *only != "" {
		servers = filterByID(servers, *only)
		if len(servers) == 0 {
			fmt.Fprintf(stderr, "mcppin-export: %s declares no server %q\n",
				*configPath, mcppin.Printable(*only))
			return exitUsage
		}
		// The manifest that comes out covers one server. Verified against a
		// lockfile that covers more, every other approved tool reads as
		// removed - loudly, but for the wrong reason.
		fmt.Fprintf(stderr, "warning: this manifest covers %s alone; verify it against a lockfile "+
			"of the same scope\n", mcppin.Printable(*only))
	}

	document := manifestDocument{
		SchemaVersion:   mcppin.ManifestSchemaVersion,
		ProtocolVersion: *protocol,
		Complete:        true,
		CapturedAt:      time.Now().UTC().Format(time.RFC3339),
		CapturedBy:      "mcppin-export/" + mcppin.Version,
	}
	for _, server := range servers {
		fmt.Fprintf(stderr, "mcppin-export: capturing %s over the %s wire\n", server.ID, era)
		capture, err := captureServer(server, *protocol, *passes, *timeout, stderr)
		if err != nil {
			// A server that could not be captured is not a smaller surface, it
			// is an unknown one. Writing the others would produce a manifest
			// whose every missing tool looks like a removal.
			fmt.Fprintf(stderr, "mcppin-export: %s: %v\n", server.ID, err)
			return exitUnreachable
		}
		if !capture.Complete {
			fmt.Fprintf(stderr, "mcppin-export: %s: two readings of the tool list did not agree; "+
				"the surface changed while it was being captured\n", server.ID)
			document.Complete = false
		}
		document.Servers = append(document.Servers, serverDocument{
			ID:              server.ID,
			ReportedName:    capture.ReportedName,
			ProtocolVersion: capture.ProtocolVersion,
			Passes:          capture.Passes,
			Tools:           capture.Tools,
		})
	}
	sort.Slice(document.Servers, func(i, j int) bool { return document.Servers[i].ID < document.Servers[j].ID })

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "mcppin-export: %v\n", err)
		return exitUnreachable
	}
	encoded = append(encoded, '\n')
	// The manifest is read back before it is handed over. Writing one this
	// project's own reader refuses would move a server's malformed answer into
	// a file somebody trusts, and turn a capture failure into a verify failure
	// on a different day.
	if _, err := mcppin.ReadManifest(bytes.NewReader(encoded)); err != nil {
		fmt.Fprintf(stderr, "mcppin-export: the captured manifest does not read back: %v\n", err)
		return exitUnreachable
	}

	if *output == "" {
		_, err = stdout.Write(encoded)
	} else {
		err = mcppin.WriteFileAtomically(*output, func(w io.Writer) error {
			_, err := w.Write(encoded)
			return err
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcppin-export: %v\n", err)
		return exitUnreachable
	}
	if !document.Complete {
		return exitIncomplete
	}
	return exitOK
}

func filterByID(servers []ServerConfig, id string) []ServerConfig {
	for _, server := range servers {
		if server.ID == id {
			return []ServerConfig{server}
		}
	}
	return nil
}

// captureServer runs one server and reads its surface. The process is killed
// when the deadline passes rather than left behind: this is a capture, not a
// client, and it holds nothing open once it has its answer.
func captureServer(config ServerConfig, protocol string, passes int, timeout time.Duration, stderr io.Writer) (Capture, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.CommandContext(ctx, config.Command, config.Args...)
	command.Env = os.Environ()
	for _, key := range sortedKeys(config.Env) {
		command.Env = append(command.Env, key+"="+config.Env[key])
	}

	to, err := command.StdinPipe()
	if err != nil {
		return Capture{}, err
	}
	from, err := command.StdoutPipe()
	if err != nil {
		return Capture{}, err
	}
	diagnostics, err := command.StderrPipe()
	if err != nil {
		return Capture{}, err
	}
	if err := command.Start(); err != nil {
		return Capture{}, fmt.Errorf("%s could not be started: %w", config.Command, err)
	}

	var logging sync.WaitGroup
	logging.Add(1)
	go func() {
		defer logging.Done()
		forward(diagnostics, stderr, config.ID)
	}()

	session, err := NewSession(to, from, protocol, mcppin.Version)
	if err != nil {
		command.Process.Kill()
		command.Wait()
		return Capture{}, err
	}
	capture, captureErr := CaptureSurface(session, passes)

	to.Close()
	if captureErr != nil {
		// The deadline is the likely reason a read failed, and it is worth
		// saying so rather than reporting a closed pipe.
		if ctx.Err() != nil {
			captureErr = fmt.Errorf("%w (the %s deadline passed)", captureErr, timeout)
		}
		_ = command.Process.Kill()
	}
	logging.Wait()
	_ = command.Wait()
	return capture, captureErr
}

// forward relays what a server writes to its own standard error, rendered.
// Those bytes are the server's, they land in the operator's terminal, and a
// line of them can carry an escape sequence that erases the warning above it.
func forward(from io.Reader, to io.Writer, id string) {
	scanner := bufio.NewScanner(from)
	for line := 0; line < maxServerLogLines && scanner.Scan(); line++ {
		fmt.Fprintf(to, "  [%s] %s\n", mcppin.Printable(id), mcppin.Printable(scanner.Text()))
	}
	io.Copy(io.Discard, from)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
