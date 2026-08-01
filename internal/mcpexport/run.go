package mcpexport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

// defaultProtocolVersion is what this build asks a server to speak. The server
// answers with the version it will actually use, and that answer is what the
// manifest records.
const defaultProtocolVersion = "2026-07-28"

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
	// the identity, never as it.
	ReportedName string `json:"reported_name,omitempty"`
	// ProtocolVersion is what this server negotiated, which two servers in one
	// capture are free to disagree about.
	ProtocolVersion string           `json:"protocol_version,omitempty"`
	Tools           []map[string]any `json:"tools"`
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

	servers, err := ReadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin-export: %v\n", err)
		return exitUnreachable
	}
	if *only != "" {
		servers = filterByID(servers, *only)
		if len(servers) == 0 {
			fmt.Fprintf(stderr, "mcppin-export: %s declares no server %q\n", *configPath, *only)
			return exitUsage
		}
	}

	document := manifestDocument{
		SchemaVersion:   mcppin.ManifestSchemaVersion,
		ProtocolVersion: *protocol,
		Complete:        true,
		CapturedAt:      time.Now().UTC().Format(time.RFC3339),
		CapturedBy:      "mcppin-export/" + mcppin.Version,
	}
	for _, server := range servers {
		fmt.Fprintf(stderr, "mcppin-export: capturing %s\n", server.ID)
		capture, err := captureServer(server, *protocol, *timeout, stderr)
		if err != nil {
			// A server that could not be captured is not a smaller surface, it
			// is an unknown one. Writing the others would produce a manifest
			// whose every missing tool looks like a removal.
			fmt.Fprintf(stderr, "mcppin-export: %s: %v\n", server.ID, err)
			return exitUnreachable
		}
		if !capture.Complete {
			fmt.Fprintf(stderr, "mcppin-export: %s: the tool list was not read to the end\n", server.ID)
			document.Complete = false
		}
		document.Servers = append(document.Servers, serverDocument{
			ID:              server.ID,
			ReportedName:    capture.ReportedName,
			ProtocolVersion: capture.ProtocolVersion,
			Tools:           capture.Tools,
		})
	}
	sort.Slice(document.Servers, func(i, j int) bool { return document.Servers[i].ID < document.Servers[j].ID })

	emit := func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		return encoder.Encode(document)
	}
	if *output == "" {
		err = emit(stdout)
	} else {
		err = mcppin.WriteFileAtomically(*output, emit)
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
func captureServer(config ServerConfig, protocol string, timeout time.Duration, stderr io.Writer) (Capture, error) {
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

	capture, captureErr := CaptureSurface(NewSession(to, from), protocol, mcppin.Version)

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

func forward(from io.Reader, to io.Writer, id string) {
	scanner := bufio.NewScanner(from)
	for line := 0; line < maxServerLogLines && scanner.Scan(); line++ {
		fmt.Fprintf(to, "  [%s] %s\n", id, strings.TrimRight(scanner.Text(), "\r"))
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
