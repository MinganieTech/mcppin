package mcppin

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Version is declared here and nowhere else.
const Version = "0.1.0"

// Exit codes are a public contract: CI pipelines branch on them, so changing
// one is a breaking change. The distinction that matters is 1 against 3 - a
// digest that cannot be reproduced must never be indistinguishable from a
// digest that matched.
const (
	ExitOK           = 0 // every requested policy holds
	ExitPolicyFailed = 1 // a departure from the approved surface was proven
	ExitUsage        = 2 // the command line is wrong
	ExitUndecidable  = 3 // a digest is not reproducible
	ExitUnreadable   = 4 // an input could not be read
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func usage(stderr io.Writer) {
	fmt.Fprintf(stderr, "usage: mcppin <command> [flags] <manifest.json>\n\n")
	fmt.Fprintf(stderr, "Pin the tool surface an agent was approved to see, and refuse the drift.\n\n")
	fmt.Fprintf(stderr, "commands:\n")
	fmt.Fprintf(stderr, "  lock     write the lockfile for the manifest as it stands\n")
	fmt.Fprintf(stderr, "  verify   compare the manifest against a lockfile\n\n")
	fmt.Fprintf(stderr, "exit codes: 0 clean, 1 violation proven, 2 usage, 3 undecidable, 4 unreadable input\n")
}

// Main runs the command line and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "lock":
		return runLock(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "-version", "--version":
		fmt.Fprintf(stdout, "mcppin %s\n", Version)
		return ExitOK
	case "-h", "--help", "help":
		usage(stderr)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "mcppin: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func runLock(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin lock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("o", "", "write the lockfile here instead of standard output")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: mcppin lock [-o mcp.lock.json] <manifest.json>\n\n")
		fmt.Fprintf(stderr, "What can be seen in the manifest itself is reported on standard error,\n")
		fmt.Fprintf(stderr, "and the lockfile is written anyway: you cannot fix what you have not\n")
		fmt.Fprintf(stderr, "pinned. Run verify to turn those observations into a gate.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ExitUsage
	}

	manifest, err := LoadManifest(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	inspection := Inspect(manifest)
	for _, finding := range inspection.Findings {
		fmt.Fprintf(stderr, "warning: %s: %s\n", finding.Policy, finding.Detail)
	}

	lock, err := BuildLock(manifest)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	writer := stdout
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
		defer file.Close()
		writer = file
	}
	if err := WriteLock(writer, lock); err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	// Pinning a tool whose digest is not reproducible produces a lockfile that
	// will drift on its own. The file is still written, and the exit code says
	// the pin cannot be trusted.
	if len(inspection.Unstable) > 0 {
		for _, unstable := range inspection.Unstable {
			fmt.Fprintf(stderr, "mcppin: %s %s carries %s, which float64 does not hold exactly\n",
				unstable.Server, unstable.Tool, strings.Join(unstable.Literals, ", "))
		}
		return ExitUndecidable
	}
	return ExitOK
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockPath := fs.String("lock", "", "the approved lockfile (required)")
	var failOn stringList
	fs.Var(&failOn, "fail-on", "policy that must hold, repeatable")
	asJSON := fs.Bool("json", false, "emit the machine-readable report instead of text")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: mcppin verify -lock mcp.lock.json [flags] <manifest.json>\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\npolicies accepted by -fail-on:\n")
		for _, p := range Policies() {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *lockPath == "" || fs.NArg() != 1 {
		fs.Usage()
		return ExitUsage
	}
	for _, policy := range failOn {
		if !validPolicy(policy) {
			fmt.Fprintf(stderr, "mcppin: unknown policy %q; accepted: %s\n",
				policy, strings.Join(Policies(), ", "))
			return ExitUsage
		}
	}

	manifest, err := LoadManifest(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	lock, err := LoadLock(*lockPath)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	result, err := Verify(manifest, lock)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	if *asJSON {
		if err := WriteJSON(stdout, result); err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
	} else {
		WriteText(stdout, result, failOn)
	}

	for _, policy := range failOn {
		if len(result.FindingsFor(policy)) > 0 {
			return ExitPolicyFailed
		}
	}
	if len(result.Unstable) > 0 {
		return ExitUndecidable
	}
	return ExitOK
}
