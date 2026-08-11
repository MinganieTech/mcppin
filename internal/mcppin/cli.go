package mcppin

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Version is declared here and nowhere else. The release workflow refuses a
// tag that disagrees with it.
//
// Below 1.0 the formats are still moving: the manifest, the lockfile and the
// JSON report each carry their own schema version, and a build says which ones
// it reads. What will not move quietly is the exit codes.
const Version = "0.2.1"

// now and stdin are variables so a test can pin the moment a signature was
// made and feed a key in without reaching for the process's own input.
var (
	now             = time.Now
	stdin io.Reader = os.Stdin
)

// Exit codes are a public contract: CI pipelines branch on them, so changing
// one is a breaking change. The distinction that matters is 1 against 3 - a
// digest that cannot be reproduced must never be indistinguishable from a
// digest that matched.
//
// When a run earns more than one of them, the strongest statement wins: 1
// outranks 3, because an undecidable digest can only hide a departure, never
// invent one, so a departure reported next to it is still proven. Both are in
// the report either way, and both fail a gate.
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
	fmt.Fprintf(stderr, "  verify   compare the manifest against a lockfile\n")
	fmt.Fprintf(stderr, "  sign     sign a lockfile, so it says who approved it\n")
	fmt.Fprintf(stderr, "  key      generate an Ed25519 signing key\n\n")
	fmt.Fprintf(stderr, "The manifest is a file. Capture one with mcppin-export, or export it from\n")
	fmt.Fprintf(stderr, "your own gateway; this command speaks to nobody.\n\n")
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
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "key":
		return runKey(args[1:], stdout, stderr)
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

	lock, err := BuildLock(manifest, 1)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	// Approving over an existing lockfile counts one past it, and counts the
	// same when the surface has not moved. Written to standard output there is
	// nothing to count from, and this is the first approval as far as the run
	// can tell.
	if *output != "" {
		lock.ApprovalSerial = SerialFor(*output, lock)
	}

	if *output == "" {
		if err := WriteLock(stdout, lock); err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
	} else {
		// What was there before is read first, so that re-locking an unchanged
		// surface does not announce a signature problem it has not caused. A
		// warning that fires when nothing happened is a warning people learn
		// to skip.
		previous, _ := os.ReadFile(*output)
		if err := WriteLockFile(*output, lock); err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
		current, _ := os.ReadFile(*output)
		// The old signature is not deleted: removing somebody's signature is
		// not this command's decision, and a stale one fails closed anyway.
		if _, err := os.Stat(SignaturePath(*output)); err == nil && !bytes.Equal(previous, current) {
			fmt.Fprintf(stderr, "warning: %s no longer matches this lockfile; sign it again\n",
				SignaturePath(*output))
		}
	}

	// A tool carrying a number the canonical form does not identify is pinned
	// as undecidable rather than given a digest that would also cover the
	// values around it. The file is still written - you cannot fix what you
	// have not pinned - and the exit code says part of it proves nothing.
	undecidable := false
	for _, unstable := range inspection.Unstable {
		fmt.Fprintf(stderr, "mcppin: %s %s carries %s, which float64 does not identify; it is pinned as undecidable\n",
			unstable.Server, unstable.Tool, strings.Join(unstable.Literals, ", "))
		undecidable = true
	}
	// Approving a partial capture pins a surface nobody saw whole: every tool
	// the exporter missed will look added the first time it appears.
	if !manifest.Complete {
		fmt.Fprintf(stderr, "mcppin: this capture says it does not hold every tool; "+
			"the lockfile approves only what was in it\n")
		undecidable = true
	}
	if undecidable {
		return ExitUndecidable
	}
	return ExitOK
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockPath := fs.String("lock", "", "the lockfile to sign (required)")
	keyPath := fs.String("key", "", "the PKCS#8 PEM private key, or - for standard input (required)")
	output := fs.String("o", "", "write the signature here instead of <lock>.sig")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: mcppin sign -lock mcp.lock.json -key signing-key.pem\n\n")
		fmt.Fprintf(stderr, "The signature is detached and covers the canonical form of the lockfile,\n")
		fmt.Fprintf(stderr, "so re-indenting the file does not break it and changing what it approves\n")
		fmt.Fprintf(stderr, "does.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *lockPath == "" || *keyPath == "" || fs.NArg() != 0 {
		fs.Usage()
		return ExitUsage
	}

	lockfile, err := os.ReadFile(*lockPath)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	// The lockfile is parsed before it is signed. Vouching for a file this
	// build cannot read would put a signature on something nobody validated.
	if _, err := ReadLock(bytes.NewReader(lockfile)); err != nil {
		fmt.Fprintf(stderr, "mcppin: %s: %v\n", *lockPath, err)
		return ExitUnreadable
	}

	pemBytes, err := readKeyMaterial(*keyPath, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	key, err := LoadPrivateKey(pemBytes)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %s: %v\n", *keyPath, err)
		return ExitUnreadable
	}

	signature, err := SignLock(lockfile, key, now())
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	path := *output
	if path == "" {
		path = SignaturePath(*lockPath)
	}
	if err := WriteFileAtomically(path, func(w io.Writer) error { return WriteSignature(w, signature) }); err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	fmt.Fprintf(stdout, "signed %s as %s\nby %s\n", *lockPath, signature.LockDigest, signature.PublicKeyFingerprint)
	return ExitOK
}

func runKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("o", "", "write the private key here, and the public key beside it (required)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: mcppin key -o signing-key.pem\n\n")
		fmt.Fprintf(stderr, "Writes an Ed25519 pair: the private key at -o, the public key at -o.pub.\n")
		fmt.Fprintf(stderr, "Neither file is overwritten if it exists. The private key is not\n")
		fmt.Fprintf(stderr, "encrypted: protect it the way you protect any other secret, and note\n")
		fmt.Fprintf(stderr, "that anyone holding it can approve any surface.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *output == "" || fs.NArg() != 0 {
		fs.Usage()
		return ExitUsage
	}

	publicPath := *output + ".pub"
	public, private, err := GenerateSigningKey()
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	privatePEM, err := EncodePrivateKey(private)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	publicPEM, err := EncodePublicKey(public)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	// Created, not written: checking for the file and then writing it leaves a
	// window in which something else creates it, and losing that race means
	// overwriting a signing key. 0600 is honoured on Unix; on Windows the
	// inherited permissions decide, so check them.
	if err := createExclusively(*output, privatePEM, 0o600); err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	if err := createExclusively(publicPath, publicPEM, 0o644); err != nil {
		// A private key with no public key beside it is a trap: the operator
		// would have no way to verify what it signs.
		os.Remove(*output)
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	fingerprint, err := Fingerprint(public)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	fmt.Fprintf(stdout, "private key %s\npublic key  %s\nfingerprint %s\n", *output, publicPath, fingerprint)
	return ExitOK
}

// createExclusively writes a file that must not exist yet, and says so in the
// terms the caller cares about when it does.
func createExclusively(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists; refusing to replace a key", path)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// readKeyMaterial reads a key from a file, or from standard input when the
// path is "-", so a pipeline can sign without writing a private key to disk.
func readKeyMaterial(path string, in io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(in)
	}
	return os.ReadFile(path)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcppin verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockPath := fs.String("lock", "", "the approved lockfile (required)")
	var failOn stringList
	fs.Var(&failOn, "fail-on", "policy that must hold, repeatable; also all or none")
	var trusted stringList
	fs.Var(&trusted, "pubkey", "an SPKI PEM key the lockfile must be signed by, repeatable")
	signaturePath := fs.String("signature", "", "the detached signature (default <lock>.sig)")
	minSerial := fs.Int("min-serial", 0, "refuse a lockfile approved before this serial")
	maxAge := fs.Duration("max-signature-age", 0, "refuse a signature older than this")
	format := fs.String("format", "text", "text, json or sarif")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: mcppin verify -lock mcp.lock.json [flags] <manifest.json>\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\npolicies accepted by -fail-on:\n")
		for _, p := range Policies() {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		fmt.Fprintf(stderr, "  all   every policy above\n")
		fmt.Fprintf(stderr, "  none  report only, exit 0 on any finding; must stand alone\n")
		fmt.Fprintf(stderr, "\nwithout -fail-on the gate is %s.\n", strings.Join(DefaultPolicies(), ", "))
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
	gate, err := resolveGate(failOn)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUsage
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "mcppin: unknown format %q; accepted: text, json, sarif\n", *format)
		return ExitUsage
	}

	manifest, err := LoadManifest(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	// The lockfile is read once, and the same bytes are both parsed and put to
	// the signature. Reading it twice would leave a moment between the two in
	// which the file could change, and the run would then verify a surface
	// against one lockfile while vouching for another.
	lockfile, err := os.ReadFile(*lockPath)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}
	lock, err := ReadLock(bytes.NewReader(lockfile))
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %s: %v\n", *lockPath, err)
		return ExitUnreadable
	}
	// The floor comes from the command line, which is to say from wherever the
	// pipeline is configured - somewhere an attacker who can rewrite the
	// lockfile does not necessarily reach. A lockfile below it is an older
	// approval put back in place, signature and all.
	if lock.ApprovalSerial < *minSerial {
		fmt.Fprintf(stderr, "mcppin: %s is approval %d and this run was told to accept nothing "+
			"below %d\n", *lockPath, lock.ApprovalSerial, *minSerial)
		return ExitUnreadable
	}

	result, err := Verify(manifest, lock)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return ExitUnreadable
	}

	// The signature is checked before anything is reported. A lockfile that
	// fails it is not a smaller approval, it is not an approval: exit 4,
	// because the record could not be read as one, and nothing about the
	// served surface has been proven either way.
	signedBy, code := checkTrust(lockfile, *lockPath, *signaturePath, trusted, *maxAge, stderr)
	if code != ExitOK {
		return code
	}
	result.SignedBy = signedBy

	switch *format {
	case "text":
		WriteText(stdout, result, gate)
	case "json":
		if err := WriteJSON(stdout, result, gate); err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
	case "sarif":
		if err := WriteSARIF(stdout, result, gate, fs.Arg(0)); err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return ExitUnreadable
		}
	}

	_, exit := Outcome(result, gate)
	return exit
}

// checkTrust settles who approved the lockfile that was read, and returns the
// exit code to stop on when the answer is nobody this run trusts. It is given
// the bytes rather than the path, so that what is vouched for is what was
// parsed.
//
// With no -pubkey the question is not asked, and a signature sitting next to
// the lockfile is said to be unchecked rather than silently passed over: a
// repository that signs and a pipeline that forgot to check is the failure
// this is here to prevent.
func checkTrust(lockfile []byte, lockPath, signaturePath string, trusted []string,
	maxAge time.Duration, stderr io.Writer) (string, int) {
	path := signaturePath
	if path == "" {
		path = SignaturePath(lockPath)
	}
	if len(trusted) == 0 {
		if maxAge > 0 {
			fmt.Fprintf(stderr, "mcppin: -max-signature-age asks how old a signature is, "+
				"which means checking it; name a key with -pubkey\n")
			return "", ExitUsage
		}
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(stderr, "warning: %s exists and was not checked; pass -pubkey to check it\n", path)
		}
		return "", ExitOK
	}

	keys := make([]ed25519.PublicKey, 0, len(trusted))
	for _, keyPath := range trusted {
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Fprintf(stderr, "mcppin: %v\n", err)
			return "", ExitUnreadable
		}
		key, err := LoadPublicKey(pemBytes)
		if err != nil {
			fmt.Fprintf(stderr, "mcppin: %s: %v\n", keyPath, err)
			return "", ExitUnreadable
		}
		keys = append(keys, key)
	}

	signature, err := LoadSignature(path)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %v\n", err)
		return "", ExitUnreadable
	}
	fingerprint, err := CheckSignature(lockfile, signature, keys)
	if err != nil {
		fmt.Fprintf(stderr, "mcppin: %s: %v\n", path, err)
		return "", ExitUnreadable
	}
	// signed_at is the one date worth trusting here: whoever replays an old
	// lockfile does not hold the key, so they cannot move it. It bounds how
	// far back a rollback can reach; it does not stop one.
	if maxAge > 0 {
		signedAt, err := time.Parse(time.RFC3339, signature.SignedAt)
		if err != nil {
			fmt.Fprintf(stderr, "mcppin: %s: signed_at is not an RFC 3339 timestamp: %v\n", path, err)
			return "", ExitUnreadable
		}
		if age := now().Sub(signedAt); age > maxAge {
			fmt.Fprintf(stderr, "mcppin: %s was signed %s ago and this run accepts nothing older "+
				"than %s\n", lockPath, age.Round(time.Second), maxAge)
			return "", ExitUnreadable
		}
	}
	return fingerprint, ExitOK
}

// resolveGate turns -fail-on into the list of policies the exit code answers
// for. An empty command line means the default gate rather than no gate: a
// verify that prints a violation and exits 0 is the failure mode this tool
// exists to prevent, so reporting without gating has to be asked for by name.
func resolveGate(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return DefaultPolicies(), nil
	}
	for _, policy := range requested {
		switch policy {
		case "all":
			if len(requested) > 1 {
				return nil, errors.New("-fail-on all covers every policy and cannot be combined")
			}
			return Policies(), nil
		case "none":
			if len(requested) > 1 {
				return nil, errors.New("-fail-on none gates nothing and cannot be combined")
			}
			return nil, nil
		}
		if !validPolicy(policy) {
			return nil, fmt.Errorf("unknown policy %q; accepted: %s, all, none",
				policy, strings.Join(Policies(), ", "))
		}
	}
	return requested, nil
}
