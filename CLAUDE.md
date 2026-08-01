# mcppin - working conventions

## Language

**Everything committed to this repository is written in English** - code, comments, README and
docs, CLI output and error messages, commit messages, issues and pull requests. Conversation with
the owner happens in French; the artifacts never do.

## Isolation

This repository has no relationship with any other codebase, including the other tools in the same
family. Do not read a neighbouring project to derive a convention, a vocabulary, a template or a
technical choice here. Every decision is justified from this tool alone. Arriving at the same
answer as a neighbour is fine; reasoning from its precedent is not.

## Scope

`mcppin` answers one question: **is the tool surface being served the one that was approved?**

- The input is an exported manifest. No network call, no daemon, no MCP client, no runtime
  dependency.
- It never judges what a description says. No classifier, no score, no intent. Drift and hidden
  characters are structural; "this text looks like an instruction" is not, and that market is both
  saturated and bypassable.
- The digest covers the whole tool object, including fields this build does not understand. An
  approval covers everything the server said, so the hash must too.

## Engineering rules

- **Go, no third-party dependency.** The one thing that could have justified one - JSON
  canonicalisation - is written here instead, because it is the load-bearing part and a digest
  nobody can audit is not evidence. Unicode scripts and format categories come from the standard
  library.
- **RFC 8785 is the contract, not an implementation detail.** Key order by UTF-16 code unit,
  ECMAScript number form, minimal escaping. The number cases in `jcs_test.go` come from the RFC and
  must stay green; Go's own shortest form agrees on the digits and disagrees on when to switch to
  exponential notation, which is exactly the trap.
- **A digest that cannot be reproduced is not evidence.** An integer beyond 2^53 does not survive
  the double JCS canonicalises through, so the tool reports it and exits `3` rather than pinning a
  value that will drift on its own.
- **Printed text is ASCII.** These tools run in CI logs and on Windows consoles whose code page
  renders anything else as `?`. Documentation is free; CLI output is not. Findings *about*
  non-ASCII characters name them by code point, never by reproducing them.
- **Exit codes are a public contract** (`0` clean, `1` violation proven, `2` usage, `3`
  undecidable, `4` unreadable input).
- **`lock` writes even when it has complaints.** You cannot fix what you have not pinned. It says
  what it saw on standard error; `verify` is what turns that into a gate.
- **Only names are checked for mixed writing systems.** Descriptions are prose and mix scripts
  legitimately; flagging them would train users to ignore the tool.
- **`PASS` and `FAIL` belong to the gate summary only.** A finding printed while the tool exits `0`
  is called `VIOLATION`, and no line may read as reassurance while the exit code says otherwise.
- **The README states what a matching lockfile does not prove.** It proves served text equals
  approved text, never that the approval was sound. Any wording that lets a reader hear "this
  server is safe" is a bug.
- **The JSON report and the lockfile are contracts.** Additive changes are free; removing a field
  or changing what it means bumps `ReportSchemaVersion` or `LockSchemaVersion`. A digest carries
  its algorithm as a prefix so a second one can be added without breaking old files.
- The version lives in `internal/mcppin/cli.go` and nowhere else.
- `gofmt -l .` stays empty, `go vet ./...` and `go test ./...` stay green on Linux, Windows and
  macOS.
