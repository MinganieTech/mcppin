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

### The two binaries

`cmd/mcppin` compares two files and speaks to nobody. Everything above is a rule about it, and
`internal/mcppin` must never import `internal/mcpexport`.

`cmd/mcppin-export` is the one place a protocol is spoken. It exists because a verifier with no
capture path is a verifier nobody can use, and it is a **separate binary and a separate package**
because the thing that decides whether a surface is approved must not also be the thing an
untrusted server gets to answer. It may import `internal/mcppin`; the dependency never points the
other way.

- It reads the `mcpServers` object clients already share, and the identity of a server is the key
  it was filed under - never the name the server reports for itself.
- `complete` is set from what happened, never from what was hoped. It is true only when the
  `tools/list` cursor was followed to the end.
- A server that cannot be reached fails the whole export. An absent server is not a smaller
  surface, it is an unknown one.

## Engineering rules

- **Go, and one dependency: `golang.org/x/text` for Unicode normalisation.** The bar is not "no
  dependencies", which was a habit carried over from an ecosystem with a different supply chain. It
  is this: a dependency has to be something that cannot be written here correctly. Unicode
  normalisation tables are exactly that - hand-rolling them would be a subtly wrong copy of data
  somebody else maintains against the standard. JSON canonicalisation is exactly not that, and is
  written here, because it is the load-bearing part and a digest nobody can audit is not evidence.
  Unicode scripts and format categories come from the standard library.
- **A new dependency is a decision, not a convenience.** `go.mod` names it, `go.sum` pins it, and
  the reason it could not be written here goes in the commit that adds it.
- **RFC 8785 is the contract, not an implementation detail.** Key order by UTF-16 code unit,
  ECMAScript number form, minimal escaping. The number cases in `jcs_test.go` come from the RFC and
  must stay green; Go's own shortest form agrees on the digits and disagrees on when to switch to
  exponential notation, which is exactly the trap.
- **Input is read strictly, because JCS canonicalises I-JSON.** A duplicate member name, an
  unpaired surrogate escape, invalid UTF-8, a second value after the document: each is something two
  honest parsers resolve differently, and a canonical form computed on one resolution is not
  evidence. They are refused, never repaired.
- **Two names that are one name after NFC are one name.** Member names, server identities and tool
  names all go through `nameSet`. Composed and decomposed spellings display identically, so a
  document carrying both has a reviewer reading one and a client reading the other. The mcp-lock
  draft requires this and it is why `x/text` is here.
- **A digest that cannot be reproduced is not evidence.** The rule is about the *value*, not the
  notation: an integral value beyond 2^53 shares its double with its neighbours whether it is
  written `9007199254740993`, `9007199254740993.0` or `1e30`, and a value outside the float64 range
  becomes an infinity or a zero that is not the value. Such a tool is pinned as
  `undecidable_literals` rather than given a digest, and the run exits `3`.
- **The guarantee is equality of the canonical tool object, never "byte for byte".** JCS erases key
  order, `1` against `1.0`, and equivalent escapes on purpose. Any wording that claims the document
  itself is compared is wrong.
- **Printed text is ASCII, and served text is never printed as itself.** These tools run in CI logs
  and on Windows consoles whose code page renders anything else as `?` - and a description is
  attacker-controlled text, so a diff that pasted it verbatim would hand a terminal escape or a
  right-to-left override to the reviewer it is meant to inform. Everything outside printable ASCII
  is named by code point in the text and SARIF renderings. The `json` report is the one output not
  meant for a terminal, and the one that carries values as they were served.
- **The lockfile keeps the approved tool, not only its digest.** Two digests say that something
  changed and never what, and a lockfile nobody can review is how a description gets approved
  without being read. Every digest is recomputed from the object beside it on read: a file whose
  halves disagree is refused, never half-believed.
- **A capture that admits it is partial proves nothing about absence.** `tool-removed` becomes a
  list of unseen tools and exit `3`. Anything that would let a partial capture exit `0` is a bug.
- **Server identity is the configuration key.** `reported_name` is what the server claims and is
  evidence, never identity; when it moves, that is `server-renamed`.
- **Exit codes are a public contract** (`0` clean, `1` violation proven, `2` usage, `3`
  undecidable, `4` unreadable input). `1` outranks `3`: undecidability hides departures, it does not
  invent them.
- **`verify` gates by default.** With no `-fail-on` it holds the surface to `tool-changed`,
  `tool-added` and `tool-removed`. Printing a violation and exiting `0` is the one failure mode a
  pinning tool cannot have, so reporting without gating is `-fail-on none` and nothing else.
- **`lock` writes even when it has complaints.** You cannot fix what you have not pinned. It says
  what it saw on standard error; `verify` is what turns that into a gate. It writes through a
  temporary file in the target directory and a rename: truncating the approved baseline and then
  failing would destroy the only record of what was approved.
- **Signing answers "who approved this", and it is optional.** Ed25519, detached, over the
  canonical form of the lockfile, envelope included so a signature cannot be lifted onto another
  one. A run given `-pubkey` refuses anything but a valid signature by a key it was told to trust,
  and exits `4`: a lockfile that fails its signature is not a smaller approval, it is not one, and
  nothing about the served surface has been proven either way. A run with no `-pubkey` says that a
  signature it found went unchecked rather than passing over it.
- **This build never holds a secret.** No passphrase prompt, no key store, no encrypted key
  format - each would be a worse version of something the operating system already does. `key`
  writes `0600` and refuses to overwrite; the rest is the operator's.
- **The lockfile is refused when it is ambiguous.** Two servers of one name, one tool pinned twice,
  a digest of the wrong algorithm or length, a pin that is neither a digest nor an admission that
  none is possible. For every other input the tool reports; for its own approved record it stops.
- **Only names are checked for mixed writing systems.** Descriptions are prose and mix scripts
  legitimately; flagging them would train users to ignore the tool. Hidden characters are the
  opposite case: every string in the tool object is searched, and each finding carries the RFC 6901
  pointer of where it was found.
- **`PASS` and `FAIL` belong to the gate summary only.** A finding printed while the tool exits `0`
  is called `VIOLATION`, and no line may read as reassurance while the exit code says otherwise.
- **The README states what a matching lockfile does not prove**, and `docs/threat-model.md` states
  it in full: the exporter is trusted and assumed complete, the lockfile is unsigned, the approval
  may have been wrong. It proves served text equals approved text, never that the approval was
  sound. Any wording that lets a reader hear "this server is safe" is a bug, and any new coverage
  claim belongs in the threat model table before it belongs in the README.
- **The JSON report, the manifest and the lockfile are contracts.** Additive changes are free;
  removing a field or changing what it means bumps `ReportSchemaVersion`, `ManifestSchemaVersion`
  or `LockSchemaVersion`. A digest carries its algorithm as a prefix so a second one can be added
  without breaking old files.
- **Every schema version this project has ever written stays readable.** The upgrade path for a
  format change must never be "re-approve the surface", because approving a surface you have not
  compared is the failure this tool exists to prevent.
- The version lives in `internal/mcppin/cli.go` and nowhere else. The release workflow refuses a
  tag that disagrees with it.
- `gofmt -l .` stays empty, `go vet ./...` and `go test ./...` stay green on Linux, Windows and
  macOS.
