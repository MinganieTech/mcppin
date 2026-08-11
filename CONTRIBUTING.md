# Contributing

Issues and pull requests are welcome. This file is the short version of what a change here has to
hold to, so that a review is about the change rather than about the rules.

## What this tool is, and is not

`mcppin` answers one question: **is the tool surface being served the one that was approved?**

It never judges what a description *says*. No classifier, no score, no reading of intent. Drift and
hidden characters are structural; "this text looks like an instruction" is not, and a change that
adds that kind of judgement will be declined however well it works.

`mcppin` reads files and speaks to nobody. `mcppin-export` is the one place a protocol is spoken,
in its own package and its own binary, because the thing that decides whether a surface is approved
must not also be the thing an untrusted server gets to answer. `internal/mcppin` must never import
`internal/mcpexport`.

## Rules a change is reviewed against

- **English, everywhere.** Code, comments, docs, CLI output, commit messages, issues, pull
  requests.
- **A dependency has to be something that cannot be written here correctly.** There is one,
  `golang.org/x/text`, for Unicode normalisation tables. JSON canonicalisation is written here
  instead of imported, because it is load-bearing and a digest nobody can audit is not evidence.
  A new dependency needs the reason it could not be written here, in the commit that adds it.
- **RFC 8785 is the contract.** Key order by UTF-16 code unit, ECMAScript number form, minimal
  escaping. The number cases in `jcs_test.go` come from the RFC and stay green.
- **Input is read strictly.** A duplicate member name, two names equal after Unicode NFC, an
  unpaired surrogate escape, invalid UTF-8, a value after the document: each is something two
  honest parsers resolve differently, and a canonical form computed on one resolution is not
  evidence. They are refused, never repaired.
- **Exit codes are a public contract** (`0` clean, `1` violation proven, `2` usage, `3` something
  could not be compared, `4` an input could not be read). `1` outranks `3`.
- **No line may read as reassurance while the exit code says otherwise.** `PASS` belongs to the
  gate summary and to a policy that actually held. A report that says the surface matches, above a
  list of things nobody looked at, is a bug.
- **Served text is never printed as itself.** Everything a server touches goes through `Printable`
  on its way to a terminal - descriptions, names, its error messages, its standard error. A `%s`
  straight from a manifest is a bug. The `json` report is the one output that carries values as
  they were served.
- **Formats are contracts, and "adding a field is free" has a limit.** An older build ignores a
  field it does not know. That is harmless for provenance and unacceptable for a decision, because
  a lockfile carrying `expires_at` or `policy` would be *silently disregarded* by every build
  released before it - the reader would pass a surface the file said to refuse. So:

  | New field | What it takes |
  |---|---|
  | Informational: provenance, timestamps, counts, anything a reader may ignore without being wrong | Add it. No version bump. |
  | Load-bearing: anything a correct reader **must** act on to reach the right verdict | Bump `ManifestSchemaVersion`, `LockSchemaVersion` or `ReportSchemaVersion`, so an older build refuses the file instead of half-reading it |

  Removing a field, or changing what one means, always bumps. Every lockfile version this project
  has written stays readable, because the upgrade path must never be "re-approve a surface you have
  not compared". The signature envelope is stricter still and refuses any member it does not know:
  what is not read there is not signed, so there is no such thing as an informational field in it.
- **The threat model comes first.** A change that widens what the tool covers updates
  [docs/threat-model.md](docs/threat-model.md) in the same pull request. Any wording that lets a
  reader hear "this server is safe" is a bug.
- The version lives in `internal/mcppin/cli.go` and nowhere else.

## Before you open a pull request

```bash
gofmt -l .        # stays empty
go vet ./...
go test ./...
go mod tidy -diff
```

CI runs the same on Linux, Windows and macOS, plus `go test -race` and `govulncheck`.

Tests here are named for the behaviour they hold, not the function they call, and say **why** the
behaviour matters when it is not obvious. A fix for a defect comes with the test that fails without
it - and the test is worth writing first, so that it does fail.

## Reporting a security problem

Not through an issue. See [SECURITY.md](SECURITY.md).
