# Changelog

Below 1.0 the formats are still moving. Each of them carries its own schema version, and a build
says which ones it reads. The exit codes are the part that will not move quietly.

## 0.2.1

### The guarantee said more than the default gate did

The threat model promised that no string carries a character that occupies no visible space, while
`hidden-characters` was not in the default gate. A surface approved with a `U+200B` in it therefore
printed `VIOLATION hidden-characters` and exited `0`.

The split is kept and the claim is corrected, because gating those policies by default would fail
every run of a surface nobody had changed: what the default gate answers for is **drift**, and the
properties of the surface itself are reported and become gates with `-fail-on all`.

The report no longer leaves that to be inferred. A run that found something it did not answer for
now says so:

```
NOT GATED: hidden-characters
  reported above and not answered for by the exit code. These describe the
  surface rather than a departure from the approved one, so a surface can be
  approved with them already in it. -fail-on all makes them fail the run.
```

### Fixed

- `protocol-changed` had no SARIF description, so its rule reached a dashboard blank. Every rule is
  now checked to have one, and a rule declared without a description says so loudly instead of
  quietly.
- An undecidable digest, an incomplete capture and an unexamined server exit `3` and were SARIF
  warnings. They are errors: the severity has to agree with the exit code.

### Added

- **Install instructions**: release binaries for Linux, macOS and Windows with checksum
  verification, `go install`, and a complete GitHub Actions workflow that captures a surface,
  gates on it and uploads the findings to code scanning.
- **Build provenance attestation** on every release artefact, verifiable with
  `gh attestation verify <file> --repo MinganieTech/mcppin`. A checksum published beside the file
  it covers, by the job that made both, says only that the download is not corrupt.
- A release now **refuses to publish a commit that did not pass CI** - all six checks, including
  the race detector, the fuzzing and `govulncheck` - rather than trusting that it compiles.

### Changed

- The rule for adding a field to a format is written down: informational fields are free, and a
  field a correct reader must act on bumps the schema version. An older build ignores what it does
  not know, which is fine for provenance and unacceptable for a decision.

## 0.2.0

First release. Version 0.1.0 was never tagged; it is listed below as what the repository held
before this.

### The gate

- `verify` is fail-closed. With no `-fail-on` it holds the surface to `tool-changed`, `tool-added`,
  `tool-removed` and `server-renamed`. Reporting without gating is `-fail-on none` and nothing else.
- `-fail-on all` covers every policy. New policies: `invalid-tool-name`, `server-renamed`,
  `protocol-changed`.
- `hidden-characters` searches every string in a tool object, not only the name and the
  description, and names the RFC 6901 pointer where it found one.
- The gate summary says `PARTIAL` when nothing was proven among what could be compared and what
  could not is where a departure would hide.
- `-format text|json|sarif` replaces `-json`. SARIF is 2.1.0. The JSON report carries the run's own
  `status` and `exit_code`.

### What is read, and how

- Manifests, lockfiles and server answers are read as I-JSON: a duplicate member name, two names
  equal only after Unicode NFC, an unpaired surrogate escape, invalid UTF-8, a value after the
  document, or nesting past 256 levels is refused rather than resolved.
- The number rule is about the value, not the notation: an integral value beyond 2^53 has no
  reproducible identity whether it is written `9007199254740993`, `9007199254740993.0` or `1e30`,
  and such a tool is pinned as undecidable instead of given a digest that covers its neighbours.

### Manifests

- **Schema 2**, carrying `protocol_version`, `complete`, capture provenance, a server `id` distinct
  from the `reported_name`, and an optional `scope`.
- `complete` means the capture holds the surface as one state. A capture that says it is not
  complete cannot prove that a tool was withdrawn.
- `scope` names the servers a capture claims to cover; its absence claims the whole surface.
  Approved servers outside it are reported as unexamined rather than withdrawn.
- **Schema 1 manifests are refused.** They could not state completeness, and a removal proven
  against a capture of unknown coverage is not proven. Capture the surface again.

### Lockfiles

- **Schema 2**, keeping the approved tool object beside its digest, so a violation says what
  changed rather than that a hash moved. Every digest is recomputed from the object beside it on
  read.
- `approval_serial` counts approvals, and `verify -min-serial` holds a floor against a rollback.
- Written through a temporary file and a rename, so a failed write cannot destroy the baseline.
- Refused when ambiguous: two servers of one identity, a tool pinned twice, a digest of the wrong
  algorithm or length, a pin that is neither a digest nor an admission that none is possible.
- **Schema 1 lockfiles still verify**, falling back to comparing digests.

### Signing

- `mcppin key` and `mcppin sign`: Ed25519, detached, over the canonical form of the lockfile and
  over the whole envelope. `verify -pubkey` refuses anything else and exits `4`.
- `-max-signature-age` bounds how stale a signature may be.
- An envelope carrying a member this build does not sign is refused.

### Capturing

- **`mcppin-export`**, a second binary, speaks stdio MCP over both wire eras: `initialize` for
  `2024-10-07` through `2025-11-25`, and the stateless `_meta` design from `2026-07-28`. A revision
  it has not been written against is refused rather than guessed at.
- It follows the `tools/list` cursor to the end - an empty cursor is a cursor - and reads the list
  twice by default, claiming `complete` only when both readings agree.
- A server that cannot be reached fails the whole export.

### Output

- Nothing a server touches reaches a terminal as itself. Everything outside printable ASCII is
  named by code point, in the text report and in SARIF messages.

### Elsewhere

- CI on Linux, Windows and macOS, with `-race` and `govulncheck`.
- A release workflow that refuses a tag disagreeing with the version constant, and publishes
  checksums.
- [Threat model](docs/threat-model.md) and [interop notes](docs/interop.md) against the `mcp-lock`
  draft.
- One dependency: `golang.org/x/text`, for Unicode normalisation.

### Found by the first CI run, and shipped in the same release

These entries were written after the rest of this section, because the matrix found them on its
first run and no development machine could have.

- **The `go` directive is a floor of 1.25.3**, not 1.25.0. Below it, three standard library
  advisories are reachable from the code that reads a key: quadratic parsing in `encoding/pem`
  (GO-2025-4009) and in `crypto/x509` name constraints (GO-2025-4007), and memory exhaustion in
  `encoding/asn1` (GO-2025-4011). The PEM handed to `-pubkey` is attacker-supplied input in a tool
  whose job is to be handed hostile files. A machine whose toolchain was already past the floor saw
  nothing; the runner, obeying the directive, did.
- **`.gitattributes` fixes line endings at LF** on every platform. A checkout on Windows converts
  to CRLF by default, and `gofmt -l .` then rejects every file in the repository.
- Actions pinned to the current majors. The previous pins were two majors behind and ran on a
  deprecated Node.
- `workflow_dispatch` on CI, so the matrix can be run against a branch without opening a pull
  request to find out whether it passes on the two platforms a development machine is not.

## 0.1.0

Never released. Pinned a tool surface with a hand-written RFC 8785 canonicaliser, reported hidden
characters and colliding names, and compared digests against a lockfile.
