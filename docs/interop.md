# Interoperating with the mcp-lock draft

`mcppin` is not the only project pinning an MCP surface, and a second isolated
format helps nobody. This is where `mcppin` sits next to the
[mcp-lock draft](https://github.com/proofofwork-agency/toolpin/blob/main/docs/spec/mcp-lockfile-v1.md)
(ToolPin), what maps between them, and what does not.

Read against draft v1.0 as published at the time of writing. It is a draft: treat every
statement here as something to re-check before depending on it.

## They are not the same object

The draft locks an **installation**. One entry records a reviewed decision about a server
deployment: where the artifact was resolved from, its registry and digest, the generated client
configuration, evidence of what was verified and by whom, timestamps, and an optional detached
Ed25519 signature over the whole file. The declared tool surface is one recommended sub-object of
an entry.

`mcppin` locks **that sub-object and nothing else**, and goes further inside it than the draft
asks for. The comparison worth making is therefore between an mcppin lockfile and one entry's
surface pin, not between the two files.

## Mapping

| mcp-lock | mcppin | Notes |
|---|---|---|
| `entries[].surface.hash` | `servers[].tools[].digest` | The draft hashes one value for the server's whole tool list; mcppin hashes each tool on its own, so a finding names the tool that moved |
| `entries[].surface.coverage` | not needed | mcppin always covers the whole tool object, so there is no coverage to declare and none to downgrade |
| `entries[].surface.toolCount` | implicit | the tools are in the file |
| `entries[].surface.capturedAt` | manifest `captured_at` | mcppin keeps provenance on the capture, not on the pin |
| `entries[].name` (reverse-DNS) | `servers[].id` | mcppin takes the identity from the configuration key, the draft from a reverse-DNS server name |
| `entries[].client`, `scope`, `source`, `target`, `configDigest`, `verification`, `integrity` | nothing | installation provenance; out of scope here |
| detached signature envelope | `mcp.lock.json.sig` | same shape: Ed25519, detached, the envelope signed with its own signature member removed. Different field spellings, and mcppin has no `policyDigest` |
| `specVersion` | `schema_version` | both reject majors they do not know |

## Where the two agree

- **RFC 8785 (JCS) over UTF-8 as the canonical form.** Same canonicalisation, same reason.
- **SHA-256.**
- **Refusing ambiguous documents rather than resolving them**, including the draft's rule on names
  that are equal after NFC normalisation. mcppin applies it to member names, server identities and
  tool names; it is the one thing in this repository that has a third-party dependency behind it,
  because Unicode tables are not something to reimplement.
- **Machine-readable output naming the failed condition.** The draft asks enforcers for JSON or
  SARIF; `mcppin verify -format sarif` emits SARIF 2.1.0.
- **An enforcer must not mutate the lockfile.** `mcppin verify` never writes one; only `lock` does.
- **An empty lockfile is a failure, not a pass.**

## Where they diverge, and why

**Digest encoding.** The draft uses SRI-style `sha256-<base64>`; mcppin uses `sha256:<hex>`.
mcppin's is what a reviewer can compare against `sha256sum` output by eye. Converting between them
is mechanical, so this is a formatting difference and not a semantic one.

**What is hashed.** The draft hashes only the fields named in `coverage`, with a floor of
`name` and `description` and a recommendation to include `inputSchema`. mcppin hashes the entire
tool object, including fields this build does not understand. A coverage list is a place for a
field to hide: anything outside it can change without moving the hash, and the draft has to define
a downgrade check because of it. mcppin has nothing to downgrade.

**Per-tool against per-server.** One hash for a server's whole list is cheaper and says less. It
cannot say which tool changed, and it moves whenever any tool is added, which conflates three
different findings into one.

**Signature envelopes.** Both are detached Ed25519 over the envelope with the signature member
removed, which is the part that matters. The spellings differ: the draft uses `schema`,
`lockfileDigest`, `publicKeyFingerprint`, `signedAt` in camelCase with SRI digests; mcppin uses
snake_case and `sha256:<hex>` throughout, to stay consistent with itself. The draft also binds an
optional `policyDigest`, which mcppin has nothing to put in.

A converter between the two envelopes is a dozen lines, and it needs the digest question below
settled first: an envelope is only worth converting if the digest it vouches for means the same
thing on both sides.

## What mcppin could emit, and has not

An `mcppin verify -format mcp-lock-surface` producing a ready-to-embed `surface` object is a small
piece of work, and it is not written yet for one reason: the draft text fixes the ordering (by
name, UTF-16 code units) and the coverage filter, but not the exact shape of the record array that
gets canonicalised. A hash that only usually matches theirs would be worse than no hash at all,
because the failure mode is a green check on two surfaces that were never compared.

The honest way to close this is to agree the byte-level definition with the draft's authors first.
Until then, an mcp-lock producer that wants mcppin's guarantee can carry the mcppin lockfile
alongside its entry, or read `mcppin verify -format json`, whose `capture_complete`, `findings` and
`unstable_digests` fields are a stable contract.
