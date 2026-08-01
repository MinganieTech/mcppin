# mcppin

Pin the tool surface an agent was approved to see, and refuse the drift.

An MCP server describes its own tools, and an agent reads those descriptions as instructions. That
makes the description an input, and an input that can change after somebody approved it. The
attack that follows is not exotic: a server behaves for a week, gets approved, then rewrites what
its tool claims to do. `mcppin` is `package-lock.json` for that surface.

It is deliberately not a detector. It does not judge what a description *says* - no classifier, no
scoring, no reading of intent. A description that asks an agent to do something outrageous in
plain ASCII is a review problem, and pretending to solve it would be the fifth implementation of
something already bypassable. What `mcppin` proves is that the text you approved is the text being
served, byte for byte, and that no character in it is hiding from the reviewer.

A file in, an answer out. No network call, no daemon, no runtime.

## Usage

Approve the surface as it stands:

```bash
mcppin lock -o mcp.lock.json examples/manifest.json
```

Then check it on every start, or in CI:

```bash
mcppin verify -lock mcp.lock.json -fail-on tool-changed -fail-on tool-added examples/manifest-drifted.json
```

### Policies

| Policy | Fails when |
|---|---|
| `tool-changed` | an approved tool no longer hashes to what was approved |
| `tool-added` | a server offers a tool nobody approved |
| `tool-removed` | an approved tool is no longer offered |
| `name-collision` | two servers offer the same tool name |
| `hidden-characters` | a name or description carries text that occupies no visible space |
| `mixed-script-name` | a tool name draws on several writing systems |

Only names are checked for mixed writing systems. A description mixing Latin and Han is ordinary
prose; a tool *name* doing it is how one name is made to look like another.

### Exit codes

Exit codes are a public contract. CI pipelines branch on them, so changing one is a breaking
change.

| Code | Meaning |
|---|---|
| `0` | every requested policy holds |
| `1` | a departure from the approved surface was proven |
| `2` | the command line is wrong |
| `3` | a digest is not reproducible |
| `4` | an input could not be read |

## The digest

Tools are hashed over their **canonical** form, RFC 8785 (JCS): keys ordered by UTF-16 code unit,
numbers in the ECMAScript form, minimal string escaping, no whitespace. Without it a digest is
worthless as a pin - re-serialising the same tool with a different encoder moves key order and
number formatting, and every restart looks like drift.

The digest covers the whole tool object, not the fields this build happens to understand. A server
that adds an annotation changes the digest, and it should: you approved what it said, all of it.

RFC 8785 canonicalises through IEEE 754 doubles. A tool carrying an integer beyond 2^53 therefore
has no reproducible digest, and `mcppin` says so and exits `3` rather than pinning a value that
will drift on its own.

## Input

The tool surface exposed to an agent, across every server. Each tool is the object the server
returned from `tools/list`, unmodified:

```json
{
  "schema_version": 1,
  "servers": [
    {
      "name": "billing",
      "tools": [
        {"name": "stripe.refund", "description": "Refund a charge.", "inputSchema": {"type": "object"}}
      ]
    }
  ]
}
```

Exporting that file from your gateway is your side of the contract; `mcppin` makes no network
call and does not speak MCP.

## What this does not prove

A matching lockfile proves the served text equals the approved text. It says nothing about whether
the approval was sound - a poisoned description approved on day one stays approved. It also cannot
see a server that behaves differently from what it describes, because the description is all there
is to hash.

The `lock` command reports hidden characters and colliding names but writes the lockfile anyway:
you cannot fix what you have not pinned. Turning those observations into a gate is what `verify`
is for.

## Build

```bash
go build ./cmd/mcppin
```

No third-party dependency is required.

## License

MIT. See [LICENSE](LICENSE).
