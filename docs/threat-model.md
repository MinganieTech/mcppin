# Threat model

`mcppin` is a gate, and a gate is worth exactly what its guarantee says. This document states that
guarantee, the assumptions it rests on, and the attacks it does not stop. Read it before putting
the exit code in a pipeline.

## The guarantee

> Every tool in the manifest canonicalises to the same bytes as the tool that was approved, no tool
> was added or removed, and no string in any of them carries a character that occupies no visible
> space.

That is a statement about **two exported representations of a tool surface**. It is not a statement
about what an agent receives at the moment it runs, and `mcppin` cannot make one: it reads a file,
speaks no MCP, and opens no connection.

## What it rests on

1. **The exporter is trusted, and says whether it was complete.** `mcppin` compares what you
   captured. A gateway that paginates `tools/list` and stops early, or that drops a field it does
   not understand, produces a manifest that describes a surface that is not the one being served.

   A version 2 manifest has to declare `complete`, and a capture that declares itself partial can
   no longer prove that a tool was withdrawn: those tools are reported as unseen and the run exits
   `3`. `mcppin-export` sets that field from what happened - it is true only when the cursor loop
   reached the end - so the claim comes from the code that did the capture rather than from the
   person writing the file. A version 1 manifest cannot say, and the run says so.

   None of that helps against an exporter that lies, and a manifest written by hand can say
   anything. This is still the largest assumption in the tool.

   `mcppin-export` carries its own: it **runs the commands in the configuration it reads**. It is
   exactly as trusted as the client whose configuration that is, and it should be pointed at a
   configuration you would let that client run. It is a separate binary so that the thing deciding
   whether a surface is approved is never the thing an untrusted server gets to answer.
2. **The lockfile is trusted, and can say who approved it.** Unsigned, it is a plain JSON file:
   anyone who can rewrite it can approve anything. Keep it in version control and review its diffs
   like code - it holds the approved text, so that review is possible.

   `mcppin sign` and `mcppin verify -pubkey` close the rest. The signature is Ed25519, detached, and
   covers the canonical form of the lockfile; a run given a public key refuses a lockfile that is
   unsigned, stale, edited or signed by anyone else, and exits `4`.

   That moves the assumption rather than removing it: **the private key is now the thing that
   approves surfaces**. Whoever holds it can approve anything, and this build does not encrypt it,
   hold it, or ask for a passphrase - use whatever your operating system or secret store already
   does for signing keys, and keep it out of the pipeline that consumes the lockfile. A pipeline
   that can both sign and verify has verified nothing.
3. **The approval was sound.** A description that was already malicious when it was first pinned
   stays approved forever. Pinning freezes a surface; it does not judge it.

## Coverage

| Threat | Covered | Notes |
|---|---|---|
| A description or a schema is rewritten after approval | Yes | `tool-changed`, on the whole tool object |
| A tool is added or removed | Yes | `tool-added`, `tool-removed`, both in the default gate |
| A character that occupies no visible space, anywhere in the tool object | Yes | `hidden-characters`, reported with a JSON pointer |
| A tool name spoofing another through mixed writing systems | Yes | `mixed-script-name`, `invalid-tool-name` |
| A server changing the name it reports for itself | Yes | `server-renamed`; the identity is the configuration key, so the rename is visible instead of looking like a second server |
| Two servers claiming the same tool name | Yes | `name-collision`, reported always, gated on request |
| A value the canonical form cannot tell from its neighbour | Yes | pinned as undecidable, exit `3`, never reported as matching |
| A document two parsers would read differently | Yes | refused, exit `4` |
| A lockfile whose digest and content disagree | Yes | every digest is recomputed from the approved object beside it |
| A capture that stopped early | Partly | it has to declare itself, and then absence proves nothing; a capture that lies about it is assumption 1 |
| A baseline poisoned before approval | Partly | the lockfile holds the approved text, so the poison is in the diff a reviewer reads - if they read it. See assumption 3 |
| Two names equal only after Unicode NFC | Yes | member names, server identities and tool names; the rule comes from the mcp-lock draft, see [interop](interop.md) |
| A server that behaves differently from what it describes | **No** | the description is all there is to hash |
| A server serving one surface to the exporter and another to the agent | **No** | out of reach of a file comparison |
| The surface changing between the check and the call | **No** | `mcppin` runs once; it is not a proxy |
| A tampered lockfile | Yes, if signed | `verify -pubkey` refuses anything but a valid signature by a key you named; unsigned, see assumption 2 |
| A stolen signing key | **No** | it approves whatever it is pointed at; see assumption 2 |
| A truncated or partial export | **No** | see assumption 1; a short manifest looks like removals, or like nothing at all |

## Where the remaining risk goes

The four uncovered rows all have the same shape: they are about the **live connection**, and a file
comparison cannot see it. Closing them takes something that sits between the agent and the server -
a proxy, or a client that checks the surface it was actually handed. `mcppin` is deliberately not
that; it is the part that says what the approved surface is, in a form such a component could
consume.

If you need the live guarantee, run the check as close to the agent as you can: export the manifest
from the same client, on the same connection, immediately before use. That shrinks the window
between the check and the call. It does not close it.
