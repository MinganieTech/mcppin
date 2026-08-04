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

   A manifest has to declare `complete`, and a capture that declares itself partial can no longer
   prove that a tool was withdrawn: those tools are reported as unseen and the run exits `3`.
   Version 1 manifests, which had no way to say, are refused rather than assumed complete.

   `mcppin-export` sets the field from what happened. Reaching the last page of `tools/list` is not
   enough: MCP does not promise that a paginated list is a snapshot, so a server free to change
   between two requests can hide a tool at a page boundary, and every page would still arrive. The
   exporter therefore traverses the list twice and claims `complete` only if both traversals see
   the same surface. **This still does not prove a snapshot** - a server can change and change back
   between the two - and it is a check where there was none.

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

   A signature says "this surface was approved by this key", and not "this is the approval in
   force". An attacker who can write the lockfile can put back an **older lockfile and its own
   valid signature** - one from before a tool was withdrawn, or before a description was
   tightened - and every check passes. No pair of files can prevent that on its own: a file cannot
   say it is the newest one, and only something that remembers can.

   Three things carry that memory, and each anchors somewhere the lockfile is not:

   - `approval_serial` in the lockfile, with `verify -min-serial N`. The floor is a number you pin
     in the pipeline configuration, which is a different place from the repository the lockfile
     sits in. The serial counts approvals rather than runs, so re-approving an unchanged surface
     does not move it.
   - `verify -max-signature-age`, against the `signed_at` in the envelope. That date is trustworthy
     here precisely because whoever replays an old lockfile does not hold the key. It bounds how
     far back a rollback can reach without stopping one, and it makes a build depend on a clock.
   - Version control, which is memory you already keep: a rollback is a commit that removes the
     newer lockfile, and it is visible in review.

   None of the three is automatic. A pipeline that reads its floor from the same repository an
   attacker can write has anchored nothing.

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
| A tool list that changes while it is being read | Partly | two traversals must agree before `complete` is claimed; a server that changes and changes back defeats it |
| A server steering the client with a malformed answer | Yes | the JSON-RPC envelope is checked, not assumed, and the result is decoded by the same strict reader as everything else |
| Terminal escapes in served text | Yes | nothing a server touches reaches a console without being rendered by code point |
| A baseline poisoned before approval | Partly | the lockfile holds the approved text, so the poison is in the diff a reviewer reads - if they read it. See assumption 3 |
| Two names equal only after Unicode NFC | Yes | member names, server identities and tool names; the rule comes from the mcp-lock draft, see [interop](interop.md) |
| A server that behaves differently from what it describes | **No** | the description is all there is to hash |
| A server serving one surface to the exporter and another to the agent | **No** | out of reach of a file comparison |
| The surface changing between the check and the call | **No** | `mcppin` runs once; it is not a proxy |
| A tampered lockfile | Yes, if signed | `verify -pubkey` refuses anything but a valid signature by a key you named; unsigned, see assumption 2 |
| A stolen signing key | **No** | it approves whatever it is pointed at; see assumption 2 |
| A rollback to an older signed lockfile | Partly | the signature stays valid; `-min-serial` and `-max-signature-age` refuse it only if the floor or the clock is anchored outside the repository. See assumption 2 |
| A capture of part of the surface passed off as all of it | Yes | a capture that names its `scope` has the rest reported as unexamined; one that does not is claiming to be everything, and the missing servers read as removals |
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
