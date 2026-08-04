# Security policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button, under the Security tab of this
repository. That opens a private advisory only the maintainers can read.

Please do not open a public issue for anything that would let somebody defeat a check while it
still reports a pass.

Expect an acknowledgement within a week. If a report holds up, the fix, the advisory and a release
go out together, and the reporter is credited unless they would rather not be.

## What counts as a vulnerability here

`mcppin` exists to say **no** when a tool surface has moved. Anything that makes it say yes when it
should not is the serious case:

- a change to a manifest that a `verify` run with a gate reports as clean;
- two different tool objects that produce the same digest;
- a document that this build reads differently from another correct reader, where the difference
  changes a digest or a finding;
- a lockfile, or a signature, that verifies against content it does not cover;
- text from a server that reaches a terminal without being rendered, or that can make a report read
  as a pass;
- anything that lets a partial or torn capture be reported as complete.

A crash on malformed input is a bug worth reporting, though it fails closed and is not urgent: the
exit code says the input could not be read, which is what a gate needs.

## What is out of scope, by design

These are limitations this project states rather than defects it hides. The
[threat model](docs/threat-model.md) covers them in full:

- **A poisoned baseline.** Pinning freezes a surface; it does not judge one. A description that was
  already malicious when it was first approved stays approved.
- **An exporter that lies.** `mcppin` compares what it was given. A manifest that claims to be
  complete and is not is outside what a file comparison can see.
- **The live connection.** A server that behaves differently from what it describes, that serves
  one surface to the exporter and another to the agent, or that changes between the check and the
  call, is beyond a tool that reads two files.
- **A stolen signing key**, and **a rollback to an older signed lockfile** where no floor was
  anchored outside the repository.

If you have a way to close one of those, it is a design discussion and very welcome as a public
issue.

## Supported versions

Below 1.0, the latest release is the supported one.
