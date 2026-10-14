# Goal: planned go-identity boundary

[Documentation index](README.md)

Status: historical scaffold goal, superseded for current implementation status.

The separately authorized identity-platform implementation now exists in the
source and nested modules. This document preserves the earlier planning boundary,
not a claim that no code exists or a replacement for current product requirements.
See [the reference composition](../reference/README.md) and module delivery metadata
for the bounded development checkpoint; full release qualification remains pending.

The coordination plan identifies `github.com/faustbrian/go-identity` as the
future storage-neutral owner of users, accounts, login identifiers, credential
references, verification state, account status, and identity-domain events.

The source planning record is
`.ai/identity-platform/goals/identity.md` in the Golib coordination tree, with
SHA-256
`5e9da1dff1d060504a9ee1ce51816439c9f38cff62ab517ac4607a3a1df45991`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Service Edge family, identity capability, ownership, and
  delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified public `go-library-tools` v2.1.2 tooling. Ordinary checks
  retain offline structure/links and every-change secrets; scheduled/manual
  checks retain online authority refresh. No runtime or release proof follows.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, or released behavior.
- Keep `releasable: false` and delivery release `blocked` until implementation,
  security verification, and release review provide executable evidence.
- Maintain the [repository threat model](security/threat-model-v0.1.md) and
  [private vulnerability reporting process](../SECURITY.md) as planning
  documents, not evidence of implemented controls.

## Deferred implementation

Source packages, nested modules, dependencies, API contracts, behavior,
hardening evidence, compatibility commitments, tags, and releases remain
outside this planning-only goal. They require separately authorized work and
their own executable acceptance evidence.
