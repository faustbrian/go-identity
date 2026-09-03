# go-identity

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-identity` reserves the planned Golib boundary for users, accounts, login
identifiers, credential references, verification state, account status, and
identity-domain events. The plan keeps those concepts separate from protocol,
provider, persistence, and application concerns.

## Planned responsibility

The future root package is intended to own storage-neutral identity records,
policy inputs and outcomes, repository boundaries, lifecycle events, and
explicit unit-of-work coordination. Its contracts remain proposals until they
are implemented, reviewed, verified, and released.

## Non-goals

The planned root boundary does not own:

- sessions or authentication ceremonies;
- credential verification and provider protocols;
- message delivery or user interfaces;
- organization membership or application authorization policy; or
- database clients, migrations, transactions, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle
state excludes this module from installable and released consumer catalogs.
The local `make cohesion` target validates that boundary with the exact
checksum-pinned `go-library-tools` release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove any identity behavior or API.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
