# go-identity

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API. The module is
> non-releasable while implementation and executable security evidence are
> absent.

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

Implementation and hardening have not started; release is blocked. The current
module declaration exists only so repository tooling can validate the planned
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

The [versioned threat model](docs/security/threat-model-v0.1.md) records
candidate trust boundaries, abuse cases, and verification obligations. It is
planning evidence only. [Security reporting](SECURITY.md) uses a private
GitHub advisory channel; no released version is currently supported.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state and
`releasable: false` exclude this module from installable and released consumer
catalogs. Release remains blocked until implementation and focused, executable
security evidence establish the relevant controls.
The local `make cohesion` target validates that boundary with the exact
checksum-pinned `go-library-tools` release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove any identity behavior or API.

Use Go 1.27.2 and the qualified public Tools v2.1.2 binary; the planned
module minimum remains Go 1.27.0. `make check`, `make ci` and `make fast-check`
validate configuration, repository structure, cohesion, offline specification
decisions, local documentation links and whole-tree/history secrets.
CI uses the same structural commands plus validated PR-base or push-before
changed-content secret checks on every change. Ordinary Required has a
five-minute job limit; changed secrets have a forty-second fatal timeout.
Scheduled/manual runs retain whole-tree secrets and online authority refresh.
`make check-full` explicitly preserves the previous full/online contract.
These commands do not run application tests or establish runtime/release proof.
See [contributing](CONTRIBUTING.md) for public tooling installation and scope.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).

Continue with the [documentation index](docs/README.md).
