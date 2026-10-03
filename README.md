# identity

Composable backend identity-domain ownership for Golib. This module is under
development and targets Go 1.27.

## Security-profile construction

`NewIdentitySecurityEventV1(clock.Clock)` constructs the shared typed profile
builder. `Build(context.Context, SecurityEventInput)` returns the existing
`audit.Record`, not a new envelope, using exact 16 KiB/256-byte profile limits,
secure record IDs, canonical numeric versions and explicit primitive redaction.
Registered HIBP profiles distinguish padded and explicitly unpadded checking;
unknown profile identifiers are rejected rather than asserted as padded.
Initial supported actions are HIBP query, match detection and range rejection;
unsupported action contracts reject. Retention is protected and changes are
explicitly absent. Outcome and provider evidence remain separate classifications.

Attribution must come from trusted composition, not HIBP SubjectScope or raw
HTTP input. An authentication-attempt subject must be a real canonical
PreAuthTransactionID; identifier digests and fabricated user IDs are invalid.
Canonical nonzero base64url IDs, uppercase ULIDs, lowercase UUIDs and 128-bit
hex IDs are preserved unchanged for tenant/actor/policy attribution. Syntax
validation does not prove provenance or confer authority. No arbitrary attribute,
description, network, breach-count or provider-payload field exists.

The builder is immutable and concurrency-safe under the borrowed clock contract.
It owns no persistence, retries, goroutines or shutdown. Persist through the
existing audit sink/recorder or transactional contributor; building a record is
not proof that audit delivery happened. Audit v1 is retained to preserve the
existing durable adapters' record identity. Other security action contracts,
provider-event integration and durable composition remain implementation work.

Current implemented slices are subject/pre-authentication ID
contracts, structural user/status-policy validation and authorized user reads
with bounded, stable-snapshot listing, versioned typed-field preparation and
authorized explicit-ID creation/recovery through a storage-neutral command owner.
Pure risk, claims, retention and redaction callbacks have a bounded validated
policy evaluator; the authorization engine remains the upstream service.
Administrative typed-field updates enforce expected-version commands and scoped
recovery through the same durable owner.
Self-service profile reads/updates use a distinct safe projection and exact
current-human-subject scope, bounded image origins, typed fields and recovery.
Suspend/ban and restore/unban use versioned commands with distinct user authority
versions, exact required-consumer manifests and pending cascade admission.
Account reads expose scoped permission-filtered metadata; the shared final-access
check excludes the removed link, expired/disabled methods and API keys.
`CheckCredentialAuthority` separately fences the exact credential record version
and tenant/user credential epoch against one current primary observation. It
denies inactive users, disabled references, wrong ownership and exclusive expiry;
ordinary user aggregate versions are not security epochs. The narrow
`CredentialAuthorityRepository` is an owned primary-read contract, not an
application-provided verifier. These metadata checks do not establish proof
provenance, consume a proof, refresh validity, or replace the other authority
dimensions required for session issuance. Its durable adapter remains pending.
Account linking and identifier changes have exact signed-intent command
admission/recovery; the platform-owned durable adapters and real feature proof
ceremonies remain required before these become complete public workflows.
Feature adapters can structurally match common command scope to a trusted
`FeatureOperation` with `CommandBinding.ValidateFor`: exact operation/schema,
safe identities, positive policy version and explicit required/omitted record.
This does not authorize or register a feature, enable execution or open the
existing kernel command/receipt union. Coordinator feature phases remain in
development; adapters must not substitute private transactions or journals.
`NewFeatureCommand` freezes an explicit structural feature branch: exact binding
and operation plus a bounded named scalar payload (including full uint64
versions, microsecond UTC instants and copied binary metadata). It grants no
authentication, schema completeness, current authority or execution readiness.
Feature adapters must exhaustively map native domain commands and validate their
schemas; applications do not implement that workflow. Raw credential/bearer
secrets are forbidden. Opaque commands redact formatting and deny JSON; trusted
returned projections are never responses, logs or evidence snapshots. Existing
kernel receipts and PostgreSQL admission remain closed to this new branch.
`CommandResult.Feature` carries only an exact structural feature descriptor and
safe primary-record before/after versions, never a bearer or native response.
Every outcome retains its descriptor; only committed record mutations have one
successor version and an audit ID. Mixed kernel payloads fail validation. Nil
feature fields are omitted from JSON so historical kernel replay bytes remain
unchanged. Validation does not prove a commit or enable feature execution;
trusted durable adapters and feature-native result policy still own those claims.
Remaining destructive lifecycle commands, durable repositories, complete policy composition,
hooks, directory import and privacy workflows are not implemented yet.

## Quick start

```go
id, err := identity.NewSubjectID()
if err != nil {
    return err
}
wire := identity.FormatSubjectID(id)
restored, err := identity.ParseSubjectID(wire)
```

The compiled examples demonstrate persisted-value reconstruction. See
[ID semantics](docs/identifiers.md) for API, adoption, security, operations,
tradeoffs and FAQ. This is not a complete login service or administrative UI.
See [user and lifecycle policy](docs/users.md) for structural validation and
transition constraints, including their distinction from authority and writes.
See [authorized user queries](docs/queries.md) for the read-only service and
its trusted composition boundary. No PostgreSQL adapter is implemented yet.
See [user listing](docs/listing.md) for filters, row permissions and encrypted
signed snapshot cursors; a cursor is never authority.
See [typed additional fields](docs/attributes.md) for normalization, defaults,
per-field write enforcement and the boundary between prepared values and a
durably authorized command.
See [creation and recovery](docs/creation.md) for the current command boundary,
durable outcome semantics and the pending PostgreSQL/keyed-admission integration.
See [policy composition](docs/policies.md) for typed fail-closed callbacks and
current read/create redaction integration.
See [administrative updates](docs/updates.md) for field policy, replay-before-
version-check semantics and required durable status/version fencing.
See [self-service profiles](docs/profiles.md) for name/image, safe additional
fields, current subject policy and the pending session/keyed/SQL composition.
See [status commands](docs/status.md) for authorization, expiry, replay, pending
cleanup and authority-preserving restore behavior.
See [account ownership](docs/accounts.md) for safe reads, credential references
and the final-access boundary that transactional unlink must enforce.

## Development verification

Run Go commands with a task-owned disposable `GOCACHE` and delete it afterwards.
The current focused checks are `go test -race ./...`, `go vet ./...`, and
`go test -run '^$' -fuzz '^FuzzIDParsing$' -fuzztime=10s .`.
Comprehensive module/release gates remain pending during implementation.

## License

[MIT](LICENSE).
