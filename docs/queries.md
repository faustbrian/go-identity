# Authorized user lookup

`NewUserQueryService` composes a `UserQueryRepository`, the exact upstream
`authorization.Service`, a `RedactFunc` and explicit `UserQueryConfig`. This is
the reusable read implementation to be composed by the full identity service,
not an alternative authorization engine or independent directory authority.
Creation performs no I/O. Nil/typed-nil dependencies, missing callbacks, zero
policy version, invalid policy ID and nonpositive/over-one-minute duration fail.
Redaction reasons must be registered explicitly: 1..32 unique nonempty codes,
each at most 64 UTF-8 bytes with no ASCII whitespace/control characters.
The constructor copies the registration slice; later caller edits do not alter
the policy. Missing or unregistered decision reasons deny the projection.
Configuration is copied; dependencies/callbacks must be concurrent-safe.

## Trust boundary and sequence

`UserGetRequest.Context` is the upstream `authorization.DecisionContext` supplied
by trusted, authenticated composition. Never decode it from client JSON, copy
an actor override, or derive administrator permissions from a user ID, a role
string or credential scopes. Direct Go callers operate on the trusted side of
this boundary; the query service is not an authentication ceremony. The future
HTTP adapter must resolve the actor through its selected authentication feature.

The request must bind the exact tenant, target, `identity.user.get` action,
`identity.user` resource type and configured policy version. Actor kinds are user,
API key or service account. Subject groups are bounded to 32; each attribute map
to 128 entries, string values to 4096 bytes and string sets to 64 elements.
Identifiers and keys use their documented structural bounds. Admission occurs
before input cloning or callback/storage work.

The service derives a context no longer than MaximumDuration, preserving an
earlier caller deadline, validates the target through the injected canonical-ID
policy without rewriting it, samples the configured `clock.Clock` once, and
requires an explicit upstream Allow at the requested revision. Stale, unknown,
NotApplicable or denied decisions never reach repository lookup. Policy errors
and panics fail closed. Authorization retains its existing engine ownership.

The repository must return the exact requested user/tenant with known status
and positive version. It honors context and owns authoritative lookup semantics;
the service does not construct a transaction. ErrUserAbsent and policy denial
are exposed identically as ForbiddenError. Other repository errors or malformed
results produce a redacted UnavailableError without a user.

Redaction receives copied field names and immutable tenant/viewer/resource,
operation, policy version and deadline bindings. Its policy ID/version must
match configuration and the reason must be registered. The current User
projection has four required fields:
id, tenant_id, status and version. All four must be explicitly visible, once
each, with no unknown or redacted fields; otherwise the whole projection is
omitted. Optional attributes and richer field projections remain upcoming core
work. No redaction failure falls back to an unfiltered user.

Cancellation and expiration are checked after every callback and repository
call; no partial output is returned. Dependencies must honor context: the
service does not spawn a goroutine to pretend an uncooperative dependency stopped.
Panic recovery redacts the panic and returns no projection. Context errors retain
errors.Is classification without retaining dependency diagnostic strings.

## Development and adoption

Compiled tests prove successful lookup, exact admission and denial before reads,
real authorization-engine default denial, malformed results, redaction isolation,
cancellation and error/panic handling. The test repository is not a production
adapter. Durable PostgreSQL, user listing/creation, mutation/cascade execution,
full PolicySet composition and comprehensive release gates remain required work.

Authorization is pinned to the committed local identity-contract candidate;
it has not been published under this goal. Development uses an explicit
task-owned workspace binding that candidate. Published replacement-free
consumer adoption must be proven at the release boundary; do not describe
workspace composition as released dependency availability.

## FAQ

- **Does UserGet authenticate the caller?** No. Trusted composition supplies
  the already authenticated upstream decision context; authorization still must
  explicitly allow the exact bound query.
- **Does a suspension timestamp restore access?** No. Reads can return blocked
  administrative projections when authorized; downstream authentication must
  separately enforce the lifecycle state and its authoritative freshness.
- **Are imported ULIDs replaced?** No. The injected validator admits or rejects
  the original ID, and repository identity must match it exactly.
- **Does this prove the 30-second shared-issuer revocation guarantee?** No.
  That guarantee needs the affected authoritative version and cache paths.
