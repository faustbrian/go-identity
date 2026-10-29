# Opt-in API-key management HTTP

Development profile for Go1.27. This optional module composes the public
`identity/apikey` native ports with the existing HTTP decoder, network resolver,
session owner and shared atomic secret-rate limiter. It owns no API-key store,
policy engine, replay journal, transaction or migration.

## Selected surface

| Selection | Method/path | Closed JSON body |
| --- | --- | --- |
| `Create` | `POST /v1/apikey/create` | `name`, `permissions`, `expiresAt` |
| `Rotate` | `POST /v1/apikey/rotate` | `keyID`, `expectedVersion` |
| `Revoke` | `POST /v1/apikey/delete` | `keyID`, `expectedVersion` |

Each route requires exactly one `Authorization: Bearer <native password session>`
and one original `Idempotency-Key`. All three use keyed native custody. This is
the explicit strict-bearer profile of the canonical operation IDs, not the
draft rotate/repeat transport labels. Cookie profiles are not selected, and
ambient cookies cannot supply authority. No recovery route is invented.

Use `NewFeature(FeatureConfig{Config: Config{...}, Create: true, ...})` with actual
owned `apikey/postgres.Service` ports, the same native session validation owner
and deployment-wide `KeyedSecretRateLimiter`. Only selected native ports are
required. Obtain operations with `identityhttp.NewOperationDescriptors`, then
compose `identityhttp.NewRouter` using the same network configuration. Empty
selection should omit this feature entirely; disabled routes and schemas are
absent. Construction performs no database, policy, credential or provider IO.

## Input and output custody

- Exact HTTPS tenant hosts and trusted full IP come from `NetworkConfig`, not
  body fields or untrusted forwarding headers. Actor, tenant and native
  configuration are not request-selected. Query inputs are forbidden.
  The explicit organization profile below accepts only its typed owner target.
- JSON fields are exact, closed and duplicate-free. Names are at most128 UTF-8
  bytes. Permissions are an explicit array of at most64 bytewise-sorted unique
  strings, each at most128 UTF-8 bytes; `[]` is a zero-permission ceiling.
  Missing/null permissions deny. Absolute expiry must have microsecond precision.
- Configure body limits at least64KiB, decoded limits at least16KiB and at least
  72 fields so supported native grants do not become unusable through HTTP.
  Creation additionally requires nesting depth at least2 for its permissions
  array; independently selected scalar-only rotation/revocation allows depth1.
  The native owner independently enforces current permissions, original primary
  authentication freshness, allowed lifetime and non-expanding rotation.
- Responses are bounded no-store JSON and never issue cookies or redirect.
  `committed` and `commitOutcome` retain native historical disposition; they are
  not current authentication or delivery confirmation. Keep original safe
  `commandID`/`recovery` scope for direct, current-authorized native recovery.
- Only original committed invocation-local custody can return `secret` once.
  It is absent on replay, status recovery and unknown commitment. Lost or partial
  delivery is not permission to reconstruct plaintext or issue a replacement.
  No automatic retry occurs. Reuse exactly the original input/key for retry.
- Shared HTTP IP/subject budgets are separate from native protected-risk
  counters. Neither admission grants domain authority. Outages fail closed.

## Supported profile and remaining work

This slice selects modern self-owned and explicitly selected organization-owned
human password-bearer management with unlimited quota, no cache and native Narrow
permission reduction. Legacy import, finite quota, projections and API-key-as-session authentication
are separate profiles, not fallback behavior. Full Reference composition,
release qualification and complete M21 acceptance remain in progress.

The tests distinguish wire-port doubles from the genuine PostgreSQL/HTTPS
consumer in the owning native module. Local workspace integration is not proof
that an unpublished module is available to a clean public consumer.

## Explicit organization profile

Set `FeatureConfig.OrganizationOwned` and supply `Config.OrganizationCreator`
when selecting `Create`. The existing create route then accepts optional
`organizationID`; its absence still selects the ordinary self-key port. Unknown,
null, empty, duplicate, aliased and oversized owner fields deny before session,
rate or native work. The optional property appears only in the selected OpenAPI
request schema. Actor and tenant still come exclusively from the genuine bearer
and trusted host; an organization target is not a supplied principal.

Supply the actual native `NewOrganizationService` for selected organization
management. Its current-member policy, protected authority fences and independent
credential epoch own permission to act; HTTP neither reads membership tables nor
creates an organization store. Rotation/revocation select the key's immutable
actual owner. The response's recovery actor remains the human manager rather
than a fabricated credential-owning user. Retain the target organization with
the original key/input for direct `RecoverOrganization` status queries.

For user-only HTTP, supply native `NewService` mutation ports. The wire flag is
not a replacement for that domain restriction, and HTTP cannot undo effects
from a wrongly supplied port. Reference composition must select the matching
native profile even when its separate direct API enables organization support.
Unselected organization input and organization result projections fail closed;
neither failed nor unknown output reveals a key, and wrong-owner committed
output is reported as unavailable without disclosure.
