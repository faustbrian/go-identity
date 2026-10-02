# Typed additional fields

`AttributeSchema` declares versioned `FieldPolicy` entries. Each field states
kind/cardinality, default, normalization, input/output permission, write class,
sensitivity, indexing and migration version. `schema.Validate()` is structural
validation only. `NewAttributeProcessor` freezes a deep copy without callbacks
or storage access; configure dependencies once and do not mutate them while used.

## API and adoption

Use `AttributeProcessor.Prepare(ctx, AttributePrepareRequest)` from trusted
identity-command composition, with the exact tenant, target, schema version and
upstream `authorization.DecisionContext`. This context must never be decoded
from a client request. The allowed operations are `identity.user.create`,
`identity.profile.update` and `identity.user.update-admin`; all use the exact
`identity.user` resource ID. IDs preserve canonical ULIDs and confer no authority.

Explicit configuration requires a concurrency-safe `clock.Clock`, a duration
up to one minute, current policy revision, canonical UserID validator,
`NormalizeAttributeFunc` and `ValidateAttributeFunc`. The callbacks must be
bounded and side-effect-free, without stores, transactions or workflows.
Normalization is delegated to a pinned, stable versioned implementation of
Unicode/identifier/phone policy; this module does not silently use toolchain
Unicode tables or claim normalization merely by naming its enum. Validation sees
normalized, intrinsically bounded values and private copies of field policy and
value. A callback cannot rewrite the prepared value by mutating its copy.

The compiled schema example shows a string field declaration. Preparation
requires real explicit policy composition; a schema declaration is not a grant.
The processor owns no background workers, synchronization or database handles.

## Bounds, presence and versions

- Schema ID: 1..128 UTF-8 bytes, without ASCII whitespace/control characters.
- Schema: positive uint32 version, 1..128 unique fields. Each field's positive
  migration version must equal it; no automatic migration or version fallback.
- Field names: 1..128 lower ASCII letters/digits/underscores, starting with a
  letter. `id`, `tenant_id`, `status` and `version` are reserved core fields.
- Strings: valid UTF-8, at most 4096 bytes. A list has 0..64 string scalars.
  Combined string bytes across values/defaults in one preparation: at most
  256 KiB, checked before copying and again after normalization expansion.
- False, zero int64 and an empty string are present values because Kind selects
  the active arm. A non-nil empty list is a present empty replacement; nil is
  absence. Inactive scalar arms must be zero; mixed or unknown kinds fail.
- Nonzero time scalars are converted to UTC without changing their instant.
  Integer values never pass through JSON float64 or a narrower integer.

Defaults fill only omitted fields on create, in schema order. Explicit values
replace them, including explicit empty values. Updates never reset absent fields
to defaults. A default may populate an input-denied field but still requires its
write-class authorization and validation. Input permissions reject explicit
writes before policy/callback work. There is no removal/patch expression here.

## Authorization and security

The operation requires upstream Allow before normalization, and each field,
including defaults, independently requires Allow at the configured revision.
Self-class writes additionally require a user actor whose ID matches the target.
Administrator/system classes are required metadata, not roles inferred from a
principal, operation name or caller-supplied string. The existing policy service
must explicitly authorize them. No identity-owned decision engine is introduced.

Resource attributes reserved to preparation are overwritten: `identity.schema.id`,
`identity.schema.version`, `identity.fields.first`, `identity.fields.second`,
`identity.field`, `identity.field.write_class` and `identity.field.sensitivity`.
The two field-name sets preserve the 128-field admission bound without exceeding
the upstream 64-element collection bound. Operation admission removes any
caller-supplied per-field class/sensitivity. Field contents are never added to
authorization context; policy receives safe metadata only. Secret fields cannot
be indexed or output-readable and must not be used as credential storage.

Failures return no partial values: unknown/duplicate fields, stale versions,
malformed values, mismatched scope, denied/stale decisions, callback errors or
panics, deadline expiry and cancellation. Dependency details/values are absent
from errors. Cancellation/deadline errors unwrap to the standard context error.
One trusted clock sample supplies decision time; elapsed work uses bounded
context deadlines, not subtraction from untrusted wall time.

## Tradeoffs, FAQ and unfinished integration

**Does Prepare mutate a user?** No. It returns owned typed values. The durable
command must independently bind these values, actor/tenant, authorization policy,
schema version and command identity, and enforce idempotency and aggregate fences.
Prepared slices are not opaque proofs and cannot be used as authorization tokens.

**Does OutputPermission redact reads?** Not by itself. Read composition must
intersect field policy with its own authorization and redaction. Current user
queries return only the four core fields; extended-field output is still pending.

**Does Indexed create an index?** No. It is a schema decision for the storage
adapter and migration owner. No PostgreSQL indexes or persisted field migrations
are implemented or claimed by this slice.

Creation/mutation integration, persistence, lifecycle/privacy handling, full
typed-policy/catalog reconciliation and module release gates remain pending.
Intrinsic bounds plus custom validation are deliberately explicit: consumers
cannot safely rely on a permissive implicit validator or normalizer.
