# User projections and lifecycle policy

`User` carries a case-sensitive `UserID`, `TenantID`, closed `Status` and positive
`Version`. `Validate(expectedTenant)` checks structural bounds and exact tenant
equality without changing the projection. IDs are nonempty valid UTF-8 of at
most 128 bytes, without ASCII spaces/control characters or DEL. These are
structural bounds, not canonicalization: the future service's injected canonical
ID policy must validate source IDs, including ULIDs, without rewriting them.
This does not implement directory import, source mapping or tombstone storage.

The five statuses are active, suspended, banned, anonymized and deleted.
`AllowsAuthentication` is only a lifecycle eligibility predicate: all but active,
including zero and unknown states, deny. It is not credential validation,
authorization, proof of current authoritative state or a cache freshness check.
Expired suspension/ban does not restore an identity or any prior credentials.

`StatusPolicy` configuration lists 1..32 distinct directed `StatusTransition`
edges. Unknown states, self edges, outgoing deleted edges and anonymized edges
other than deletion are rejected. The suspension maximum is positive and at most
87,600 hours; reuse cooldown is nonnegative and bounded by the same maximum.
Zero reuse cooldown and false reason requirements are explicit valid choices;
there are no implicit defaults. Configure once, freeze the exported fields and
slice before concurrent use, and copy the slice before retaining another
caller's configuration. Validation retains no borrowed state or resources.

`CheckTransition(from, to, hasReason, restriction)` revalidates the whole policy
and admits only a listed edge. The command layer derives `hasReason` from its
validated reason; no raw reason enters this diagnostic boundary. An edge's
reason requirement and the independent ban requirement both apply. Zero duration
means indefinite suspension/ban. A positive duration may apply only to suspension
or ban and cannot exceed the configured maximum. Restore/delete operations cannot
smuggle in a restriction duration.

## Adoption and security

The compiled examples show structural validation and edge checks. Neither
method performs a mutation or grants authority. The future command layer must
authorize through the existing authorization engine, check freshness and expected
versions, own transaction/idempotency outcomes, and collect required cascade
acknowledgements before reporting anonymized/deleted state as completed. This
policy must never be used as an alternative to those boundaries.

Errors are typed `InvalidInputError` values. `Field` names a fixed schema field;
`Error()` is constant and never echoes IDs, status strings or reasons. Caller
constructed errors should not put personal data in `Field`.

## Tradeoffs and FAQ

- **Are imported IDs forced through SubjectID?** No; directory IDs preserve
  their original validated representation and require a separate canonical policy.
- **Can policy resurrect a deleted/anonymized account?** No. Anonymized records
  may proceed to deletion, never to active identity.
- **Does an allowed edge prove deletion succeeded?** No; it is only a proposed
  edge check. Durable lifecycle/cascade commands remain implementation work.
- **Can I mutate policy while using it?** No. Its exported configuration is
  caller-owned and must be frozen for concurrent reads.
