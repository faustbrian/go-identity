# Changelog

## Unreleased

- Add bounded two-credential upgrade and two-command recovery contracts.
  Target proof, guest possession, explicit merge plan and unchanged remember
  policy remain distinct; replay/recovery is metadata-only and forbids
  implicit credential disclosure. Native authenticated orchestration is still
  required before selecting an upgrade endpoint.

- Define bounded typed upgrade merge decisions with a distinct permanent target,
  canonical conflict ordering and owned snapshots. Plans carry no credentials
  or transfer authority; native atomic upgrade remains in development.

- Reject anonymous TTLs with sub-microsecond remainders during policy
  construction, rather than accepting configuration that native signin cannot
  persist without changing its original expiry.

- Add the authenticated anonymous self-deletion port and original possession-
  bound metadata recovery. Matching native composition enforces current
  retention, atomic disposal and session withdrawal without permanent credentials.
  Upgrade and complete unit qualification remain in development.

- Define bounded self-deletion request custody with exact lifecycle version,
  original credential and CSRF possession, reason and retry identity. Native
  deletion and retention enforcement remain in development.

- Define bounded explicit anonymous policy and original subject/lifecycle
  metadata. Reserved placeholders are not contacts or verification authority;
  durable workflows and complete module qualification remain in development.
- Add bounded original pre-auth signin input and credential-free keyed recovery
  correlation. These structural contracts grant no issuance, possession or
  disclosure authority; native public signin composition remains unfinished.
