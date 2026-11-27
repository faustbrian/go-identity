# Changelog

## Unreleased

- Add opt-in conditional Group PATCH with the original If-Match, bounded
  PatchOp, shared quota and native replay. Keep Group PUT independent.

- Add opt-in conditional Group PUT using the original strong If-Match, shared
  protocol quota and native replay. Return the validated Group, ETag and
  Location without enabling another Group operation.

- Add opt-in managed-bearer Group Create over HTTPS. Preserve native Group
  validation and membership authority, shared protocol quota, and the exact
  committed Group, ETag and Location.

- Add independent opt-in managed Group Get and List over HTTPS, preserving
  native authorization, shared quota, Group projection and the Get ETag.

- Add opt-in conditional User PUT with full native replacement, exact original
  If-Match and replay, shared protocol quota, and validated User/ETag/Location.

- Add opt-in issued-bearer User PATCH. Preserve native If-Match, canonical
  replay, and User/ETag/Location under the shared protocol quota.

- Add opt-in managed conditional User Delete on the exact resource route.
  Forward singleton If-Match to native authority, forbid client retry keys and
  alternate input channels, and reuse shared atomic protocol admission. Return
  only bodyless 204 or bounded redacted errors; native source withdrawal and
  headerless replay remain unchanged, without selecting another operation.

- Add opt-in managed-bearer User Create at the exact SCIM collection POST.
  Delegate bounded raw schema input and native command custody, forbid client
  idempotency keys, and charge shared atomic protocol quota after current native
  authority. Return 201 with validated native Location, exact ETag and body;
  no other route or write is selected.

- Add opt-in managed-bearer User Get at the canonical single-resource route,
  retaining the native bounded projection and exact ETag after current native
  authority and one shared atomic protocol admission. No implicit method,
  conditional-read, write, collection, search or discovery variant is selected.

- Add opt-in managed-bearer User List at the exact SCIM collection route.
  Preserve bounded RFC query scalars for the native snapshot owner and charge
  the existing shared atomic protocol quota only after current native authority.
  No dynamic Get, writes, search, Groups or discovery is selected.

- Add opt-in managed connection creation with explicit verified bearer sessions,
  original native request-key custody and shared atomic administrator admission.
  Newly confirmed native creation may present its one-time bearer; retries return
  only the safe original connection. Cookie authority, provisioning, rotation and
  deletion remain unselected.

- Add independently selected managed connection Get/List over strict-session
  bearer HTTPS, with canonical shared safe-read admission and native current
  administrator authorization. Return only bounded safe scoped projections.
- Select SCIM Bulk and matching discovery over one native executor. Require
  a shared atomic quota and return only a complete, currently authorized
  BulkResponse under the original request's replay policy.
