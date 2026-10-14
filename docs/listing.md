# Bounded user listing

`NewUserDirectoryService` composes the existing `UserQueryService` with a
`UserDirectoryRepository` and explicit `UserListConfig`. `UserGet` is unchanged;
`NewUserQueryService` remains get-only and rejects listing as unavailable.
The service owns no database, transaction, goroutine or lock. Dependencies and
validators must be concurrency-safe and honor their bounded contexts.

## Admission and authorization

`UserListRequest` requires an exact tenant, trusted authenticated upstream
decision context, 1..100 limit and 1..16 unique known statuses. Optional
identifier filtering pairs one closed namespace with a canonical value of at
most 512 UTF-8 bytes. It is exact indexed lookup, never arbitrary text search.
The injected bounded validator validates without rewriting canonical values.
Status order is normalized; other values preserve their canonical bytes.

The collection action is `identity.user.list`, resource type
`identity.user.collection`, resource ID the exact tenant. Revision must match
the immutable query configuration. As with UserGet, the transport must derive
the decision context from real authentication, never decode a client actor
override or infer administrator permissions from an ID or role string.

The service overwrites these reserved resource attributes with actual input:

- `identity.query.statuses`: string set of normalized statuses;
- `identity.query.identifier_kind` and `identity.query.identifier`: strings;
- `identity.query.limit`: signed integer, bounded to 100;
- `identity.user.status` and `identity.user.version`: null for the collection,
  then actual snapshot status and canonical unsigned-decimal version string
  for each row. A string preserves the full uint64 version without narrowing.

At most 128 resource attributes, including reserved members, are admitted.
Collection denial/stale policy prevents all repository access. Every returned
row is independently authorized for `identity.user.list` on `identity.user`
with its exact ID before redaction. Snapshot possession does not bypass policy.
Denied rows are omitted, not returned as IDs or totals. Redaction uses the same
registered policy/reason and four-field projection contract as UserGet, with
`identity.user.list` operation binding. No unfiltered fallback exists.

## Snapshot ownership and continuations

`ListUsersQuery` carries copied filters, safe fields, bounded limit, original
exclusive expiry and an opaque storage-neutral `Cursor`. The repository owns
the immutable retained snapshot: bytewise ascending canonical UserID, no
duplicates, exact tenant and indexed filters. `NewCursor` accepts a canonical
random snapshot SubjectID and a positive scanned position through MaxInt64.
An initial zero cursor starts a snapshot; it is not a proof or permission.

The repository must retain that snapshot through ExpiresAt, never switch it
or recreate an expired snapshot, and return a terminal empty page when done.
A nonterminal cursor advances by exactly the number of scanned rows. The
service validates size, tenant, status, order, cursor advancement, same snapshot
and cross-page ordering; it then copies visible users into caller-owned results.
The hidden encrypted last ID prevents repeated/retrograde pages. Continuation
advances over denied/redacted rows without backfilling or disclosing their IDs.

This core defines and tests the storage contract, not durable PostgreSQL
snapshot retention. The PostgreSQL adapter must implement real retention,
concurrent directory changes and bounded cleanup before release proof.

## Cursor profile and lifetime

CursorKey is an independently generated 256-bit secret; zero is rejected.
Keep it out of logs and use consistent configuration on serving replicas.
Rotation invalidates previous cursors; it does not revoke sessions or keys.
CursorTTL is explicit, positive and at most 15 minutes. No default is inferred.

The private v1 cursor uses standard-library AES-256-GCM with random nonces plus
HMAC-SHA256 over the version and ciphertext. Encryption/signature keys are
domain-separated with HMAC using `golib.identity.user.list.cursor.v1`.
Strict unpadded base64url input is bounded to 1024 bytes. Verify the outer MAC
before decryption, then reject unknown/noncanonical JSON or invalid claims.
Ciphertext hides snapshot positions and last user IDs, including omitted users.

Each cursor binds tenant, actor ID/kind, normalized filters, limit and policy
identity/version. It retains initial issuance and exclusive expiry across pages;
neither retry nor continuation extends its lifetime. All pages still authorize
the current trusted context. Callback groups/attributes are not cached authority.
Wire timestamps use positive Unix nanoseconds (1970 through the supported
2262 range); zero/overflowing clock samples fail closed.

One configured wall-clock sample selects the validity interval per page.
Process-local monotonic elapsed time reduces the remaining budget, and the
derived context is capped by both request duration and original snapshot expiry.
Every callback/read and final result checks cancellation. Panics, policy or
repository errors, malformed pages and expired/tampered tokens return stable
redacted errors without partial users or a cursor. Dependencies may not ignore
cancellation; no goroutine is spawned to disguise an uncooperative operation.

## Adoption and remaining scope

The compiled tests cover page traversal, live-directory changes against an
immutable test snapshot, current row denial, copied configuration/results,
cancellation, expiry, tampering, scope changes and concurrent readers. They
do not establish durable retention, external interoperability or the 30-second
shared-issuer revocation guarantee. User creation, mutation, rich attributes,
complete PolicySet, PostgreSQL, catalog reconciliation and release gates remain
required work. Listing is directory administration, not a login workflow.
