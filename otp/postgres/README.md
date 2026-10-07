# OTP PostgreSQL

The private Send initiation envelope authenticates the kernel's complete
`RequestKeyPreparationBinding` and immutable native configuration. It retains
the original flow, recipient or suppression branch, authority, times and
authentication-lane identifier/network/device dimensions. Its attempt identity
is the original server-issued command ID. Restoration requires separate bearer
possession and never renews authority, freshness or expiry. Suppressed originals
cannot become ordinary issuance commands. This codec does not itself implement
native request-key preparation, current risk admission or a public Send service;
those remain implementation work. Existing custody profiles are unchanged.

Native Send can retain an identity-owned recipient snapshot separately from
the original authenticated subject or anonymous flow. Its new request profile
and authenticated issuance wrapper preserve the original identifier,
verification, security versions and observation time through restart. Primary
recipient locks and comparisons run before generation and again in the sole
issuance transaction. The legacy no-recipient profiles remain readable;
anonymous discovery never grants a user subject to the command. Public Send
must compose this with owned recipient resolution and Authentication-lane risk
admission; that public composition is not yet available.

The private pre-generation Send input now preserves the original complete
session/pre-auth continuation, attempt policy, primary expectations and initial
times without a fabricated challenge or digest. Mapping is deterministic and
checks separately supplied original bearer possession. Its bounded closed
request frame is distinct from generated issuance and submitted-attempt frames;
existing retained issuance bytes are unchanged. This is an invocation-memory
input, not an authority proof or a public Send endpoint.

Private native composition now enables prepared Send on one immutable registered
OTP contributor, preserving its existing check/consume behavior. The existing
coordinator admits original primary authority before its durable generation
marker; the owned core generates one code for the digest and versioned template,
then the adapter retains authenticated encrypted challenge/delivery custody.
Restoration conserves original request, configuration, bearer variant, times and
output generation. It rejects changed same-version template contents as well as
changed bindings. Final execution restores invocation-local delivery through the
stable owner's Work identity and atomically stages challenge, send count,
replacement, encrypted delivery, audit and lifecycle. Failed effects roll back
together; terminal replay does not generate again. Install the kernel's optional
`PreparationMigrationSource` and every retained digest-key metadata version.

This remains private platform composition, not a public Send endpoint or a
caller-supplied recipient/risk clearance seam. Native recipient resolution,
identifier/IP/device risk admission, enumeration-safe no-op selection and the
public Send service remain unfinished. Do not activate these private phases from
application request handlers. Full release/composition gates remain pending.

## Native issuance command custody

`AttemptCodec.MapIssuancePreAuth` and `MapIssuanceSession` bind an initial
digest-only `otp.Challenge`, original server command and `AttemptAuthority`
expectations into a separate versioned encrypted issuance profile. The complete
original session/pre-auth record, purpose, destination, workflow target, policy,
remember choice and initial times survive restart. No submitted code is invented;
code and cookie/token bytes have no field in the closed frame. The submitted
bearer remains separately held by the root command. Keep this custody private.

The native send descriptor is owner `identity/otp`, operation `identity.otp.send`,
version 1 and required record target equal to the new challenge ID. Its schema
is `identity-otp-send` for a user target or `identity-otp-send-preauth` for an
explicit anonymous-flow target. Both use code-free command construction. The
anonymous namespace must equal the original pre-auth transaction ID. These
descriptors are enabled only by the private prepared-Send composition; ordinary
contributor constructors continue to expose only the existing check schemas.

Map once per logical server request and retain the original immutable command
through retries or ambiguity. Re-encryption changes command intent. Retain exact
named wrapping/code/session keys until dependent history retires; key rotation
never substitutes a newer key or changes an earlier policy/time. Invalid input
returns a zero command and redacted error, preserving caller cancellation.
The encrypted issuance frame retains its original keyed scope commitment;
changing code-key bytes under the same version is rejected, not silently
reinterpreted. The root dependency is pinned to the committed code-free bearer
constructor baseline. Publication and standalone release evidence remain pending.

The adapter's private possession check compares the separately submitted bearer
against the exact original commitment under the retained named session key. It
does not adopt a current row or authenticate from a supplied digest. Wrong,
absent or cross-variant bearers deny. This proves possession only: current
primary authority, flow state, operation permission, risk and after-lock time
checks must still precede issuance in the owning transaction. Mapping and local
custody restoration do not generate codes, persist a challenge, consume a flow
or enqueue delivery. Native Send/delivery composition remains under development.

## Native issuance storage

Install `IssuanceMigrationSource` after `SendFamilyMigrationSource`, using the
same dedicated schema and a separately allocated forward migration version.
It preserves populated challenge custody and adds an immutable keyed family
binding plus bounded active-family lookup indexes. Older unbound issuance
writes fail closed after installation; existing consumption and recovery
remain compatible. Do not activate the new writer before installing both
extensions across its selected database.

The private writer commits a proposed send-history append, replace-policy
revocation and a new digest-only challenge in its caller's original transaction.
Retain-policy predecessors keep their original times, versions and counters.
Reserved predecessors cannot be replaced; unknown reservations require their
existing owning-command recovery. A duplicate command/challenge or failed
insert requires rollback of the whole proposal, preserving predecessors and
allowances. Stored issuance fingerprints come from the sole kernel claim,
not caller-selected bytes. Replacement is represented by terminal `revoked`.

Legacy populated challenges have no reversible destination/family identity.
Migration does not guess or attach one. A live unbound challenge blocks new
issuance for its subject/purpose until its existing owner terminalizes it.
Already terminal legacy custody remains unchanged. New family bindings cannot
be detached or rewritten, including during an otherwise valid attempt update.
Expired unreserved challenges, including legacy rows, retain their tombstones
without occupying the live predecessor bound. Unresolved reserved challenges
remain exclusions even after expiry. Separate bounded indexed live/reserved
candidate lanes prevent old retained history from becoming a lifetime quota.

This is native storage, not a public Send endpoint or a complete workflow.
The owning adapter must still enforce original-flow/current authority and
risk, generate/render once, stage encrypted delivery and commit audit/journal
through the existing coordinator. No application-written store, separate
transaction or guessed unknown outcome is supported.

The private native execution phase now admits the original user or anonymous
flow, locks shared abuse and send-family state, and stages the frozen challenge
and encrypted delivery in the same kernel Work. User security epochs, optional
credential authority, directory and authorization authority remain original;
expiry is rechecked after lock waits. Delivery or audit failure rolls back
challenge, send allowance, replacement and protected effects together. Retained
challenge tombstones prevent a negative recovery vote; recovery never generates
a replacement code or guesses that missing delivery payload means rollback.

This phase is deliberately not a public constructor or usable Send workflow.
Owned risk admission, recipient resolution, same-code generation/rendering,
cleanup and complete login remain in progress. Consumers must not supply their
own orchestration to bypass those pending platform responsibilities.

## Original authenticated-session custody

The opt-in private v4 attempt frame retains the complete session-owned original
record inside the existing encrypted envelope. Session/family IDs and versions,
all authority dimensions and optional-presence flags, lookup digest, resolved
remember policy and original authentication timeline survive a fresh codec
instance. The existing authority-envelope v3 may wrap this frame; legacy v1
and pre-auth v2 bytes are unchanged. Parsing rejects unknown/mixed profiles,
truncation, trailing bytes, noncanonical times and invalid owner projections.
No raw session token or OTP code enters this record; mapping/restoration grants
no current validity or authenticated-session admission.

Structural custody alone is not a current lookup, credential-possession proof
or operation permission. Native admission is explicitly enabled separately.

## Native authenticated-session execution

Use `NewContributorWithSession` with a separate `SessionAdmissionConfig` to
enable authenticated-session denial and consumption. The existing
`ContributorConfig` and pre-auth-only `NewContributor` remain compatible.
A session-only installation may omit pre-auth configuration; installations
supporting both contexts must configure both retained-key profiles.

Configure the session owner's identifier admission profile, retained token
keys and a positive freshness limit. The participant authenticates the separate
bearer against complete original custody, checks current primary directory,
credential, authorization, session and family authority, and denies unsupported
optional authority dimensions. It rechecks original freshness and credential
expiry after lock waits; retries cannot renew either deadline.

Reservation, exact generation takeover and protected finalization consume OTP
atomically with domain, audit and lifecycle effects. An authenticated session
is not itself a one-time reservation and remains unchanged. Sealed rollback
and restart recovery use retained OTP predecessor evidence without recovering
the bearer; ambiguous evidence retains the reservation. This is not an
operation-permission decision, risk grant or complete login workflow.

`MapSession` and `MapSessionWithAuthority` freeze the separately submitted
session token in root's opaque command branch beside the code. The latter also
retains original primary expectations. Neither stores raw token/code in its
encrypted original-session record, renews original authentication time, performs
SQL or grants live admission. A session token cannot become a pre-auth cookie;
the coordinator fingerprints its intent under a distinct retained-key domain.

## Native counted denial

`NewContributor(ContributorConfig)` now supplies the exact
`identity.otp.store` participant for the coordinator's
`PrepareOTPAttemptPlan` / `RecordOTPAttemptDenial` path. Enlist the returned
pointer alongside the real domain, audit, lifecycle and owning-feature
contributors. Configuration supplies installed OTP/session schemas, the owned
attempt codec, explicit deployment and user-policy namespace, dedicated stable
lockout key and exact retained pre-auth cookie keys. Construction copies keys,
performs no IO and creates no independent transaction or replay owner.

Use `MapPreAuthWithAuthority` once for the original submission. The participant
requires complete original pre-auth custody and the separately submitted cookie;
legacy records do not acquire fresh authority. It checks locked deployment,
tenant and applicable user/credential/authorization authority, then the original
session-owned flow, shared abuse exclusions and scoped challenge. Database time
is sampled after challenge locking; original flow and applicable credential
expiry are checked again after downstream waits. Wrong-code charging, expiry/exhaustion,
shared lockout extension, required denial audit and stable aborted receipt commit
atomically. Exact retry reads that receipt without comparing or charging again;
changed intent conflicts. Callback errors and failed audit persistence roll back
all provisional writes. Reconstruct immutable configuration on restart, retaining
the original named key material; never replace an ambiguous command by remapping.

The separate `PrepareOTPReservationPlan` / `ReserveOTPCommand` entry point now
reserves correct pre-auth submissions. `Begin`, protected feature application
and `Commit` consume OTP and pre-auth atomically with the domain, audit, outbox
and command receipt. Live replay does not charge again; exact takeover preserves
original custody and timing and rejects the previous owner. Install
`ConsumingMigrationSource` after OTP storage and session's
`PreAuthReleaseMigrationSource` before enabling this profile. The forward OTP
migration retains only the bounded encrypted code/cookie-free original envelope
inside existing challenge storage; historical reservations receive no invented
authority. Rollback releases exact predecessors only through the coordinator's
sealed noncommit phase. Restart recovery uses retained original custody, not the
submitted command/code/cookie; divergent evidence leaves reservations pending.

The denial entry point still returns unchanged for correct codes. Successful
metered checks and issuance remain pending.
Do not enable a public login workflow or supply an application-written store to
fill those gaps. Existing command journaling owns denial recovery; unresolved
participant history without exact retained evidence remains unknown. Module source pins and clean-consumer,
coverage/mutation and release verification remain pending.

`MapWithAuthority` and `MapPreAuthWithAuthority` bind original primary authority
expectations to the same encrypted original-attempt command. `AttemptAuthority`
requires deployment/tenant epochs and, for user commands, the effective user's
authorization namespace/epoch and independent user/identifier/credential epochs,
also for passwordless login. Include the credential reference whenever the
workflow uses an existing credential. Anonymous commands cannot carry user
authority. Capture these
expectations through their primary owners once; never update them on retries.
The authenticated v3 plaintext embeds the unchanged v1/v2 attempt projection
and bounded authority projection. No raw bearer/code or authority lease is
stored; existing `Map`/`MapPreAuth` framing is unchanged. Old records remain
readable but do not acquire invented authority. Restoration validates original
envelope and core MAC before returning expectations. This is structural custody,
not a permission decision or live primary check. Counted denial now dispatches
through the native contributor alongside pre-auth consuming phases. End-to-end
login and successful metered-check profiles are pending.
Enable authority-aware mapping only after every command reader supports v3;
older binaries reject this new opt-in profile, while new readers retain v1/v2.

Private native pre-auth admission now recomputes the separately submitted cookie
under its exact retained named key and authenticated original flow, then borrows
the session adapter's locked issued/reserved primary checks. Wrong, absent or
retired-key cookies cannot substitute the stored commitment. Reserved admission
requires exact command, fingerprint and current generation; primary time after
the lock owns exclusive expiry. Admission does not charge an attempt, write a
result or renew the flow. Counted-denial dispatch composes this admission with
current authority and lockout/challenge ordering. The native consuming path
composes protected execution and retained-original recovery through the same
coordinator. No public raw store is exposed.

`AttemptCodec.MapPreAuth` explicitly maps a complete bound-flow attempt and its
separate submitted `authentication.BearerCredential`. The bearer is retained
only by opaque root command custody; `Feature()` and encrypted attempt fields
never contain it. ID-only legacy continuation or malformed token syntax deny.
The original code and attempt remain unchanged. A syntactically valid wrong
cookie is still submitted intent, not proof: the native owner must derive its
commitment under the named retained pre-auth key, then compare the complete
canonical primary flow and current authority in the sealed phase. Map once and
retain the command through ambiguity; credential-free recovery cannot recreate
the bearer. Native pre-auth consumption is available; usable OTP login remains
pending until issuance and full owning-feature/session composition are complete.

## Complete original pre-auth custody

Mapping an attempt prepared with `otp.NewBoundPreAuthAuthorization` retains
the complete immutable session-owned flow inside the authenticated encrypted
command envelope. The code-free plaintext has explicit
`identity-otp-attempt-custody-v2` + NUL framing, appending the bounded full-flow
projection before the existing core command-record MAC. Legacy contexts retain
exact v1 framing, bounds and bytes. No schema migration, raw bearer, new flow
store, journal or transaction owner is introduced.

Restoration preserves canonical nanosecond UTC times, original nonce, exact
intent/policy, resolved remember choice, named cookie commitment and version;
mixed IDs, invalid fields, truncation, trailing data or changed core MAC deny.
The v2 plaintext limit is 8192 bytes; the existing encrypted wire limit remains
8192. Old v1 plaintext remains limited to 4096 bytes. Inputs are bounded before
allocation and parsing; decoding itself is structural, not MAC verification.
`restoreRecord` verifies the original core MAC and `restoreAttempt` requires
the original opaque submitted code—custody cannot reconstruct it from storage.

This profile alone is not active-flow or cookie-possession evidence. The native
participant requires it and rechecks the canonical session-owned primary
record, submitted cookie and current policy during active consuming phases.
Recovery/release instead require exact original reserved predecessors and
coordinator-proven noncommit. Legacy ID-only records may be read for compatibility
but cannot stand in for complete-flow consuming admission. Successful metered
checks and authenticated-session profiles remain under development.

Go 1.27 native storage for purpose-bound OTPs, sharing the identity coordinator's
PostgreSQL transaction domain. Experimental and incomplete: this initial batch
implements challenge storage/migrations, **not** a usable issuance or verification
service, plus encrypted original-attempt command custody. Installing it never
proves a code, grants a reservation or authorizes a
workflow. Do not implement a consumer-written store to fill the remaining gaps.

## Quick start and API

```go
source := otppostgres.MigrationSource{Schema: "otp_store", Version: 100}
history, err := source.Load(ctx)
```

Import `github.com/faustbrian/go-identity/otp/postgres`. Compose the source with
the owned `go-migrations/v3` runner and its PostgreSQL backend, after the identity
kernel migrations. Allocate `Version` permanently in the single composition
history. The example is compiled in tests. `Load` is pure, cancellation-aware,
concurrent-safe and returns independently owned history. It accepts a dedicated
lowercase SQL namespace of at most 63 bytes; reserved schemas and zero versions
are invalid. The migration is atomic and forward-only; occupied namespaces fail
instead of being silently adopted. Reuse installed history via the migration
runner, never by executing installation SQL again.

## Storage and security

Native private primary reads now lock the exact keyed scope from committed
issuance and reconstruct the original core profile, counters and full-width
version. Denial/check/expiry writes use optimistic CAS plus a final database-time
expiry fence. Correct consumption is rejected by that separate counter writer.
These helpers are not exposed as a raw store or online verification API. Current
flow/lockout authority, command replay/result/audit and consuming participant
composition remain mandatory before a public attempt workflow is enabled.

`NewAttemptCodec` copies trusted local wrapping, attempt-issuer and code-digest
keyrings. `Map(ctx, attempt, retainedDigestVersion, featureSpec)` returns the
owning feature command and exact coordinator OTP plan. It requires the original
core `AttemptIssuer.PrepareForCommand` submission and matching structural scope.
The `otp.*` field namespace is reserved. Mapping performs no SQL or challenge
comparison; native restoration is private, not an online verification oracle.

Map once and keep the returned command/plan for retries. Encryption is randomized;
remapping changes command intent and cannot replace an ambiguous original attempt.
Retain original wrapping, issuer and digest-key versions while dependent command
history remains. Changing bytes under an existing version is not key rotation.
All keys are copied and concurrent codec use is safe. Configuration formatting
is redacted and serialization is denied. No provider callback is injectable.

Private destination and explicit flow/remember policy are encrypted and bound to
the exact command structure and selected digest version. The raw submitted code
remains only in opaque command custody, never in the encrypted record. Decrypted
byte buffers are cleared; Go cannot guarantee erasure of immutable reconstructed
strings. Cancellation/deadlines are checked before and after local cryptography;
OS entropy and crypto calls cannot be interrupted mid-call. No late success is
returned. Mapping is not proof of current session, challenge or account authority.

- Only versioned keyed code/scope digests are stored, never codes, destinations,
  key bytes or flow/session bearers. Key metadata has no secret material.
- Scoped identity, original expiry, issued policy and issuance linkage cannot
  be reset. Counters and row versions are monotone. Full `uint64` generations
  and versions are preserved without fractional rounding.
- Pre-account challenges preserve an explicitly empty, non-null subject; no
  invented account identifier substitutes for the original continuation.
- Stored states are issued, reserved, finalized, released, expired, revoked and
  exhausted. Successful checks share the total counter, but cannot reserve.
  Reservation custody is complete or absent, never partially nullable.
  Terminal release stores unchanged rollback ownership or the exact recovery
  successor, with no code comparison or interim reservation needed.
- Primary journal FKs preserve issuance and consumer lineage. Unresolved
  reservations cannot expire into clean release. Terminal rows cannot resurrect.
  No deletion path exists yet; retention/key retirement cleanup is pending.
- Database constraints reject impossible storage transitions; they **do not**
  establish cryptographic verification, current authority, counted replay,
  correct reservation generation, or a proof of non-commit. Those belong to the
  forthcoming native participant APIs in the sole coordinator transaction.
- All original policy fields are frozen. Full alphabet/entropy validation still
  belongs to `otp.NewCodeProfile`; SQL bounds are storage defenses, not another
  policy engine. Only trusted native adapter projections will write this store.

## Adoption, tradeoffs and FAQ

`LockoutMigrationSource` installs a separately versioned forward-only extension
after challenge custody. Private shared lockout identities use a dedicated HMAC
key over tenant/subject and tenant/channel/canonical destination, never plaintext
PII. Purpose, challenge, flow and rotating code-key versions cannot reset them.
Pre-account flows retain destination exclusion without inventing a subject.
The dedicated lockout key is pinned by an immutable digest binding; absent or
changed key configuration fails closed. Its future explicit migration must
preserve live lockouts, not initialize another empty namespace.

Future issuance must precreate these unique scope rows before exposing a
challenge. Native verification locks destination then subject before challenge
comparison, samples primary time after lock waits and denies active lockouts.
Only newly counted wrong exhaustion may extend them in the same coordinator
denial transaction as counters, audit and stable result; correct checks cannot.
The private SQL primitives do not yet activate these public workflows or replace
current session/pre-auth authority. No caller-owned lockout store is supported.

Private consuming persistence now projects one provisional correct comparison
into the coordinator-owned transaction, preserving exact original command,
attempt and generation custody. Exact successor takeover does not compare again,
renew times or charge another attempt. Finalization can commit atomically with a
protected domain effect; rollback removes both. Finalization and takeover enforce
exclusive primary database expiry even if the sampled decision time was earlier.
Reservation/takeover preserve a row-version increment for eventual terminalization.

Release persistence accepts unchanged rollback ownership or one exact recovery
successor, including after original expiry, without decrypting submitted codes.
These private helpers are not admission or noncommit proof: public sealed native
participant callbacks compose current flow/lockout checks and command replay/audit
under the coordinator's authoritative recovery. No public raw
transaction or binding-to-release shortcut is exposed.

**Can I use this for login?** Not yet. Native issuance/send windows and bounded
cleanup remain in development. Native original pre-auth/authenticated-session
checks and consuming composition are not complete login. There
is intentionally no public raw SQL/pool/store workaround.

**Does a successful check authenticate?** No. Register the native contributor
and explicitly select `Coordinator.RecordOTPMeteredCheck` with its exact
record-free `identity.otp.check` declaration and original check-mode command.
The original separately submitted cookie/session bearer, frozen authority and
current primary admission are required before comparison. Each new admitted
check charges both the separate check allowance and shared total allowance,
including correct checks; disabled or exhausted allowances do not charge.
Wrong final exhaustion may extend shared lockouts; correct final exhaustion
cannot. Counters, required audit and the existing journal receipt commit
atomically, without reservations, session changes, domain application or
lifecycle delivery. An audit failure rolls back the charge.

Exact retries preserve the result without another comparison. A correct check's
`CommitOutcomeCommitted` means only that its metering receipt committed, never
proof or permission to perform a protected action. Wrong checks return retained
`CommitOutcomeNotCommitted`; the first submission reports denial, while ordinary
exact replay returns the retained receipt. `RecoverOTPMeteredCheck` requires
current query authorization and the original scalar attempt plan, not the code
or bearer; it recovers historical classification without renewing authority.
`ApplyFeature` always denies: generic domain execution cannot run this operation.


**Can I rotate a digest in place?** No. Existing rows keep their original retained
key version and digest. Future issuance selects the modern active profile;
retirement must preserve referenced replay tombstones.

**Does expiry release a reserved OTP?** No. Only the coordinator's authoritative
non-commit protocol can do that. A terminal release requires a newly issued OTP.

**Which checks exist?** Real isolated PostgreSQL tests exercise installed storage,
counter CAS races, expiry, immutable terminal states, full-width custody and
transaction rollback. These are not end-to-end code verification, delivery,
recovery, complete adapter coverage/mutation or release evidence.

## Release notes

`SendFamilyMigrationSource` installs rolling-hour send history after challenge
and lockout storage using a separately allocated migration version. It leaves
existing challenges untouched. Histories contain at most ten database-time
instants and a keyed family digest, never a destination, code or flow bearer.
The stable pinned abuse key has a separate send-family HMAC domain over tenant,
purpose, subject and channel/destination. A new challenge, target, flow, policy
version or rotating code key cannot refill the allowance.

Private issuance persistence requires original-flow admission, shared abuse
locks, then a family lock and a new primary-time sample. The rolling window is
`(now - one hour, now]`; resend equality is allowed. Schema guards reject
history erasure, deletion, identity changes, backward/future time and omitted
live sends. Counters must commit with challenge/replacement, required audit,
encrypted delivery and the existing command journal, or roll back together.
The extension does not yet expose public Send, perform generation/delivery,
resolve enumeration-safe account lookup or implement challenge replacement.
Existing consuming/check APIs are unchanged.

See [CHANGELOG.md](CHANGELOG.md). No stable release or production-readiness claim
is made for this development checkpoint.
