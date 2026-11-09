# OAuth PostgreSQL

Native RP transaction storage and recoverable PKCE custody, under development.
`NewLinkService` composes the explicit-self password-session OIDC linking
profile through real current authority and the existing kernel transaction.
The selected reference journey is exercised locally; publication and complete
OAuth qualification remain unfinished.

## Explicit account linking

`LinkStart` requires the original fresh password session and synchronizer,
keyed request custody, configured provider/scopes and exact application callback
allowlists. It checks primary directory, credential, policy and known-empty MFA
authority before issuing recoverable state/nonce/S256 custody. Unknown or
enrolled factor state denies rather than selecting a weaker profile.

`Callback` derives its actor from authenticated state and the original browser.
The root journal reserves one-use state before verifier release and exchange;
retained encrypted output resumes without repeating the exchange. Account and
credential changes, encrypted provider tokens and exchange-secret erasure share
the root transaction. Exact committed retry does not require a newly valid
session epoch and never creates a new session. `CallbackRateSource` supplies
only original rate attribution, not exchange or account authority.

Successful linking atomically records `identity.oauth.handle_callback`,
`identity.oauth.link_account` and `identity.account.link` with standard retention
and one correlated causation chain. Known terminal refusals record the same
applicable actions without claiming a mutation. Protected-counter denial erases
the original exchange secrets before exchange; proven rollback can erase them
after final proof expiry without making that proof usable again. Failed cleanup
rolls back terminalization rather than claiming a known refusal.

Backend maintenance can call `EraseExpiredUnused(ctx, maximum, cursor)` to erase
abandoned, expired explicit-link PKCE/state-proof ciphertext even when the browser
never returns. Start with an empty cursor, examine at most 1–100 rows per call,
and continue with its returned cursor until empty. Repeat the sweep later from
the beginning to revisit locked rows. The caller owns scheduling and a bounded
outer context; this service starts no background worker or HTTP route.

Each batch authenticates retained RP metadata and locks its rows before erasure.
Any existing callback command claim excludes that transaction, including pending
or uncertain exchanges; expiry is never evidence that a code was not exchanged.
Claimed rows advance pagination so they do not starve later abandoned rows.
The canonical journal/capability owners remain unchanged. A batch error returns
no count or next cursor; retry from the prior cursor after an unknown commit
acknowledgement. Keep the configured provider and retained keys available until
their custody is drained. This is a maintenance entry point for a trusted backend,
not an end-user operation or a substitute for external-effect reconciliation.

For a known attached callback abandoned beyond the original RP window, use
`RecoverExpiredAttached(ctx, tenant, maximum, cursor)`. It authenticates retained
metadata and enters the existing coordinator's unanimous-negative recovery. No
browser credential, current state proof, grant restoration or second exchange
is needed. Ordinary expired callbacks still deny. Unattached/uncertain exchanges
remain pending; expiry alone never proves noncommit.

This tenant-scoped sweep examines at most 1–100 rows and rejects a cursor from
another tenant. It closes each candidate through its own canonical transaction,
without holding an RP lock ahead of the coordinator's claim-first lock order.
Counts describe acknowledged noncommit observations, not exactly-once erasures;
concurrent sweepers can observe the same outcome. On error, prior counts and
the last completed cursor remain valid. Keep scheduling and pool lifetime with
the trusted backend caller; this operation exposes no HTTP route.

An issuer-bound provider-error response uses the original state and browser too.
It does not synthesize a code or decrypt PKCE. The existing coordinator consumes
the original grant, erases exchange ciphertext and records a denied outcome
with the RP lifecycle transition, then returns the original allowlisted error
callback. Exact retry returns that outcome; replacing the error with a code
cannot exchange or link. Provider text is never surfaced, and cancellation
does not create an identity/session or change the existing password access path.

If denial-secret erasure fails, the transaction retains its pending receipt and
reserved state rather than acknowledging cancellation with secrets left behind.
Retry can finish the original cancellation while its RP window remains valid.
After expiry, `RecoverExpiredAttached` can settle that original claim through
the registered native owner, atomically erasing custody, releasing state and
recording failure; it cannot produce a successful cancellation redirect.

A definitive token-endpoint refusal is authenticated and retained in the same
preparation journal. Retry and historical recovery settle it without another
exchange or a final link grant. A lost response or failure before durable
retention remains uncertain; expiry does not turn that uncertainty into refusal.

Final successful linking uses `PrepareLink` and the neutral `LinkUnitOfWork`:
the ready handoff carries immutable `LinkCommand`/`LinkParticipants`, not an open
transaction. `WithinLink` binds a private authoritative writer, applies the
identity transition and commits every required participant through the existing
coordinator. A provisional `LinkApplication` is not a durable receipt. Handoff
copies share one-use execution and preserve the original earlier deadline.

Install the native kernel account/preparation/erasure and RP/token-vault histories
before selecting the service. The reference backend owns that composition when
`SocialOAuth` is selected; `HTTPSocialOAuth` independently selects routes. Stable
intent custody is separate from retained state, PKCE and envelope rotation keys.
Do not expose this developing profile as social signin, refresh or unlinking.

This service also selects the risk owner's `RetainCounterKeyVersions` profile.
Install `risk/postgres.CounterKeyVersionMigrationSource` after protected-counter
history before enabling it. Original charge aliases are retained atomically and
read back through that owner before reconstructing a retry. Retained-key additions
do not replace the original redirect, command, protected network or expiry;
missing original keys or unknown historical metadata deny. New charges continue
to require the full current key set. Request admission time is not new logical
intent, but the original primary time still bounds every authorization and effect.

## Storage ownership

`MigrationSource{Schema: "identity_oauth", Version: allocatedVersion}` supplies
one forward migration for the existing migrations runner after the identity
kernel. It preserves populated identity rows and installs no endpoint. Use a
dedicated unoccupied schema and permanently allocate the version in the owning
composition's history. No destructive down migration is provided.

RP rows distinguish authenticated-user linking from actual anonymous pre-auth
flows. State lookup uses keyed digests. PKCE, canonical state proofs and private
bindings are encrypted; SQL constraints do not authenticate their contents.
The canonical capability participant and kernel journal retain all replay,
reservation, execution and recovery authority. This is not another journal.

Private PKCE custody uses the existing secret-envelope AEAD and core OAuth
verifier, exact RP AAD, separately keyed commitments and original deadlines.
The selected native AAD values are limited to 1024 bytes, matching the upstream
envelope context bound; longer values fail rather than being truncated.
Opening custody alone cannot authorize exchange. Actual callback orchestration
must reserve canonical state and admit the original browser/session first.

No flow, account, session, token-vault, HTTP or whole-unit qualification claim
follows from these storage and cryptographic checks.

## Tests

Run `go test ./...` for custody behavior. The integration-tagged storage tests
require an explicitly provisioned disposable loopback PostgreSQL database named
`identity_test` through `IDENTITY_POSTGRES_TEST_DSN`. They create and remove a
unique child database; never point them at an existing application database.
