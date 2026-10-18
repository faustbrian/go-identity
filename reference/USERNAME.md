# Optional username composition

The reference library composes the public username and native password owners;
applications supply configuration, current policy and the declared external
sender/provider seams, not a domain store or orchestration implementation.
The baseline CLI does not implicitly enable this optional profile.

## Select the owned services

Set `StoreConfiguration.Username` with a frozen `username.Policy` and the
independent native selections. Signup reuses `PasswordSignup` configuration with
the distinct username operation; it still requires email verification. Signin
reuses `PasswordSignin` configuration without replacing the email login owner.
Their original pre-authentication handles are `UsernameSignupPreAuth` and
`UsernameSigninPreAuth`. Availability and Rename require their explicit native
configurations; nil exposes no corresponding handle.

For native signup, use `UsernameRegistrationVerification` to confirm the
delivered original proof and recover its outcome. This is independent of HTTP
and never substitutes the email registration owner or automatically signs in.

Use the fixed versioned normalization profile. Rename's native domain selects
that same profile, retained identifier keys and the thirty-day reuse cooldown.
Its action-specific primary must select `identity.username.update`, its exact
signed audience, cookie transport and retained issued CSRF keys. Configure that
target in `PasswordVerification.Native.Targets` before composition. Protected
counters must enable lockouts and retain the **same policy value** used by the
graph's risk evaluator, not a separately constructed equivalent. Signup HIBP
screening must admit `identity.username.signup` and retain that risk revision.
Authorization and risk revisions are separate contracts.

Availability uses its actual durable PostgreSQL counters and canonical audit
owner. Every request is separately metered before occupancy is disclosed. A
positive result is advisory, never a reservation; unavailable authority cannot
be interpreted as an available name.
Its configured counter schema is installed independently of the graph's selected
counter lane. Availability and rename install the native identifier cooldown
history even when signup and managed email are unselected.

## Select transport independently

Set `StoreConfiguration.HTTPUsername` only for the desired routes:

| Selection | Route | Original flow method |
| --- | --- | --- |
| `Signup` | `POST /v1/username/signup` | `username-signup` |
| `Signin` | `POST /v1/username/signin` | `username` |
| `Availability` | `GET /v1/username/available?username=…` | none |
| `Rename` | `POST /v1/username/update` | fresh action-bound password proof |

Signup/signin require the original browser-device and HTTP rate owners. Their
trusted actor/revision come from deployment policy, not request input. Rename
requires explicit cookie-only protection, trusted HTTPS origins and a separate
keyed rate namespace/key. Disabled operations expose neither routes nor method
metadata. Selected operations with missing native dependencies fail composition.

When username signup and HTTP registration confirmation are selected, the
existing canonical email confirmation route authenticates signed issuance
provenance and chooses the persisted original email or username registration
owner. It never tries another owner after a failure. Managed-address confirmation
remains an independent selection. Automatic verification-signin cannot be
combined with this selected username-registration profile; composition rejects
that unsupported combination rather than substituting email custody.

## Consumer journey

1. Apply the graph's selected native migration plan, initialize features and
   confirm readiness. Original installed migration bytes remain unchanged.
   Registration's retained purpose predecessors install before username's
   supersets; session purpose extensions preserve the actually selected password,
   magic-link, MFA and verification lineage. Rename also installs the existing
   counted-preparation, lockout and action-proof consumption suffixes.
2. Initiate `username-signup` through `POST /v1/session/preauth-issue`. Retain
   its original flow and signed browser-device cookies. Submit username, email,
   password, original flow ID and its configured callback with one stable
   `Idempotency-Key`. Neutral collisions reveal no existing account or session.
3. Schedule `WorkerSet.ProcessDeliveryOne` through the existing worker owner.
   The external sender receives the real encrypted-queue verification delivery.
   Confirm its original token at `POST /v1/email/verification-confirm`. Signup
   and confirmation do not issue a session. Unverified username signin denies.
4. Initiate the separate `username` flow, retaining its cookies. Submit the
   original flow ID, username, password and the **signin** callback configured
   by `PasswordSignin.PreAuth` (which may differ from signup's callback).
   Retain the actual issued session cookie and `X-CSRF-Token`, plus the existing
   browser-device cookie required for password reauthentication.
5. Read the authenticated session. Trusted backend composition may use the
   existing public native `identity/postgres.Repository.GetIdentifierState` for
   that exact current self principal to obtain username ID and identifier/
   verification versions. This storage port is not browser authorization; never
   accept an arbitrary client-selected user/tenant for that read. No application
   SQL or replacement store is required. Generic directory HTTP composition is
   separate from the selected username transport.
6. Obtain fresh proof through `POST /v1/password/verify` for purpose
   `identity.password.verify`, action `identity.username.update` and the exact
   configured audience. Send original session/device cookies and issued CSRF.
   Submit the proof ID, username ID, both expected versions and replacement name
   to `/v1/username/update` with original CSRF and a stable idempotency key.
7. A canonical rename retires the old name and invalidates identifier-bound
   sessions. Its exact retry retains original cookie/proof/key/input and returns
   committed metadata after that session invalidation; it issues no credentials
   or renewed proof. Changed input under the same key conflicts. Sign in under
   the new canonical name, read that session and sign out with issued CSRF.

Enrolled or unknown MFA state denies the selected username signin/rename
profile. There is no password-only fallback. Username-only registration,
username MFA continuation and automatic confirmation-signin are not enabled by
this profile. Native contracts retain their broader ownership; this document
does not claim complete platform or release qualification.

`TestReferencePostgresUsernameHTTPS` runs this journey through the actual
reference HTTPS server and PostgreSQL/native owners, including coexisting email
confirmation, unverified signin denial, canonical occupancy, CSRF denial,
original rename recovery, old-session/old-name denial and logout. Only external
HIBP IO and the application's email sender are controlled. With the disposable
PostgreSQL fixture described in [the baseline guide](BASELINE.md), run from this
module with task-owned Go caches:

```sh
go test -race -tags=integration -run '^TestReferencePostgresUsernameHTTPS$' -count=1 .
```
