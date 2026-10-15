# Runnable password authentication, reset and change backend (B1/B2/B3)

This is a **local, loopback-only backend**, not a UI or a production deployment.
It composes public owners and real PostgreSQL for registration, verification,
password signin, authenticated session reads and logout. Nothing seeds a user or
substitutes a domain store. HTTP features are explicitly selected; reset is an
additional opt-in profile. Fresh verification/password change is independently
opt-in. OTP signin, MFA and other login methods are not enabled here.

## Prerequisites and source boundary

- Go 1.27.2, Ruby and PostgreSQL binaries on PATH.
- This identity checkout and normal access to its pinned public Go modules.
- HTTPS access to HIBP's public range API. The command uses the real owned client,
  padded k-anonymity requests and fail-closed screening; it has no "pretend clean"
  option. Integration tests replace only external provider IO.

The runner builds the reference module with `GOWORK=off` and its normal pinned
public dependency graph, then cleans its private Go caches when it exits. It
does not read sibling checkouts, replace modules or consume historical
`LOCAL_SOURCES.json` wiring. The first collection argument is retained only for
command compatibility and does not select dependencies. This is a runnable local
backend, not full-unit or platform release qualification. Consumers need not
implement missing stores, migrations or handlers.

## Run against a disposable local database

Run from this repository root. Set `collection` to the directory containing the
Golib repositories. The database below is newly created, loopback-only and owned
by this walkthrough. Trust authentication is appropriate only for this disposable
local cluster; never use these database instructions for production.

```sh
collection="$(dirname "$PWD")"
baseline_parent="$(mktemp -d /tmp/identity-baseline.XXXXXX)"
cleanup_baseline() {
  if [ -f "$baseline_parent/postgres/postmaster.pid" ]; then
    pg_ctl -D "$baseline_parent/postgres" -m fast -w stop
  fi
  case "$baseline_parent" in
    /tmp/identity-baseline.*)
      find "$baseline_parent" -type d -exec chmod u+w {} +
      find "$baseline_parent" -depth -delete
      ;;
    *) return 1 ;;
  esac
}
trap cleanup_baseline EXIT
initdb -D "$baseline_parent/postgres" --username=postgres --auth=trust --encoding=UTF8 --no-locale
pg_ctl -D "$baseline_parent/postgres" -l "$baseline_parent/postgres.log" \
  -o "-h 127.0.0.1 -p 55439 -k $baseline_parent" -w start
createdb -h 127.0.0.1 -p 55439 -U postgres identity_baseline
printf '%s' 'host=127.0.0.1 port=55439 user=postgres dbname=identity_baseline sslmode=disable search_path=public' \
  > "$baseline_parent/postgres.dsn"
chmod 600 "$baseline_parent/postgres.dsn"
ruby scripts/identity-baseline.rb "$collection" init \
  --local-capture --directory "$baseline_parent/app"
ruby scripts/identity-baseline.rb "$collection" migrate \
  --local-capture --directory "$baseline_parent/app" \
  --dsn-file "$baseline_parent/postgres.dsn"
printf 'Private walkthrough directory: %s\n' "$baseline_parent"
ruby scripts/identity-baseline.rb "$collection" serve \
  --local-capture --directory "$baseline_parent/app" \
  --dsn-file "$baseline_parent/postgres.dsn"
```

Wait for `local HTTPS baseline ready`. In a second terminal, from the same
repository, set `baseline_parent` to the printed directory and run:

```sh
baseline_parent="/tmp/identity-baseline.REPLACE_WITH_PRINTED_SUFFIX"
ruby scripts/identity-baseline.rb "$(dirname "$PWD")" exercise \
  --local-capture --directory "$baseline_parent/app"
```

The consumer uses a random account/password, trusts only the generated local
certificate, traverses public HTTPS endpoints and reads its verification email
from the selected private sender destination. It also proves unverified and
wrong-password denial, CSRF rejection, and rejection of the original saved session
cookie after logout. It prints outcomes, never passwords, tokens or mail.
Success ends with:

```text
baseline passed: registration -> captured verification -> verification -> password signin -> authenticated session -> logout -> original session denied
```

Stop serving with Ctrl-C; the command cancels and drains its listener and worker.
Exit the first shell to remove this walkthrough's database and private files.
Choose different PostgreSQL/HTTPS ports when these ports are already occupied;
pass the same exact `--origin https://127.0.0.1:PORT` to every command.

## Supported composition and security choices

- `ComposeStores` → `ComposeProviders` → `ComposeWorkers` → `ComposeFeatures`
  → `NewServer`; no private replacement engine or hidden feature registration.
- `PostgresOnly` with explicit `DurableAdmission`, not forged Valkey history.
  Protected one-time consumption/effects remain in the existing native transaction.
- `init` creates private restart-stable independent owner keys and loopback TLS.
  It refuses existing directories. Credential/DSN files must be regular private
  files; links, expired certificates and public-readable keys deny.
- `migrate` explicitly calls native Check/Plan/Apply. The private original operator
  request is saved before Apply for exact interrupted-run recovery. Serving never
  applies migrations. Drift/unmanaged objects deny adoption.
- Default Argon2id, required verified email before login, original browser/device
  custody, strong HTTP admission, current primary account/session authority,
  audit/outbox effects, secure host-only cookies and synchronizer CSRF.
- The finite application policy uses the existing authorization engine at a fixed
  revision/tenant. It grants selected service actions and self-session revocation;
  unselected claims/privacy/risk callback families fail closed.
- Mail goes to private `app/mail/*.json` files only under explicit `--local-capture`.
  This is accepted local capture, **not real provider delivery** or a production
  sender. Files may contain verification secrets; do not commit, export or log
  them. The bounded mailbox permits 1,024 messages.
- Durable admission retains at most 100,000 attempts per selected tenant. Full
  capacity denies rather than evicting replay/key history or resetting allowance.
  Automatic retirement/operator cleanup is not implemented in this B1 profile;
  this is not complete risk-adapter qualification.

## Reproduce the selected integration proof

Use a newly created disposable cluster with an `identity_test` database and the
same explicit loopback port. This invokes native frozen tests serially, not an
aggregate release gate. Fixtures create/remove databases and native cluster-scoped
audit roles, so do not point them at a shared cluster.

```sh
IDENTITY_REFERENCE_POSTGRES_PORT=55439 \
IDENTITY_RISK_POSTGRES_TEST_DSN='host=127.0.0.1 port=55439 user=postgres dbname=identity_test sslmode=disable' \
  ruby scripts/identity-baseline.rb "$(dirname "$PWD")" integration
```

## Opt into emailed password reset (B2)

Keep the same private directory, database and exact HTTPS origin. Stop the B1
server without removing the disposable database, then migrate and restart with
the explicit selection. Do not initialize or replace the stable private keys.
The operator completes or resumes the baseline's original migration request
before preparing reset. It retains a separate migration-request-reset.json;
partial reset retries reuse that original input, not a newly planned command.

```sh
ruby scripts/identity-baseline.rb "$collection" migrate --password-reset \
  --local-capture --directory "$baseline_parent/app" \
  --dsn-file "$baseline_parent/postgres.dsn"
ruby scripts/identity-baseline.rb "$collection" serve --password-reset \
  --local-capture --directory "$baseline_parent/app" \
  --dsn-file "$baseline_parent/postgres.dsn"
```

In the second terminal, with the same private directory selected:

```sh
ruby scripts/identity-baseline.rb "$(dirname "$PWD")" exercise-reset --password-reset \
  --local-capture --directory "$baseline_parent/app"
```

The consumer registers/verifies a fresh account and signs in twice. It then
requests reset and reads the actual captured link, inspects twice without
consumption, explicitly completes and replays the same command, rejects changed
replay and a new command using the consumed proof, and proves both saved original
session cookies are denied. The old password cannot sign in; the new password
can. Reset itself issues no session or cookie; signin remains a separate action.
The final new session is logged out and its saved cookie is also denied.

Selected routes are POST /v1/password/reset-request,
POST /v1/password/reset/inspect and POST /v1/password/reset-complete. Tokens
belong only in bounded POST bodies, never inspection URLs or query parameters.
Inspection returns only advisory valid/invalid state and cannot authorize later
completion. Required HIBP screening, current account/recipient/factor checks,
atomic one-use, credential replacement and all-session revocation remain native
owner responsibilities. This profile supports only current known-empty MFA
authority at the original signed generation; it is not MFA bypass or administrative
recovery. Default serving without --password-reset advertises none of these routes.

### Recover uncertain required audit delivery

The selected local host durably retains the exact redacted native HIBP audit
records in private `app/audit-custody/` before PostgreSQL append. An uncertain
primary acknowledgement still denies password screening; local custody is not
permission to complete reset. It survives process restart and cannot recreate
record IDs, repeat HIBP screening or perform credential/session effects.

Stop the local server, retain its existing private directory/database, and run:

```sh
ruby scripts/identity-baseline.rb "$collection" reconcile-audits --password-reset \
  --local-capture --directory "$baseline_parent/app" \
  --dsn-file "$baseline_parent/postgres.dsn"
```

This bounded operation submits unchanged original records through the native
idempotent audit append protocol. It reapplies the native privacy policy without
changing canonical bytes, and removes custody only after confirmed primary
acceptance or duplicate acknowledgement. Then restart the selected server.
There is no background recovery loop or production audit-delivery service here.
At most 256 batches of one or two records are retained; full capacity or an
unavailable filesystem denies new required audit delivery rather than evicting
unconfirmed records. Do not edit or delete pending files to manufacture success.

## Opt into fresh verification and password change (B3)

Keep the existing private directory, database and exact HTTPS origin. Stop
serving, then explicitly select the new profile:

    ruby scripts/identity-baseline.rb "$collection" migrate --password-change \
      --local-capture --directory "$baseline_parent/app" \
      --dsn-file "$baseline_parent/postgres.dsn"
    ruby scripts/identity-baseline.rb "$collection" serve --password-change \
      --local-capture --directory "$baseline_parent/app" \
      --dsn-file "$baseline_parent/postgres.dsn"

If the database already has reset selected, retain **--password-reset** on both
commands. The combined upgrade resumes the original reset request before adding
change. A new migration-request-change.json (or migration-request-reset-change.json
for the combination) preserves its own original operator input; it never
overwrites the original baseline/reset request or installed history.

Explicit migration adds private password-change-credentials.json for independent
reauthentication signing, identifier and change-intent keys. Serving cannot
generate missing keys. Original credentials.json is unchanged; keep both files
stable across restarts. Unsafe, ambiguous or unavailable custody denies.

In the second terminal:

    ruby scripts/identity-baseline.rb "$(dirname "$PWD")" exercise-change --password-change \
      --local-capture --directory "$baseline_parent/app"

The consumer traverses registration/verification/signin, creates two sessions,
denies missing-CSRF/wrong-password/unselected-purpose verification, obtains a
fresh original proof without extending its session, denies current-password
reuse, then explicitly changes with native required HIBP/audit delivery. It
proves both saved original sessions are denied, old-password signin fails,
new-password signin succeeds and the old proof cannot change that new session.
It ends with logout and rejection of the saved replacement-session cookie.

With both profiles installed, `exercise --password-reset --password-change`
runs reset and then change against the reset's replacement credential.
`exercise-reset` and `exercise-change` keep their respective journeys separate,
even when both feature flags are present.

POST /v1/password/verify accepts current password plus the exact selected
purpose/action/audience; POST /v1/password/change accepts proofID/newPassword and
one Idempotency-Key header. Both require the original browser/session custody,
exact HTTPS Origin and CSRF. Subject identity comes from current native
authentication, not a caller-selected subject. Change consumes the original
issued proof in the protected transaction; revoke-all policy is trusted startup
configuration, not a request override. This adopts the supported public change
contract rather than the historical catalog's subject/current-password/
revocation fields in the change body.

A same-key HTTP retry after successful revoke-all change denies because its
cookie is revoked; idempotency does not restore authentication. Original keyed
replay and code-free scoped recovery remain available through the separate
native ports under independent trusted authorization, without another hash,
screening or mutation. The local command does not expose a recovery bypass.

Audit reconciliation above also accepts --password-change; retain both flags
when both profiles are installed. Full unit/release qualification and the other
retained milestones remain; these selected journeys do not close the platform.
