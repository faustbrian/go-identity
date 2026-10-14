# Runnable password authentication baseline (B1)

This is a **local, loopback-only backend**, not a UI or a production deployment.
It composes public owners and real PostgreSQL for registration, verification,
password signin, authenticated session reads and logout. Nothing seeds a user or
substitutes a domain store. HTTP features are explicitly selected; reset/change,
OTP signin, MFA and other login methods are not enabled here.

## Prerequisites and source boundary

- Go 1.27.2, Ruby, Git and tar; PostgreSQL binaries on PATH.
- This identity checkout and the local Golib repositories named in
  [LOCAL_SOURCES.json](LOCAL_SOURCES.json), containing those committed objects.
- HTTPS access to HIBP's public range API. The command uses the real owned client,
  padded k-anonymity requests and fail-closed screening; it has no "pretend clean"
  option. Integration tests replace only external provider IO.

The runner archives immutable supplier commits into its own temporary workspace,
builds the command and cleans its source archives and Go caches when it exits.
It does not change supplier checkouts or add permanent module replacements.
Historical dependency revisions are not all publicly downloadable, so this is
**development-source compatibility, not public-install/release qualification**.
Consumers need not implement missing stores, migrations or handlers.

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

These proofs do not close the platform: reset is B2, password change is B3, and
full unit/release qualification and the other retained milestones remain.
