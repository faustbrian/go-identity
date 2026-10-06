package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// LockoutMigrationSource adds shared OTP subject/destination lockouts after
// MigrationSource, without changing an applied migration. Schema must be the
// same OTP namespace; Version is a separately allocated permanent history
// version. No key, destination or subject is embedded in migration SQL. The
// explicit deployment key binding and native issuance remain in development;
// an absent binding fails closed. Load is pure, concurrent-safe and forward-only.
type LockoutMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = LockoutMigrationSource{}

// Load returns independently owned atomic extension SQL. Cancellation is
// preserved and invalid trusted configuration is redacted. It opens no database.
func (s LockoutMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "otp_lockout_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(lockoutSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_otp_shared_lockouts", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// A dedicated stable key is independent of rotating code keys. Its binding
// prevents changed deployment key bytes from addressing fresh abuse identities.
// In-place key changes/deletion are forbidden; a future explicit migration must
// preserve every live lockout before changing this namespace, never fall back.
const lockoutSchemaSQL = `LOCK TABLE @schema@.challenges IN SHARE MODE;
CREATE TABLE @schema@.lockout_key_binding(
 singleton boolean PRIMARY KEY CHECK(singleton),
 key_binding bytea NOT NULL CHECK(octet_length(key_binding)=32 AND key_binding<>decode(repeat('00',32),'hex'))
);
CREATE TABLE @schema@.lockouts(
 tenant_id identity.directory_id NOT NULL,
 kind text COLLATE "C" NOT NULL CHECK(kind IN('destination','subject')),
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32 AND scope_digest<>decode(repeat('00',32),'hex')),
 version identity.version NOT NULL DEFAULT 1,
 blocked_until timestamptz CHECK(blocked_until>=timestamptz '0001-01-01 AD' AND blocked_until<timestamptz '10000-01-01 AD'),
 PRIMARY KEY(tenant_id,kind,scope_digest)
);
CREATE INDEX otp_lockout_expiry ON @schema@.lockouts(blocked_until,tenant_id,kind,scope_digest) WHERE blocked_until IS NOT NULL;
CREATE FUNCTION @schema@.guard_lockout() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP lockout retention required'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.blocked_until IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP lockout initial state conflict'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.tenant_id,NEW.kind,NEW.scope_digest) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.kind,OLD.scope_digest)
  OR NEW.version<>OLD.version+1 OR NEW.blocked_until IS NULL
  OR (OLD.blocked_until IS NOT NULL AND NEW.blocked_until<OLD.blocked_until) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP lockout monotonicity conflict';
 END IF;
 RETURN NEW;
END
$guard$;
CREATE TRIGGER otp_lockout_guard BEFORE INSERT OR UPDATE OR DELETE ON @schema@.lockouts FOR EACH ROW EXECUTE FUNCTION @schema@.guard_lockout();
CREATE FUNCTION @schema@.guard_lockout_key() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
 RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP lockout key migration required';
END
$guard$;
CREATE TRIGGER otp_lockout_key_guard BEFORE UPDATE OR DELETE ON @schema@.lockout_key_binding FOR EACH ROW EXECUTE FUNCTION @schema@.guard_lockout_key();
`
