package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SendFamilyMigrationSource adds digest-only send-family rolling-hour history
// after MigrationSource and LockoutMigrationSource. Schema is the same dedicated
// OTP namespace; Version is a separately allocated permanent migration version.
// It neither issues challenges nor enables public Send. Load is pure,
// concurrent-safe and forward-only; populated challenge state is untouched.
type SendFamilyMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = SendFamilyMigrationSource{}

// Load validates configuration and returns independently owned atomic SQL.
// Nil/invalid input returns redacted InvalidInputError; cancellation is retained.
// No connection, runner, key, destination or subject is embedded or acquired.
func (s SendFamilyMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "otp_send_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(sendFamilySchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_otp_send_families", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Keep only the last hour's at-most-ten instants, not recipient identities or
// code custody. Writers cannot drop live sends, reset a family by replacing it,
// or move time backwards. Retention/abuse-key migration is a separate operation;
// ordinary expiry and challenge/code-key replacement do not delete this state.
const sendFamilySchemaSQL = `LOCK TABLE @schema@.lockout_key_binding IN SHARE MODE;
CREATE TABLE @schema@.send_families(
 tenant_id identity.directory_id NOT NULL,
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32 AND scope_digest<>decode(repeat('00',32),'hex')),
 version identity.version NOT NULL DEFAULT 1,
 sent_at timestamptz[] NOT NULL DEFAULT ARRAY[]::timestamptz[],
 PRIMARY KEY(tenant_id,scope_digest),
 CHECK(cardinality(sent_at)<=10 AND (array_ndims(sent_at) IS NULL OR (array_ndims(sent_at)=1 AND array_lower(sent_at,1)=1)))
);
CREATE FUNCTION @schema@.guard_send_family() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
DECLARE
 at timestamptz;
 previous timestamptz;
 latest timestamptz;
 expected timestamptz[];
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send family retention required'; END IF;
 IF NEW.sent_at IS NULL OR cardinality(NEW.sent_at)>10
  OR (array_ndims(NEW.sent_at) IS NOT NULL AND (array_ndims(NEW.sent_at)<>1 OR array_lower(NEW.sent_at,1)<>1)) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send history bounds conflict';
 END IF;
 FOREACH at IN ARRAY NEW.sent_at LOOP
  IF at IS NULL OR at<timestamptz '0001-01-01 AD' OR at>=timestamptz '10000-01-01 AD'
   OR at<>date_trunc('microseconds',at) OR (previous IS NOT NULL AND at-previous<interval '30 seconds') THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send history time conflict';
  END IF;
  previous:=at;
 END LOOP;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR cardinality(NEW.sent_at)<>0 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send family initial conflict'; END IF;
  RETURN NEW;
 END IF;
 latest:=NEW.sent_at[cardinality(NEW.sent_at)];
 IF ROW(NEW.tenant_id,NEW.scope_digest) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.scope_digest)
  OR NEW.version<>OLD.version+1 OR latest IS NULL OR latest>clock_timestamp()
  OR (cardinality(OLD.sent_at)>0 AND latest-OLD.sent_at[cardinality(OLD.sent_at)]<interval '30 seconds') THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send family monotonicity conflict';
 END IF;
 expected:=ARRAY(SELECT v FROM unnest(OLD.sent_at) WITH ORDINALITY AS x(v,n) WHERE v>latest-interval '1 hour' ORDER BY n)||ARRAY[latest];
 IF NEW.sent_at IS DISTINCT FROM expected THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP send family allowance reset'; END IF;
 RETURN NEW;
END
$guard$;
CREATE TRIGGER otp_send_family_guard BEFORE INSERT OR UPDATE OR DELETE ON @schema@.send_families FOR EACH ROW EXECUTE FUNCTION @schema@.guard_send_family();
`
