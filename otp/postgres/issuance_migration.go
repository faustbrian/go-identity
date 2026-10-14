package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// IssuanceMigrationSource adds immutable challenge-to-send-family binding after
// SendFamilyMigrationSource. Schema is the existing dedicated OTP namespace;
// Version is a separately allocated permanent migration version. Load is pure,
// concurrent-safe and forward-only. It neither issues codes nor enables Send.
// Existing challenges retain their NULL family and exact original custody.
// New writers must supply a family; older unbound issuance writes fail closed.
// Consumption/recovery of existing challenges is unchanged. A live legacy
// challenge with unknown family blocks new issuance for that subject/purpose
// until its existing owner terminalizes it; migration cannot infer destinations.
type IssuanceMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = IssuanceMigrationSource{}

// Load returns owned atomic installation SQL with no down migration, runner or
// service access. Nil/invalid input is redacted; cancellation is preserved.
func (s IssuanceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "otp_issuance_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(issuanceSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_otp_issuance_family", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const issuanceSchemaSQL = `LOCK TABLE @schema@.send_families IN SHARE MODE;
ALTER TABLE @schema@.challenges ADD COLUMN send_family_digest bytea
 CHECK(send_family_digest IS NULL OR (octet_length(send_family_digest)=32 AND send_family_digest<>decode(repeat('00',32),'hex')));
ALTER TABLE @schema@.challenges ADD CONSTRAINT otp_challenge_send_family
 FOREIGN KEY(tenant_id,send_family_digest) REFERENCES @schema@.send_families(tenant_id,scope_digest);
CREATE INDEX otp_issuance_family_live ON @schema@.challenges(tenant_id,send_family_digest,expires_at,challenge_id)
 WHERE state='issued';
CREATE INDEX otp_issuance_family_reserved ON @schema@.challenges(tenant_id,send_family_digest,challenge_id)
 WHERE state='reserved';
CREATE INDEX otp_legacy_issuance_live ON @schema@.challenges(tenant_id,purpose,subject_id,expires_at)
 WHERE send_family_digest IS NULL AND state='issued';
CREATE INDEX otp_legacy_issuance_reserved ON @schema@.challenges(tenant_id,purpose,subject_id)
 WHERE send_family_digest IS NULL AND state='reserved';
CREATE FUNCTION @schema@.guard_issuance_family() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.send_family_digest IS NULL THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP issuance family required';
  END IF;
 ELSIF NEW.send_family_digest IS DISTINCT FROM OLD.send_family_digest THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP issuance family is immutable';
 END IF;
 RETURN NEW;
END
$guard$;
CREATE TRIGGER otp_issuance_family_guard BEFORE INSERT OR UPDATE ON @schema@.challenges
 FOR EACH ROW EXECUTE FUNCTION @schema@.guard_issuance_family();
`
