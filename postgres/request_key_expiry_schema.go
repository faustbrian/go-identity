package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// RequestKeyExpiryMigrationSource appends optional irreversible mapped-origin
// refusal to the existing global command-ID claim, not another journal. Base
// must include request-key preparation; Version follows every installed step.
// Existing history/rows and ordinary retirement semantics remain unchanged.
// The keyed origin commitment contains no plaintext subject or credential.
// Typed fences cannot be updated/deleted/truncated; no downgrade is supported.
type RequestKeyExpiryMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward history without I/O. Cancellation and source errors
// are preserved; absent preparation history or non-successor versions fail closed.
func (s RequestKeyExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidRequestKey()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	preparation := false
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidRequestKey()
		}
		preparation = preparation || m.Name() == "identity_request_key_preparation"
	}
	if !preparation {
		return nil, invalidRequestKey()
	}
	next, err := migrations.NewMigration(s.Version, "identity_request_key_expiry", migrations.TransactionModeDefault, requestKeyExpirySQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const requestKeyExpirySQL = `ALTER TABLE identity.identity_command_id_claims
 ADD COLUMN request_key_expiry_fingerprint bytea,
 ADD CONSTRAINT identity_request_key_expiry_shape CHECK (
  request_key_expiry_fingerprint IS NULL
  OR (retired AND octet_length(request_key_expiry_fingerprint)=32));

CREATE FUNCTION identity.request_key_expiry_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
 IF TG_OP='TRUNCATE' THEN
  RAISE EXCEPTION 'permanent command identity' USING ERRCODE='23514';
 END IF;
 IF OLD.request_key_expiry_fingerprint IS NOT NULL THEN
  RAISE EXCEPTION 'irreversible request refusal' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END
$fn$;
CREATE TRIGGER identity_request_key_expiry_guard BEFORE UPDATE OR DELETE
 ON identity.identity_command_id_claims FOR EACH ROW EXECUTE FUNCTION identity.request_key_expiry_immutable();
CREATE TRIGGER identity_request_key_expiry_truncate BEFORE TRUNCATE
 ON identity.identity_command_id_claims FOR EACH STATEMENT EXECUTE FUNCTION identity.request_key_expiry_immutable();
`
