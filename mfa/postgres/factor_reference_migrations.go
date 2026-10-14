package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// FactorReferenceMigrationSource appends a shared immutable factor-identity
// namespace after existing TOTP/recovery history. This is reference integrity,
// not enrolled-factor state, policy or authentication. It preserves historical
// TOTP identities and recovery rows; future methods use the same recovery owner.
// Allocate Version after every installed MFA migration. The atomic migration
// locks/scans the factor and recovery tables: operators must bound lock/statement
// waits and provision backfill headroom. No production latency budget is implied.
type FactorReferenceMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward-only SQL without IO. The existing source contract
// rejects missing, typed-nil, cancelled, empty or conflicting history. The old
// schema must contain TOTP factors and recovery sets; unexpected schema drift
// fails during application rather than silently relaxing integrity.
func (s FactorReferenceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_factor_references",
		migrations.TransactionModeDefault, factorReferenceSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

// References contain immutable identity/method only. Per-method stores retain
// enrollment, verification and replay ownership. Legacy TOTP inserts register
// their identity in this same transaction, without secrets or lifecycle effects.
// The primary authority lock precedes these writes in native workflows. Locks
// below prevent an old writer entering between backfill and trigger installation.
const factorReferenceSQL = `LOCK TABLE identity_mfa.totp_factors,identity_mfa.recovery_sets IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE identity_mfa.factor_references (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 factor_id text COLLATE "C" NOT NULL CHECK(factor_id ~ '^[A-Za-z0-9_-]{22}$'),
 method text COLLATE "C" NOT NULL CHECK(method IN('totp','otp','security-key')),
 PRIMARY KEY(tenant_id,factor_id),
 UNIQUE(tenant_id,user_id,factor_id),
 UNIQUE(tenant_id,user_id,factor_id,method),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity_mfa.factor_authorities(tenant_id,user_id)
);
INSERT INTO identity_mfa.factor_references(tenant_id,user_id,factor_id,method)
 SELECT tenant_id,user_id,factor_id,'totp' FROM identity_mfa.totp_factors;

CREATE FUNCTION identity_mfa.factor_reference_immutable_v1() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
 IF ROW(NEW.tenant_id,NEW.user_id,NEW.factor_id,NEW.method) IS DISTINCT FROM
    ROW(OLD.tenant_id,OLD.user_id,OLD.factor_id,OLD.method) THEN
  RAISE EXCEPTION USING ERRCODE='23514',CONSTRAINT='mfa_factor_reference_identity',MESSAGE='factor reference identity is immutable';
 END IF;
 RETURN NEW;
END
$body$;
REVOKE ALL ON FUNCTION identity_mfa.factor_reference_immutable_v1() FROM PUBLIC;
CREATE TRIGGER mfa_factor_reference_immutable BEFORE UPDATE ON identity_mfa.factor_references
 FOR EACH ROW EXECUTE FUNCTION identity_mfa.factor_reference_immutable_v1();

CREATE FUNCTION identity_mfa.register_factor_reference_v1() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE
 existing_user identity.directory_id;
 existing_method text;
BEGIN
 IF TG_NARGS<>1 OR TG_ARGV[0] IS NULL OR TG_ARGV[0] NOT IN('totp','otp','security-key') THEN
  RAISE EXCEPTION USING ERRCODE='23514',CONSTRAINT='mfa_factor_reference_method',MESSAGE='unsupported factor reference method';
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.tenant_id,NEW.user_id,NEW.factor_id) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.user_id,OLD.factor_id) THEN
   RAISE EXCEPTION USING ERRCODE='23514',CONSTRAINT='mfa_factor_reference_identity',MESSAGE='factor reference identity is immutable';
  END IF;
 END IF;
 INSERT INTO identity_mfa.factor_references(tenant_id,user_id,factor_id,method)
  VALUES(NEW.tenant_id,NEW.user_id,NEW.factor_id,TG_ARGV[0])
  ON CONFLICT(tenant_id,factor_id) DO NOTHING;
 SELECT user_id,method INTO existing_user,existing_method FROM identity_mfa.factor_references
  WHERE tenant_id=NEW.tenant_id AND factor_id=NEW.factor_id FOR KEY SHARE;
 IF existing_user IS DISTINCT FROM NEW.user_id OR existing_method IS DISTINCT FROM TG_ARGV[0] THEN
  RAISE EXCEPTION USING ERRCODE='23514',CONSTRAINT='mfa_factor_reference_owner',MESSAGE='factor reference owner or method mismatch';
 END IF;
 RETURN NEW;
END
$body$;
REVOKE ALL ON FUNCTION identity_mfa.register_factor_reference_v1() FROM PUBLIC;
CREATE TRIGGER mfa_totp_factor_reference BEFORE INSERT OR UPDATE OF tenant_id,user_id,factor_id ON identity_mfa.totp_factors
 FOR EACH ROW EXECUTE FUNCTION identity_mfa.register_factor_reference_v1('totp');
ALTER TABLE identity_mfa.totp_factors ADD CONSTRAINT mfa_totp_factor_reference_fk
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.factor_references(tenant_id,user_id,factor_id);
ALTER TABLE identity_mfa.recovery_sets DROP CONSTRAINT recovery_sets_tenant_id_user_id_factor_id_fkey;
ALTER TABLE identity_mfa.recovery_sets
 ADD COLUMN factor_method text COLLATE "C" NOT NULL DEFAULT 'totp' CHECK(factor_method IN('totp','otp','security-key')),
 ADD COLUMN totp_factor_id text COLLATE "C" GENERATED ALWAYS AS(CASE WHEN factor_method='totp' THEN factor_id END) STORED;
ALTER TABLE identity_mfa.recovery_sets ADD CONSTRAINT mfa_recovery_factor_reference_fk
 FOREIGN KEY(tenant_id,user_id,factor_id,factor_method) REFERENCES identity_mfa.factor_references(tenant_id,user_id,factor_id,method);
ALTER TABLE identity_mfa.recovery_sets ADD CONSTRAINT mfa_recovery_totp_factor_fk
 FOREIGN KEY(tenant_id,user_id,totp_factor_id) REFERENCES identity_mfa.totp_factors(tenant_id,user_id,factor_id);
`
