package impersonationpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// DenialMigrationSource appends terminal denial custody to the unchanged
// SelfStop history. Apply through v9 before selecting denial. Earlier
// binaries can keep operating: their approval and revocation writes remain
// fenced. Roll back code without dropping the retained denial history.
type DenialMigrationSource struct{}

var _ migrations.Source = DenialMigrationSource{}

// Load builds forward-only history without database I/O. The empty table
// and approval function upgrade precede the bounded existing-table DDL.
func (DenialMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	for _, next := range []struct {
		version migrations.Version
		name    string
		sql     string
	}{
		{7, "identity_impersonation_denial", denialSchemaSQL},
		{8, "identity_impersonation_denied_approval_fence", denialApprovalFenceSQL},
		{9, "identity_impersonation_denied_revocation_fence", denialRevocationFenceSQL},
	} {
		migration, err := migrations.NewMigration(next.version, next.name, migrations.TransactionModeDefault, next.sql, "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		history = append(history, migration)
	}
	return history, nil
}

const denialSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE identity_impersonation.denials (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND command_id<>grant_id),
 requester_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL CHECK(target_id<>requester_id),
 denier_id identity_impersonation.directory_id NOT NULL CHECK(denier_id<>requester_id AND denier_id<>target_id),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 policy_id identity_impersonation.directory_id NOT NULL,
 policy_version numeric(20,0) NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615),
 before_version smallint NOT NULL CHECK(before_version=1),
 after_version smallint NOT NULL CHECK(after_version=2),
 encrypted_payload bytea NOT NULL CHECK(octet_length(encrypted_payload) BETWEEN 1 AND 65536),
 denied_at timestamptz NOT NULL CHECK(isfinite(denied_at) AND denied_at>='0001-01-01 00:00:00+00'::timestamptz AND denied_at<'10000-01-01 00:00:00+00'::timestamptz),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,command_id)
);
CREATE FUNCTION identity_impersonation.preserve_denial() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'impersonation denial is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER preserve_denial BEFORE UPDATE OR DELETE ON identity_impersonation.denials
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_denial();
`

// Replace the existing function without a metadata lock on the hot grants
// table. Approval and denial serialize on the existing grant row; no v1/v2
// schema or status convention changes for legacy readers and writers.
const denialApprovalFenceSQL = `SET LOCAL lock_timeout = '5s';
CREATE OR REPLACE FUNCTION identity_impersonation.reject_revoked_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_impersonation.revocations WHERE tenant_id=OLD.tenant_id AND grant_id=OLD.grant_id) THEN
  RAISE EXCEPTION 'impersonation grant is revoked' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM identity_impersonation.denials WHERE tenant_id=OLD.tenant_id AND grant_id=OLD.grant_id) THEN
  RAISE EXCEPTION 'impersonation grant is denied' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
`

// Native revoke already locks the original grant, including in older
// binaries. Fence its terminal insert after that lock without rewriting rows.
const denialRevocationFenceSQL = `SET LOCAL lock_timeout = '5s';
CREATE FUNCTION identity_impersonation.reject_denied_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_impersonation.denials WHERE tenant_id=NEW.tenant_id AND grant_id=NEW.grant_id) THEN
  RAISE EXCEPTION 'impersonation grant is denied' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER reject_denied_revocation BEFORE INSERT ON identity_impersonation.revocations
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.reject_denied_revocation();
CREATE FUNCTION identity_impersonation.denial_ready() RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT true;
$$;
`
