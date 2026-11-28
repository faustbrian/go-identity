package impersonationpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// RevocationMigrationSource appends terminal storage and legacy-writer fences
// to unchanged v1/v2 history. Apply all five versions before enabling revocation;
// constructors never apply DDL. Each fence takes only a bounded metadata lock
// on its existing writer table. No existing rows are rewritten or backfilled.
// Reverting code retains the terminal records and fences; there is no
// destructive down migration that could restore revoked authority.
type RevocationMigrationSource struct{}

var _ migrations.Source = RevocationMigrationSource{}

// Load returns fresh forward-only history without I/O. The caller must apply
// each version in its own migration transaction and resolve any lock timeout
// before enabling revocation. The readiness function appears only with the
// final fence; it indicates installation, not grant or audit authority.
func (RevocationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ActivationMigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	for _, next := range []struct {
		version migrations.Version
		name    string
		sql     string
	}{
		{3, "identity_impersonation_revocation", revocationSchemaSQL},
		{4, "identity_impersonation_revoked_approval_fence", revocationApprovalFenceSQL},
		{5, "identity_impersonation_revoked_activation_fence", revocationActivationFenceSQL},
	} {
		migration, err := migrations.NewMigration(next.version, next.name, migrations.TransactionModeDefault, next.sql, "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		history = append(history, migration)
	}
	return history, nil
}

// Terminal records belong to the revocation lifecycle, not to audit. The
// original grant remains immutable intent history for mixed-version readers.
const revocationSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE identity_impersonation.revocations (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND command_id<>grant_id),
 revoker_id identity_impersonation.directory_id NOT NULL,
 requester_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL CHECK(target_id<>requester_id AND target_id<>revoker_id),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 policy_id identity_impersonation.directory_id NOT NULL,
 policy_version numeric(20,0) NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615),
 before_version smallint NOT NULL CHECK(before_version BETWEEN 1 AND 3),
 after_version smallint NOT NULL CHECK(after_version=before_version+1),
 encrypted_payload bytea NOT NULL CHECK(octet_length(encrypted_payload) BETWEEN 1 AND 65536),
 revoked_at timestamptz NOT NULL CHECK(isfinite(revoked_at) AND revoked_at>='0001-01-01 00:00:00+00'::timestamptz AND revoked_at<'10000-01-01 00:00:00+00'::timestamptz),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,command_id)
);

CREATE FUNCTION identity_impersonation.preserve_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'impersonation revocation is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER preserve_revocation BEFORE UPDATE OR DELETE ON identity_impersonation.revocations
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_revocation();
`

// Original approval/start writers and revocation serialize on the original
// grant row. These point reads fence those old writers without changing their
// retained v1/v2 row contracts or inferring authority from an audit event.
const revocationApprovalFenceSQL = `SET LOCAL lock_timeout = '5s';
CREATE FUNCTION identity_impersonation.reject_revoked_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_impersonation.revocations WHERE tenant_id=OLD.tenant_id AND grant_id=OLD.grant_id) THEN
  RAISE EXCEPTION 'impersonation grant is revoked' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER reject_revoked_approval BEFORE UPDATE ON identity_impersonation.grants
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.reject_revoked_approval();
`

const revocationActivationFenceSQL = `SET LOCAL lock_timeout = '5s';
CREATE FUNCTION identity_impersonation.reject_revoked_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity_impersonation.revocations WHERE tenant_id=NEW.tenant_id AND grant_id=NEW.grant_id) THEN
  RAISE EXCEPTION 'impersonation grant is revoked' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER reject_revoked_activation BEFORE INSERT ON identity_impersonation.active_grants
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.reject_revoked_activation();
CREATE FUNCTION identity_impersonation.revocation_ready() RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT true;
$$;
`
