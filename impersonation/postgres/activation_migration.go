package impersonationpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ActivationMigrationSource explicitly selects activation storage. It appends
// version two to the unchanged pending/approval history. Apply it before
// enabling activation; constructors never apply DDL. No installed table is
// altered, locked for DDL, backfilled or given a new foreign key. Reverting code
// retains historical rows; the migration deliberately has no destructive down.
type ActivationMigrationSource struct{}

var _ migrations.Source = ActivationMigrationSource{}

// Load returns fresh forward-only history without I/O. The caller owns the
// bounded migration transaction and must resolve failures before activation.
func (ActivationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	activation, err := migrations.NewMigration(2, "identity_impersonation_activation", migrations.TransactionModeDefault, activationSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, activation), nil
}

const activationSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE identity_impersonation.active_grants (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 activation_command_id text COLLATE "C" NOT NULL CHECK(activation_command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND activation_command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND activation_command_id<>grant_id),
 approval_command_id text COLLATE "C" NOT NULL CHECK(approval_command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND approval_command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND approval_command_id<>grant_id AND approval_command_id<>activation_command_id),
 actor_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL CHECK(target_id<>actor_id),
 approver_id identity_impersonation.directory_id NOT NULL CHECK(approver_id<>actor_id AND approver_id<>target_id),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 scope jsonb NOT NULL CHECK(jsonb_typeof(scope)='array' AND jsonb_array_length(scope) BETWEEN 1 AND 64),
 policy_id identity_impersonation.directory_id NOT NULL,
 policy_version numeric(20,0) NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615),
 actor_version numeric(20,0) NOT NULL CHECK(actor_version BETWEEN 1 AND 18446744073709551615),
 target_version numeric(20,0) NOT NULL CHECK(target_version BETWEEN 1 AND 18446744073709551615),
 approver_version numeric(20,0) NOT NULL CHECK(approver_version BETWEEN 1 AND 18446744073709551615),
 approver_authority_version numeric(20,0) NOT NULL CHECK(approver_authority_version BETWEEN 1 AND 18446744073709551615),
 authority_namespace identity_impersonation.directory_id NOT NULL,
 parent_id text COLLATE "C" NOT NULL CHECK(parent_id ~ '^[!-~]{1,128}$'),
 parent_version numeric(20,0) NOT NULL CHECK(parent_version BETWEEN 1 AND 18446744073709551615),
 parent_digest_key bigint NOT NULL CHECK(parent_digest_key BETWEEN 1 AND 4294967295),
 parent_digest bytea NOT NULL CHECK(octet_length(parent_digest)=32),
 derived_digest_key bigint NOT NULL CHECK(derived_digest_key BETWEEN 1 AND 4294967295),
 derived_digest bytea NOT NULL CHECK(octet_length(derived_digest)=32),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at) AND started_at>='0001-01-01 00:00:00+00'::timestamptz AND started_at<'10000-01-01 00:00:00+00'::timestamptz),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at AND expires_at<=started_at+interval '15 minutes' AND expires_at<'10000-01-01 00:00:00+00'::timestamptz),
 state text COLLATE "C" NOT NULL,
 version smallint NOT NULL,
 CHECK((state='active' AND version=3) OR (state IN ('stopped','revoked','expired') AND version=4)),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,activation_command_id),
 UNIQUE(tenant_id,derived_digest_key,derived_digest)
);

CREATE FUNCTION identity_impersonation.preserve_activation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'impersonation activation is retained' USING ERRCODE='23514';
 END IF;
 IF (to_jsonb(NEW)-'state'-'version') IS DISTINCT FROM (to_jsonb(OLD)-'state'-'version')
  OR OLD.state<>'active' OR OLD.version<>3 OR NEW.state NOT IN ('stopped','revoked','expired') OR NEW.version<>4 THEN
  RAISE EXCEPTION 'impersonation activation lineage is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER preserve_activation BEFORE UPDATE OR DELETE ON identity_impersonation.active_grants
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_activation();
`
