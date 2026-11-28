package impersonationpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SelfStopMigrationSource appends version six to unchanged v1-v5 history.
// Apply it before enabling self-stop; constructors never apply DDL. It creates
// only empty tables and their immutable guards, with no existing-table DDL,
// foreign keys or backfill. Reverting code retains the proof and stop records;
// there is no destructive down migration that could restore stopped authority.
type SelfStopMigrationSource struct{}

var _ migrations.Source = SelfStopMigrationSource{}

// Load returns fresh forward-only history without I/O. The caller owns each
// bounded migration transaction and must resolve failures before self-stop.
func (SelfStopMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (RevocationMigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	selfStop, err := migrations.NewMigration(6, "identity_impersonation_self_stop", migrations.TransactionModeDefault, selfStopSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, selfStop), nil
}

const selfStopSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE identity_impersonation.stop_proofs (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 activation_command_id text COLLATE "C" NOT NULL CHECK(activation_command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND activation_command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND activation_command_id<>grant_id),
 csrf_key bigint NOT NULL CHECK(csrf_key BETWEEN 1 AND 4294967295),
 csrf_digest bytea NOT NULL CHECK(octet_length(csrf_digest)=32),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,activation_command_id)
);

CREATE FUNCTION identity_impersonation.preserve_stop_proof() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'impersonation stop proof is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER preserve_stop_proof BEFORE UPDATE OR DELETE ON identity_impersonation.stop_proofs
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_stop_proof();

CREATE TABLE identity_impersonation.stops (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND command_id<>grant_id),
 activation_command_id text COLLATE "C" NOT NULL CHECK(activation_command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND activation_command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND activation_command_id<>grant_id AND activation_command_id<>command_id),
 actor_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL CHECK(target_id<>actor_id),
 policy_id identity_impersonation.directory_id NOT NULL,
 policy_version numeric(20,0) NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615),
 stopped_at timestamptz NOT NULL CHECK(isfinite(stopped_at) AND stopped_at>='0001-01-01 00:00:00+00'::timestamptz AND stopped_at<'10000-01-01 00:00:00+00'::timestamptz),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,command_id)
);

CREATE FUNCTION identity_impersonation.preserve_stop() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'impersonation stop is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER preserve_stop BEFORE UPDATE OR DELETE ON identity_impersonation.stops
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_stop();
`
