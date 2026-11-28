package impersonationpostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource explicitly installs version one of the independent
// identity_impersonation history. Apply it before selecting this adapter; no
// constructor applies DDL. It creates only an empty namespace and new objects,
// with no foreign keys, locks or backfill on existing authentication tables.
// Existing binaries remain unchanged. Reverting code may retain the schema;
// there is deliberately no destructive down migration for retained requests.
type MigrationSource struct{}

var _ migrations.Source = MigrationSource{}

// Load returns a fresh forward-only migration without I/O. Installation uses
// the caller's bounded migration transaction; a failure rolls back all new
// objects and must be resolved by that migration owner before enabling callers.
func (MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, identity.InvalidInputError{Field: "impersonation_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(1, "identity_impersonation_pending_approval", migrations.TransactionModeDefault, impersonationSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

const impersonationSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE SCHEMA identity_impersonation;
CREATE DOMAIN identity_impersonation.directory_id AS text COLLATE "C"
 CHECK(octet_length(VALUE) BETWEEN 1 AND 128 AND VALUE !~ '[[:cntrl:] ]');

CREATE TABLE identity_impersonation.grants (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL CHECK(grant_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND grant_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 requester_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL CHECK(target_id<>requester_id),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 encrypted_payload bytea NOT NULL CHECK(octet_length(encrypted_payload) BETWEEN 1 AND 65536),
 requested_at timestamptz NOT NULL CHECK(isfinite(requested_at) AND requested_at>='0001-01-01 00:00:00+00'::timestamptz AND requested_at<'10000-01-01 00:00:00+00'::timestamptz),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at=requested_at+interval '15 minutes' AND expires_at<'10000-01-01 00:00:00+00'::timestamptz),
 state text COLLATE "C" NOT NULL,
 version smallint NOT NULL,
 CHECK((state='pending_approval' AND version=1) OR (state='approved' AND version=2)),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,grant_id,requester_id,target_id,request_digest)
);

CREATE TABLE identity_impersonation.approvals (
 tenant_id identity_impersonation.directory_id NOT NULL,
 grant_id text COLLATE "C" NOT NULL,
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND command_id<>grant_id),
 requester_id identity_impersonation.directory_id NOT NULL,
 target_id identity_impersonation.directory_id NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 approver_id identity_impersonation.directory_id NOT NULL CHECK(approver_id<>requester_id AND approver_id<>target_id),
 encrypted_payload bytea NOT NULL CHECK(octet_length(encrypted_payload) BETWEEN 1 AND 65536),
 decided_at timestamptz NOT NULL CHECK(isfinite(decided_at) AND decided_at>='0001-01-01 00:00:00+00'::timestamptz AND decided_at<'10000-01-01 00:00:00+00'::timestamptz),
 PRIMARY KEY(tenant_id,grant_id),
 UNIQUE(tenant_id,command_id),
 FOREIGN KEY(tenant_id,grant_id,requester_id,target_id,request_digest)
  REFERENCES identity_impersonation.grants(tenant_id,grant_id,requester_id,target_id,request_digest)
);

CREATE FUNCTION identity_impersonation.preserve_request() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.tenant_id,NEW.grant_id,NEW.requester_id,NEW.target_id,NEW.request_digest,NEW.encrypted_payload,NEW.requested_at,NEW.expires_at)
  IS DISTINCT FROM ROW(OLD.tenant_id,OLD.grant_id,OLD.requester_id,OLD.target_id,OLD.request_digest,OLD.encrypted_payload,OLD.requested_at,OLD.expires_at)
  OR OLD.state<>'pending_approval' OR OLD.version<>1 OR NEW.state<>'approved' OR NEW.version<>2 THEN
  RAISE EXCEPTION 'impersonation request is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER preserve_request BEFORE UPDATE ON identity_impersonation.grants
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_request();

CREATE FUNCTION identity_impersonation.preserve_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'impersonation approval is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER preserve_approval BEFORE UPDATE ON identity_impersonation.approvals
 FOR EACH ROW EXECUTE FUNCTION identity_impersonation.preserve_approval();
`
