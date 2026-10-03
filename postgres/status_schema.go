package postgres

import (
	"context"
	"math"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// StatusMigrationSource composes immutable kernel history with lifecycle
// admission storage at an explicitly allocated later version. Base may include
// session adapters; Version must exceed every base version and fit signed SQL
// migration storage. Existing MigrationSource and its installed bytes are
// unchanged. Load performs no SQL; the owned migration Runner applies it.
type StatusMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = StatusMigrationSource{}

// Load returns caller-owned forward-only history. Nil/invalid composition fails
// closed; cancellation is preserved. Migration initialization deliberately
// persists security epoch 1 without changing aggregate/identifier versions or
// blocked status. Old creation/profile writers remain compatible with defaults.
func (s StatusMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "status_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "status_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "status_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_status_admission", migrations.TransactionModeDefault, statusSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

func nilStatusSource(s migrations.Source) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

const statusSchemaSQL = `ALTER TABLE identity.users
 ADD COLUMN authority_version identity.version NOT NULL DEFAULT 1,
 ADD COLUMN status_reason text COLLATE "C",
 ADD COLUMN status_expires_at timestamptz,
 ADD COLUMN legal_hold boolean NOT NULL DEFAULT false,
 ADD COLUMN legal_hold_version identity.version NOT NULL DEFAULT 1,
 ADD CONSTRAINT identity_status_reason CHECK (status_reason IS NULL OR octet_length(status_reason) BETWEEN 1 AND 512),
 ADD CONSTRAINT identity_status_expiry CHECK (status_expires_at IS NULL OR
  (isfinite(status_expires_at) AND status_expires_at >= '0001-01-01 00:00:00+00'::timestamptz AND status_expires_at < '10000-01-01 00:00:00+00'::timestamptz));

CREATE TABLE identity.status_policies (
 tenant_id identity.directory_id NOT NULL,
 policy_version identity.version NOT NULL,
 definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 65536),
 PRIMARY KEY(tenant_id,policy_version)
);

CREATE TABLE identity.status_cascades (
 cascade_id text COLLATE "C" PRIMARY KEY CHECK (cascade_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK (command_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_key bytea NOT NULL,
 operation text COLLATE "C" NOT NULL,
 generation identity.version NOT NULL CHECK (generation=1),
 manifest_version text COLLATE "C" NOT NULL CHECK (manifest_version='identity-lifecycle-consumers-v1'),
 policy_version identity.version NOT NULL,
 authority_version identity.version NOT NULL,
 aggregate_version identity.version NOT NULL,
 trigger_event_id text COLLATE "C" NOT NULL,
 trigger_event_type text COLLATE "C" NOT NULL CHECK (trigger_event_type IN ('identity.suspended.v1','identity.restored.v1')),
 trigger_schema_version integer NOT NULL CHECK (trigger_schema_version=1),
 requested_at timestamptz NOT NULL,
 deadline timestamptz NOT NULL CHECK (deadline>requested_at),
 legal_hold boolean NOT NULL,
 legal_hold_version identity.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK (state='pending'),
 UNIQUE(tenant_id,cascade_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,policy_version) REFERENCES identity.status_policies(tenant_id,policy_version),
 FOREIGN KEY(tenant_id,operation,command_key) REFERENCES identity.commands(tenant_id,purpose,command_id)
);

CREATE TABLE identity.status_consumers (
 tenant_id identity.directory_id NOT NULL,
 cascade_id text COLLATE "C" NOT NULL,
 ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 11),
 consumer_id text COLLATE "C" NOT NULL CHECK (octet_length(consumer_id) BETWEEN 1 AND 128),
 contract_version bigint NOT NULL CHECK (contract_version BETWEEN 1 AND 4294967295),
 contract_fingerprint bytea NOT NULL CHECK (octet_length(contract_fingerprint)=32 AND contract_fingerprint<>decode(repeat('00',32),'hex')),
 state text COLLATE "C" NOT NULL CHECK (state='pending'),
 PRIMARY KEY(tenant_id,cascade_id,consumer_id),
 UNIQUE(tenant_id,cascade_id,ordinal),
 FOREIGN KEY(tenant_id,cascade_id) REFERENCES identity.status_cascades(tenant_id,cascade_id)
);
`
