package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PrivacyExportJobMigrationSource appends bounded privacy job/snapshot storage
// after immutable Base history. Base must include PrivacyExportMigrationSource.
// Allocate Version after every Base version; no destructive down is supported.
// Stored metadata is pseudonymous personal data, never bearer material. This
// schema does not enable admission, workers, publication or downloads.
type PrivacyExportJobMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = PrivacyExportJobMigrationSource{}

// Load copies forward-only history without IO. Nil context/base, empty history
// and non-successor versions fail closed; cancellation and base errors propagate.
// Apply through the migration Runner; do not modify already applied SQL.
func (s PrivacyExportJobMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "privacy_job_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "privacy_job_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "privacy_job_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "identity_privacy_export_jobs", migrations.TransactionModeDefault, privacyExportJobSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const privacyExportJobSQL = `CREATE TABLE identity.privacy_export_jobs (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 export_id text COLLATE "C" NOT NULL CHECK(export_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 privacy_epoch identity.version NOT NULL,
 status text COLLATE "C" NOT NULL CHECK(status IN ('queued','running','ready','failed','cancelled','expired')),
 requested_at timestamptz NOT NULL CHECK(isfinite(requested_at) AND requested_at >= '0001-01-01 00:00:00+00'::timestamptz AND requested_at < '10000-01-01 00:00:00+00'::timestamptz),
 snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),
 receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 32768),
 PRIMARY KEY(tenant_id,user_id,export_id),
 UNIQUE(export_id),
 UNIQUE(command_id),
 UNIQUE(tenant_id,user_id,privacy_epoch),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX identity_privacy_export_queue ON identity.privacy_export_jobs(status,requested_at,export_id);
`
