package anonymouspostgres

import (
	"context"
	"math"
	"strings"

	"github.com/faustbrian/go-identity/anonymous"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource installs this dedicated owner after the actual kernel's
// anonymous-placeholder history. Version is a permanent unused allocation;
// callers use the existing migration runner's explicit history namespace. It
// enables no endpoint and has no destructive downgrade or automatic bootstrap.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one independently owned forward migration without IO. Kernel
// reference failures are fatal; no IF EXISTS fallback adopts another history.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, anonymous.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(subjectSchema, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	step, err := migrations.NewMigration(s.Version, "identity_anonymous_subjects", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	return []migrations.Migration{step}, nil
}

const subjectSchema = `CREATE SCHEMA @schema@;
CREATE TABLE @schema@.subjects(
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 subject_id identity.directory_id NOT NULL CHECK(subject_id=user_id),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 state smallint NOT NULL CHECK(state BETWEEN 1 AND 6),
 version identity.version NOT NULL CHECK(state=1 OR version>1),
 cleanup smallint NOT NULL CHECK(cleanup BETWEEN 1 AND 3),
 creation_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.anonymous.signin' CHECK(creation_purpose='identity.anonymous.signin'),
 creation_command_id bytea NOT NULL CHECK(octet_length(creation_command_id)=16),
 PRIMARY KEY(tenant_id,user_id),
 UNIQUE(tenant_id,creation_command_id),
 CHECK(expires_at>=created_at+interval '15 minutes' AND expires_at<=created_at+interval '30 days'),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,creation_purpose,creation_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
CREATE INDEX anonymous_subjects_expiry ON @schema@.subjects(tenant_id,expires_at,user_id) WHERE state=1;
`
