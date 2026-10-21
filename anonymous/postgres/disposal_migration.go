package anonymouspostgres

import (
	"context"
	"math"
	"strings"

	"github.com/faustbrian/go-identity/anonymous"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// DisposalMigrationSource appends retained anonymous-owned self-deletion
// evidence after subject/kernel histories; schema/version are permanent explicit
// installation inputs. Existing creation SQL remains byte-for-byte unchanged.
type DisposalMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load performs no IO and enables no endpoint. The existing runner owns the
// forward-only installation; invalid scope/order at installation fails closed.
func (s DisposalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, anonymous.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_disposals", migrations.TransactionModeDefault, strings.ReplaceAll(disposalSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const disposalSQL = `CREATE TABLE @schema@.disposals(
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.anonymous.delete'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 user_id identity.directory_id NOT NULL,
 before_version identity.version NOT NULL CHECK(before_version=1),
 after_version identity.version NOT NULL CHECK(after_version=2),
 terminal_state smallint NOT NULL,
 cleanup smallint NOT NULL CHECK(cleanup BETWEEN 1 AND 3),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
 CHECK((cleanup=1 AND terminal_state=3) OR (cleanup=2 AND terminal_state=5) OR (cleanup=3 AND terminal_state=6)),
 PRIMARY KEY(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES @schema@.subjects(tenant_id,user_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);`
