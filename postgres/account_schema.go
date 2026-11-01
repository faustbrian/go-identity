package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AccountMigrationSource appends identity-owned provider-link storage to Base,
// which must already include CredentialMigrationSource. Version must exceed all
// Base versions. Load performs no I/O and preserves installed migration bytes;
// the caller applies this forward-only source with the migrations Runner.
// Neither installing it nor inserting metadata establishes provider proof.
type AccountMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = AccountMigrationSource{}

// Load returns independently owned history. Missing/invalid composition and
// cancellation fail without partial history. Existing users retain their epochs,
// credentials and status; no account or authentication authority is synthesized.
func (s AccountMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "account_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "account_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "account_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_provider_accounts", migrations.TransactionModeDefault, accountSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// The exact provider tuple can exceed a PostgreSQL B-tree entry's one-third-page
// limit (PostgreSQL 18, btree.html). Index its length-framed UTF-8 SHA-256 instead,
// retain the original tuple and compare it on every lookup: a digest collision
// denies rather than selecting another identity. This is metadata indexing, not
// a bearer verifier. The CHECK prevents divergent caller-supplied index values.
const accountSchemaSQL = `CREATE TABLE identity.accounts (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 account_id identity.directory_id NOT NULL,
 provider identity.directory_id NOT NULL,
 issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
 subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 512 AND subject !~ '[[:cntrl:]]'),
 subject_key bytea NOT NULL CHECK (octet_length(subject_key)=32),
 version identity.version NOT NULL,
 social_link_version identity.version NOT NULL,
 linked boolean NOT NULL,
 PRIMARY KEY(tenant_id,account_id),
 UNIQUE(tenant_id,user_id,account_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 CONSTRAINT identity_account_subject_key CHECK (subject_key=sha256(convert_to(
  octet_length(provider)::text||':'||provider||
  octet_length(issuer)::text||':'||issuer||
  octet_length(subject)::text||':'||subject,'UTF8')))
);

CREATE UNIQUE INDEX identity_accounts_live_subject ON identity.accounts(tenant_id,subject_key) WHERE linked;
CREATE INDEX identity_accounts_user ON identity.accounts(tenant_id,user_id,account_id) WHERE linked;

CREATE TABLE identity.account_credentials (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 account_id identity.directory_id NOT NULL,
 PRIMARY KEY(tenant_id,user_id,credential_id),
 FOREIGN KEY(tenant_id,user_id,credential_id) REFERENCES identity.credential_references(tenant_id,user_id,credential_id),
 FOREIGN KEY(tenant_id,user_id,account_id) REFERENCES identity.accounts(tenant_id,user_id,account_id)
);
`
