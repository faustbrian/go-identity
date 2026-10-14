// Package mfapostgres owns durable second-factor authority. It borrows the
// identity coordinator's protected transaction; it never starts its own.
package mfapostgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource installs factor generations after kernel users and commands
// in the separately owned identity_mfa migration namespace. Version must be
// allocated permanently in that namespace. Zero denies; Load is pure and
// concurrent-safe. Existing accounts deliberately receive no empty-factor
// backfill: their state remains unknown until authoritative reconciliation.
type MigrationSource struct{ Version migrations.Version }

// Load returns additive installation SQL without destructive downgrade SQL.
// Existing unmanaged objects fail rather than being implicitly adopted.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_mfa_factor_authorities", migrations.TransactionModeDefault, authoritySQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Factor owners must lock this row before any enrollment, activation, removal,
// recovery-set or administrative reset change and advance version atomically.
// A password reset holds the same lock until its protected mutation commits.
// No enrollment writer or protocol implementation is provided by this initial
// authority install; active_factors is not inferred from a missing module.
const authoritySQL = `CREATE SCHEMA identity_mfa;
CREATE TABLE identity_mfa.factor_authorities (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 active_factors integer NOT NULL CHECK(active_factors BETWEEN 0 AND 64),
 initialized_command_id bytea NOT NULL CHECK(octet_length(initialized_command_id)=16),
 initialized_purpose text COLLATE "C" NOT NULL CHECK(initialized_purpose='identity.password.signup'),
 PRIMARY KEY(tenant_id,user_id),
 UNIQUE(tenant_id,initialized_purpose,initialized_command_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,initialized_purpose,initialized_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`
