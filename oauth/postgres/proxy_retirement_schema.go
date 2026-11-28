package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyRetirementMigrationSource adds an opt-in, local retirement state to one
// origin's existing proxy custody table. Version and Version+1 are reserved
// after its base custody migration. Apply both migrations before enabling the
// retirement writer. Neither changes existing rows or restores erased secrets.
type ProxyRetirementMigrationSource struct {
	Schema  string
	Version migrations.Version
	Kind    kernel.OAuthProxyRetirementKind
}

var _ migrations.Source = ProxyRetirementMigrationSource{}

// Load separates the short schema lock from validation of existing rows.
// Normal callback writers can still use the original open and settled shapes;
// retirement has its own version and cannot be mistaken for settlement.
func (s ProxyRetirementMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "oauth_proxy_retirement_migration"}
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version >= migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var table, previousCheck, name, custodyShape string
	switch s.Kind {
	case kernel.OAuthProxyRetireProduction:
		table, previousCheck = "proxy_transactions", "proxy_transactions_check1"
		name, custodyShape = "identity_oauth_proxy_transaction_retirement", proxyRetiredProductionShape
	case kernel.OAuthProxyRetirePreview:
		table, previousCheck = "proxy_preview_bindings", "proxy_preview_bindings_check2"
		name, custodyShape = "identity_oauth_proxy_preview_retirement", proxyRetiredPreviewShape
	default:
		return nil, invalid
	}
	qualified := rpQuotedSchema(s.Schema) + "." + table
	constraint := table + "_retirement_shape"
	expand := strings.NewReplacer("@table@", qualified, "@previous@", previousCheck, "@constraint@", constraint, "@shape@", custodyShape).Replace(proxyRetirementExpand)
	validate := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + qualified + ` VALIDATE CONSTRAINT ` + constraint + ";\n"
	history := make([]migrations.Migration, 0, 2)
	for i, step := range []struct{ name, sql string }{{name, expand}, {name + "_validation", validate}} {
		migration, err := migrations.NewMigration(s.Version+migrations.Version(i), step.name, migrations.TransactionModeDefault, step.sql, "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		history = append(history, migration)
	}
	return history, nil
}

// Replace only the original open/settled shape check. The nullable additions
// need no rewrite, and NOT VALID keeps the validation scan out of this lock.
const proxyRetirementExpand = `SET LOCAL lock_timeout = '5s';
ALTER TABLE @table@
 ADD COLUMN retirement_source_command_id bytea,
 ADD COLUMN retirement_source_version numeric,
 ADD COLUMN retired_at timestamptz,
 DROP CONSTRAINT @previous@,
 ADD CONSTRAINT @constraint@ CHECK(@shape@) NOT VALID;
`

const proxyRetiredOriginal = `retirement_source_command_id IS NULL AND retirement_source_version IS NULL AND retired_at IS NULL`

const proxyRetiredProvenance = `retirement_source_command_id IS NOT NULL AND octet_length(retirement_source_command_id)=16
 AND retirement_source_command_id<>decode(repeat('00',16),'hex') AND retirement_source_command_id<>origin_command_id
 AND retirement_source_command_id<>callback_command_id AND retirement_source_version IS NOT NULL
 AND retirement_source_version BETWEEN 1 AND 18446744073709551615
 AND scale(retirement_source_version)=0
 AND retired_at IS NOT NULL AND isfinite(retired_at) AND retired_at>=issued_at`

const proxyRetiredProductionShape = `(` + proxyRetiredOriginal + ` AND (
 (version=1 AND outcome IS NULL AND handoff_ciphertext IS NULL AND settled_at IS NULL
  AND state_proof_ciphertext IS NOT NULL AND pkce_ciphertext IS NOT NULL)
 OR (version=2 AND outcome IS NOT NULL AND outcome IN(1,2) AND settled_at IS NOT NULL AND settled_at>=issued_at
  AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL
  AND ((outcome=1 AND handoff_ciphertext IS NOT NULL) OR (outcome=2 AND handoff_ciphertext IS NULL)))
)) OR (version=3 AND ` + proxyRetiredProvenance + `
 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL
 AND ((outcome IS NULL AND settled_at IS NULL) OR (outcome IS NOT NULL AND outcome IN(1,2)
  AND settled_at IS NOT NULL AND settled_at>=issued_at AND settled_at<=retired_at)))`

const proxyRetiredPreviewShape = `(` + proxyRetiredOriginal + ` AND (
 (version=1 AND proof_ciphertext IS NOT NULL AND settled_at IS NULL)
 OR (version=2 AND proof_ciphertext IS NULL AND settled_at IS NOT NULL AND settled_at>=issued_at)
)) OR (version=3 AND ` + proxyRetiredProvenance + ` AND proof_ciphertext IS NULL
 AND (settled_at IS NULL OR (settled_at>=issued_at AND settled_at<=retired_at)))`
