package mfapostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SSOOIDCJITFactorMigrationSource adds enterprise initialization provenance to
// the same native factor-authority row. Base contains the installed MFA history;
// Version, ValidationVersion and IndexVersion follow it in that order in the
// same namespace. All three steps must finish before enabling prospective JIT.
//
// Existing signup CHECKs, command foreign keys and uniqueness remain unchanged,
// so optional magic-link, username and passkey migrations can run before or
// after this suffix. Legacy initialized_purpose becomes nullable only because
// a separate CHECK requires exactly one legacy or fixed SSO provenance branch.
// No account, enrollment, factor generation or old migration bytes are changed.
//
// Expansion adds NOT VALID constraints under a bounded metadata lock; separate
// validation scans without retaining that exclusive lock. The final unique
// partial index builds concurrently outside a transaction. The caller's bounded
// migration runner owns execution. A failed index build requires inspecting
// pg_index.indisvalid and explicit recovery: drop an invalid index concurrently
// before retrying, never adopt a same-name index. Reverting code may leave this
// additive schema in place; no destructive downgrade is supplied.
type SSOOIDCJITFactorMigrationSource struct {
	Base                                     migrations.Source
	Version, ValidationVersion, IndexVersion migrations.Version
}

// Load is pure and forward-only. Invalid ordering returns no partial history;
// existing unmanaged SSO columns or constraints fail visibly at application.
func (s SSOOIDCJITFactorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.ValidationVersion <= s.Version || s.IndexVersion <= s.ValidationVersion || s.IndexVersion > migrations.Version(math.MaxInt64) {
		return nil, invalidAuthority()
	}
	// Reuse the signup suffix's immutable-history/context validation. Only its
	// newly generated, uninstalled final step is replaced; Base is unchanged.
	history, err := (MagicLinkSignupMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	expansion, err := migrations.NewMigration(s.Version, "identity_mfa_sso_oidc_jit_expand", migrations.TransactionModeDefault, ssoOIDCJITFactorExpansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_mfa_sso_oidc_jit_validate", migrations.TransactionModeDefault, ssoOIDCJITFactorValidationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	index, err := migrations.NewMigration(s.IndexVersion, "identity_mfa_sso_oidc_jit_unique", migrations.TransactionModeNone, ssoOIDCJITFactorIndexSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	history[len(history)-1] = expansion
	return append(history, validation, index), nil
}

// LoadOffline selects transactional index creation for an offline installation
// whose existing migration owner requires an atomic command. Base, expansion
// and validation are identical to Load; only the final index step's transaction
// mode, SQL and checksum differ. The index name, columns and predicate are the
// same, with a five-second lock-acquisition timeout.
//
// Ordinary index creation blocks writes through its build and the enclosing
// transaction's lifetime. Select this only while writers are quiescent, with a
// bounded migration context; lock_timeout does not limit build or lock-hold
// duration. Choose the history before application: this variant must never
// replace an applied concurrent step at the same version. Version allocation
// remains caller-owned. This method performs no I/O and starts no transaction.
func (s SSOOIDCJITFactorMigrationSource) LoadOffline(ctx context.Context) ([]migrations.Migration, error) {
	history, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	last := len(history) - 1
	indexSQL := "SET LOCAL lock_timeout = '5s';\n" + strings.Replace(ssoOIDCJITFactorIndexSQL, "CREATE UNIQUE INDEX CONCURRENTLY ", "CREATE UNIQUE INDEX ", 1)
	index, err := migrations.NewMigration(history[last].Version(), history[last].Name(), migrations.TransactionModeDefault, indexSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	history[last] = index
	return history, nil
}

// Legacy signup suffixes explicitly replace their original purpose CHECKs.
// Keeping those CHECKs on nullable legacy provenance lets their unmodified
// SQL coexist with populated JIT rows without weakening either branch.
const ssoOIDCJITFactorExpansionSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity_mfa.factor_authorities
 ADD COLUMN sso_oidc_initialized_purpose text COLLATE "C",
 ALTER COLUMN initialized_purpose DROP NOT NULL,
 ADD CONSTRAINT factor_authorities_initialization_provenance_v1 CHECK (
  (initialized_purpose IS NOT NULL AND sso_oidc_initialized_purpose IS NULL)
  OR (initialized_purpose IS NULL AND sso_oidc_initialized_purpose IS NOT NULL
      AND sso_oidc_initialized_purpose='identity.sso.oidc-callback')
 ) NOT VALID,
 ADD CONSTRAINT factor_authorities_sso_oidc_command_fkey
 FOREIGN KEY(tenant_id,sso_oidc_initialized_purpose,initialized_command_id)
 REFERENCES identity.commands(tenant_id,purpose,command_id) NOT VALID;
`

const ssoOIDCJITFactorValidationSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity_mfa.factor_authorities VALIDATE CONSTRAINT factor_authorities_initialization_provenance_v1;
ALTER TABLE identity_mfa.factor_authorities VALIDATE CONSTRAINT factor_authorities_sso_oidc_command_fkey;
`

const ssoOIDCJITFactorIndexSQL = `CREATE UNIQUE INDEX CONCURRENTLY factor_authorities_sso_oidc_command_unique ON identity_mfa.factor_authorities(tenant_id,initialized_command_id) WHERE sso_oidc_initialized_purpose IS NOT NULL;`
