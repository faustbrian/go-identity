package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// CanonicalSAMLStartRequestMigrationSource allows only the exact SAML browser
// start GET in the existing canonical mapping and retry alias tables. Base
// includes CanonicalRequestMigrationSource. Version and Version+1 are reserved
// for the expansion and validation; previous entries and stored rows are
// unchanged. Roll back application selection, not the expanded constraints.
type CanonicalSAMLStartRequestMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns caller-owned forward-only history without I/O.
func (s CanonicalSAMLStartRequestMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version >= migrations.Version(math.MaxInt64) {
		return nil, invalidRequestKey()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	var mapping, alias bool
	for _, entry := range history {
		if entry.Version() >= s.Version {
			return nil, invalidRequestKey()
		}
		mapping = mapping || entry.UpSQL() == requestKeySQL
		alias = alias || entry.UpSQL() == canonicalRequestSQL
	}
	if !mapping || !alias {
		return nil, invalidRequestKey()
	}
	expand, err := migrations.NewMigration(s.Version, "identity_canonical_saml_start_expand", migrations.TransactionModeDefault, canonicalSAMLStartExpandSQL, "")
	if err != nil {
		return nil, err
	}
	validate, err := migrations.NewMigration(s.Version+1, "identity_canonical_saml_start_validate", migrations.TransactionModeDefault, canonicalSAMLStartValidateSQL, "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), expand, validate), nil
}

// Keep the exclusive expansion locks short; historical rows are validated in
// the subsequent migration while new rows already obey the new constraints.
const canonicalSAMLStartExpandSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity.request_key_mappings
 ADD CONSTRAINT request_key_mappings_saml_start_method CHECK (
  method IN ('POST','PUT','PATCH','DELETE') OR
  (method='GET' AND route_id='identity.sso.saml-start' AND actor_kind='service-account')
 ) NOT VALID,
 DROP CONSTRAINT request_key_mappings_method_check;
ALTER TABLE identity.request_key_aliases
 ADD CONSTRAINT request_key_aliases_saml_start_method CHECK (
  method='DELETE' OR
  (method='GET' AND route_id='identity.sso.saml-start' AND actor_kind='service-account')
 ) NOT VALID,
 DROP CONSTRAINT request_key_aliases_method_check;
`

const canonicalSAMLStartValidateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity.request_key_mappings VALIDATE CONSTRAINT request_key_mappings_saml_start_method;
ALTER TABLE identity.request_key_aliases VALIDATE CONSTRAINT request_key_aliases_saml_start_method;
`
