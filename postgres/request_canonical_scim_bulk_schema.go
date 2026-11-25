package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// CanonicalSCIMBulkRequestMigrationSource expands the existing immutable
// aliases for the exact service-account Bulk POST. Base must include the
// canonical SAML start schema migration; no SAML runtime is started or needed.
// Version and Version+1 reserve expansion and validation. Existing mappings,
// aliases and their referenced command custody are not rewritten.
type CanonicalSCIMBulkRequestMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns caller-owned forward-only history without I/O.
func (s CanonicalSCIMBulkRequestMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	var expanded, validated bool
	for _, entry := range history {
		if entry.Version() >= s.Version {
			return nil, invalidRequestKey()
		}
		expanded = expanded || entry.UpSQL() == canonicalSAMLStartExpandSQL
		validated = validated || entry.UpSQL() == canonicalSAMLStartValidateSQL
	}
	if !expanded || !validated {
		return nil, invalidRequestKey()
	}
	expand, err := migrations.NewMigration(s.Version, "identity_canonical_scim_bulk_expand", migrations.TransactionModeDefault, canonicalSCIMBulkExpandSQL, "")
	if err != nil {
		return nil, err
	}
	validate, err := migrations.NewMigration(s.Version+1, "identity_canonical_scim_bulk_validate", migrations.TransactionModeDefault, canonicalSCIMBulkValidateSQL, "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), expand, validate), nil
}

// Only replace the alias check. The POST canonical mapping is already
// supported; the alias primary and foreign keys keep the original custody.
const canonicalSCIMBulkExpandSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity.request_key_aliases
 ADD CONSTRAINT request_key_aliases_scim_bulk_method CHECK (
  method='DELETE' OR
  (method='GET' AND route_id='identity.sso.saml-start' AND actor_kind='service-account') OR
  (method='POST' AND route_id='identity.scim.bulk' AND actor_kind='service-account')
 ) NOT VALID,
 DROP CONSTRAINT request_key_aliases_saml_start_method;
`

const canonicalSCIMBulkValidateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity.request_key_aliases VALIDATE CONSTRAINT request_key_aliases_scim_bulk_method;
`
