package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AnonymousIdentityMigrationSource selects the kernel-owned non-contact
// placeholder namespace. Base must include identifier retirement and comparison
// normalization histories, plus every installed successor; Version follows all
// of them. Existing identifiers and immutable predecessor SQL are unchanged.
// This forward migration enables no anonymous lifecycle, session or endpoint;
// their owning adapters and explicit composition remain separately required.
type AnonymousIdentityMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward-only history without IO. Missing
// predecessors, invalid ordering, cancellation and zero configuration fail
// closed. The existing migrations runner owns installation and recovery.
func (s AnonymousIdentityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "anonymous_identity_migration"}
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	retirements, normalization := false, false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, invalid
		}
		retirements = retirements || step.Name() == "identity_identifier_retirements"
		normalization = normalization || step.Name() == "identity_identifier_normalization"
	}
	if !retirements || !normalization {
		return nil, invalid
	}
	step, err := migrations.NewMigration(s.Version, "identity_anonymous_placeholder", migrations.TransactionModeDefault, anonymousIdentitySQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), step), nil
}

// Anonymous placeholders are not pending email contacts. Keeping their own
// kind preserves the existing email/phone recipient index and excludes them
// from pending-contact verification/delivery. The final base64url character's
// two significant bits enforce the root's canonical 128-bit opaque-ID encoding;
// no email normalization, display value or verified history belongs here.
const anonymousIdentitySQL = `ALTER TABLE identity.identifiers
 DROP CONSTRAINT identifiers_kind_check,
 ADD CONSTRAINT identifiers_kind_check CHECK (
  kind IN ('email','phone','username','provider-subject','anonymous-placeholder')),
 ADD CONSTRAINT identity_anonymous_placeholder_shape CHECK (
  kind<>'anonymous-placeholder' OR (
   canonical_value ~ '^[A-Za-z0-9_-]{21}[AQgw]@anonymous[.]invalid$'
   AND display_value='' AND NOT verified AND NOT is_primary
   AND verification_state IN (1,3) AND verified_at IS NULL
   AND normalization_profile='' AND normalization_version=0));

ALTER TABLE identity.identifier_retirements
 DROP CONSTRAINT identifier_retirements_kind_check,
 ADD CONSTRAINT identifier_retirements_kind_check CHECK (
  kind IN ('email','phone','username','provider-subject','anonymous-placeholder'));

CREATE TABLE identity.anonymous_creation_bindings (
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.anonymous.signin'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 user_id identity.directory_id NOT NULL,
 identifier_id identity.directory_id NOT NULL,
 PRIMARY KEY(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,user_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`

var _ migrations.Source = AnonymousIdentityMigrationSource{}
