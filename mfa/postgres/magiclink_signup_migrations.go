package mfapostgres

import (
	"context"
	"math"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MagicLinkSignupMigrationSource preserves the original MFA history and adds
// passwordless creation provenance. Base must install MigrationSource; allocate
// Version after Base in its namespace. It does not backfill empty factor state.
type MagicLinkSignupMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns additive history without SQL IO or a destructive downgrade.
func (s MagicLinkSignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidAuthority()
	}
	v := reflect.ValueOf(s.Base)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.Interface:
		if v.IsNil() {
			return nil, invalidAuthority()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidAuthority()
	}
	for _, old := range history {
		if old.Version() >= s.Version {
			return nil, invalidAuthority()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_magiclink_signup", migrations.TransactionModeDefault, magicLinkSignupSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const magicLinkSignupSQL = `ALTER TABLE identity_mfa.factor_authorities
 DROP CONSTRAINT factor_authorities_initialized_purpose_check,
 ADD CONSTRAINT factor_authorities_initialized_purpose_v2 CHECK (
  initialized_purpose IN ('identity.password.signup','identity.magic-link.consume')
 );
`
