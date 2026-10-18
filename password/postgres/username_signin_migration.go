package passwordpostgres

import (
	"context"
	"math"
	"reflect"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsernameSigninMigrationSource extends original completed-password provenance.
// Base contains the existing password history; Version follows all Base entries.
// Existing rows, installed checksums and MFA continuation purposes stay unchanged.
// This suffix does not enable username MFA challenges or expose a signin route.
type UsernameSigninMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns copied forward-only history without a database or runner.
func (s UsernameSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, password.ErrPasswordWork
	}
	base := reflect.ValueOf(s.Base)
	switch base.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if base.IsNil() {
			return nil, password.ErrPasswordWork
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
		return nil, password.ErrPasswordWork
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, password.ErrPasswordWork
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_username_signin", migrations.TransactionModeDefault, `ALTER TABLE identity_password.signin_records DROP CONSTRAINT signin_records_purpose_check;
ALTER TABLE identity_password.signin_records ADD CONSTRAINT signin_records_purpose_v2 CHECK(purpose IN('identity.password.signin','identity.username.signin'));
`, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}
