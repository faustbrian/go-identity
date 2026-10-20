package passwordpostgres

import (
	"context"
	"math"
	"reflect"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhonePasswordResetMigrationSource appends phone-reset completion to the
// existing replacement material marker. Base must retain the canonical password
// history through reset-material migration 6, followed by any selected optional
// history; Version must follow every entry. Install in the same identity_password
// migration namespace. Prior SQL, checksums, rows, command foreign keys, uniqueness
// and credential-version checks remain unchanged. This suffix enables no workflow
// or independent password-reset authority.
type PhonePasswordResetMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = PhonePasswordResetMigrationSource{}

// Load copies a forward-only transactional history without IO or downgrade SQL.
// Missing or altered reset history, nil/canceled context, nil Base, unordered or
// colliding migrations, and invalid/exhausted versions return no partial history.
// Errors from Base and context cancellation preserve their classifications.
func (s PhonePasswordResetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A matching migration name alone cannot establish the installed reset
	// constraint. Compare the immutable owning history, not unrelated suffix SQL.
	canonical, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) < 6 || len(history) >= migrations.MaxMigrationFiles {
		return nil, password.ErrPasswordWork
	}
	for i, expected := range canonical[:6] {
		if history[i] != expected {
			return nil, password.ErrPasswordWork
		}
	}
	const name = "identity_password_phone_reset_material_effects"
	var previous migrations.Version
	for _, step := range history {
		if step.Version() <= previous || step.Version() >= s.Version || step.Name() == "" || step.Name() == name || step.Checksum() == (migrations.Checksum{}) {
			return nil, password.ErrPasswordWork
		}
		previous = step.Version()
	}
	forward, err := migrations.NewMigration(s.Version, name, migrations.TransactionModeDefault, phonePasswordResetMaterialSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// The canonical reset migration owns this closed constraint. Widen only its
// operation allowlist; keep the original marker and all of its custody checks.
const phonePasswordResetMaterialSQL = `ALTER TABLE identity_password.replacements
 DROP CONSTRAINT replacements_purpose_check,
 ADD CONSTRAINT replacements_purpose_check CHECK(purpose IN ('identity.password.change','identity.password.reset-complete','identity.phone.password-reset-complete'));
`
