package passwordpostgres

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

type phoneResetMigrationHistory func(context.Context) ([]migrations.Migration, error)

func (f phoneResetMigrationHistory) Load(ctx context.Context) ([]migrations.Migration, error) {
	return f(ctx)
}

type phoneResetNilHistory struct{}

func (*phoneResetNilHistory) Load(context.Context) ([]migrations.Migration, error) {
	panic("typed nil source must not be called")
}

func TestPhonePasswordResetMigrationPreservesInstalledHistory(t *testing.T) {
	ctx := context.Background()
	original, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	preReset := phoneResetMigrationHistory(func(context.Context) ([]migrations.Migration, error) { return original[:6], nil })
	phone := PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}
	for _, tc := range []struct {
		name string
		base migrations.Source
	}{
		{"native reset predecessor", preReset},
		{"current password history", MigrationSource{}},
		{"selected optional phone history", phone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := tc.base.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			source := PhonePasswordResetMigrationSource{Base: tc.base, Version: 90}
			got, err := source.Load(ctx)
			if err != nil || len(got) != len(before)+1 {
				t.Fatal("missing optional phone reset suffix", err)
			}
			if !reflect.DeepEqual(got[:len(before)], before) {
				t.Fatal("installed migration identity, SQL or checksum changed")
			}
			last := got[len(got)-1]
			if last.Version() != 90 || last.Name() != "identity_password_phone_reset_material_effects" || last.DownSQL() != "" || last.TransactionMode() != migrations.TransactionModeDefault {
				t.Fatal("suffix is not the allocated forward transactional migration")
			}
			again, err := source.Load(ctx)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("immutable source is not repeatable", err)
			}
		})
	}
	if _, err := (PhonePasswordResetMigrationSource{Base: MigrationSource{}, Version: migrations.Version(math.MaxInt64)}).Load(ctx); err != nil {
		t.Fatal("largest valid allocated successor rejected", err)
	}
	// A caller-owned source can expose spare capacity; adding the suffix must
	// neither overwrite that backing storage nor alias its original entries.
	backing := make([]migrations.Migration, len(original)+1)
	copy(backing, original)
	sentinel, err := migrations.NewMigration(100, "untouched_source_capacity", migrations.TransactionModeDefault, "SELECT 1;", "")
	if err != nil {
		t.Fatal(err)
	}
	backing[len(original)] = sentinel
	borrowed := phoneResetMigrationHistory(func(context.Context) ([]migrations.Migration, error) { return backing[:len(original)], nil })
	got, err := (PhonePasswordResetMigrationSource{Base: borrowed, Version: 9}).Load(ctx)
	if err != nil || backing[len(original)] != sentinel {
		t.Fatal("suffix overwrote source-owned capacity", err)
	}
	got[0] = migrations.Migration{}
	if backing[0] != original[0] {
		t.Fatal("returned history aliases source-owned entries")
	}
}

func TestPhonePasswordResetMigrationRejectsInvalidHistory(t *testing.T) {
	ctx := context.Background()
	original, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	makeStep := func(version migrations.Version, name, sql string) migrations.Migration {
		t.Helper()
		step, err := migrations.NewMigration(version, name, migrations.TransactionModeDefault, sql, "")
		if err != nil {
			t.Fatal(err)
		}
		return step
	}
	wrongReset := append([]migrations.Migration(nil), original...)
	wrongReset[5] = makeStep(6, original[5].Name(), "SELECT 1;")
	unordered := append([]migrations.Migration(nil), original...)
	unordered[6], unordered[7] = unordered[7], unordered[6]
	duplicated := append(append([]migrations.Migration(nil), original...), original[7])
	collision := append(append([]migrations.Migration(nil), original...), makeStep(9, "identity_password_phone_reset_material_effects", "SELECT 1;"))
	maximum := append(append([]migrations.Migration(nil), original...), makeStep(migrations.Version(math.MaxInt64), "exhausted_version", "SELECT 1;"))
	static := func(history []migrations.Migration) migrations.Source {
		return phoneResetMigrationHistory(func(context.Context) ([]migrations.Migration, error) { return history, nil })
	}
	for _, tc := range []struct {
		name    string
		base    migrations.Source
		version migrations.Version
	}{
		{"missing base", nil, 9},
		{"typed nil pointer", (*phoneResetNilHistory)(nil), 9},
		{"typed nil function", phoneResetMigrationHistory(nil), 9},
		{"empty history", static(nil), 9},
		{"missing reset predecessor", static(original[:5]), 9},
		{"unrelated history", static([]migrations.Migration{makeStep(1, "unrelated", "SELECT 1;")}), 9},
		{"forged reset name", static(wrongReset), 9},
		{"unordered history", static(unordered), 9},
		{"duplicate version", static(duplicated), 9},
		{"zero suffix migration", static(append(append([]migrations.Migration(nil), original...), migrations.Migration{})), 9},
		{"suffix name collision", static(collision), 10},
		{"version collision", MigrationSource{}, 8},
		{"version precedes history", MigrationSource{}, 7},
		{"zero version", MigrationSource{}, 0},
		{"oversized version", MigrationSource{}, migrations.Version(math.MaxInt64) + 1},
		{"exhausted history", static(maximum), migrations.Version(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (PhonePasswordResetMigrationSource{Base: tc.base, Version: tc.version}).Load(ctx)
			if !errors.Is(err, password.ErrPasswordWork) || got != nil {
				t.Fatal("invalid history did not fail closed without partial output", err)
			}
		})
	}
}

func TestPhonePasswordResetMigrationContextAndSourceFailures(t *testing.T) {
	original, err := (MigrationSource{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sourceErr := errors.New("source unavailable")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	duringLoad, stop := context.WithCancel(context.Background())
	defer stop()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		base migrations.Source
		want error
	}{
		{"nil context", nil, MigrationSource{}, password.ErrPasswordWork},
		{"cancelled context", cancelled, MigrationSource{}, context.Canceled},
		{"source error with partial output", context.Background(), phoneResetMigrationHistory(func(context.Context) ([]migrations.Migration, error) { return original, sourceErr }), sourceErr},
		{"cancelled while loading", duringLoad, phoneResetMigrationHistory(func(context.Context) ([]migrations.Migration, error) { stop(); return original, nil }), context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (PhonePasswordResetMigrationSource{Base: tc.base, Version: 9}).Load(tc.ctx)
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatal("failure lost its classification or returned partial history", err)
			}
		})
	}
}
