//go:build integration

package mfapostgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// These checks use native kernel and MFA tables in an owned database. They
// prove provenance coexistence, not callback authentication or JIT admission.
func TestSSOOIDCJITFactorMigrationPostgres(t *testing.T) {
	for _, profile := range []struct {
		constraint string
		source     migrations.Source
		purposes   []string
	}{
		{"factor_authorities_initialized_purpose_check", MigrationSource{Version: 1}, []string{"identity.password.signup"}},
		{"factor_authorities_initialized_purpose_v2", MagicLinkSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, []string{"identity.password.signup", "identity.magic-link.consume"}},
		{"factor_authorities_initialized_purpose_v3", UsernameSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, []string{"identity.password.signup", "identity.magic-link.consume", "identity.username.signup"}},
		{"factor_authorities_initialized_purpose_v4", PasskeySignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, []string{"identity.password.signup", "identity.magic-link.consume", "identity.username.signup", "identity.passkey.register-verify"}},
	} {
		t.Run(profile.constraint, func(t *testing.T) {
			fixture := newSSOOIDCJITFactorMigrationFixture(t, profile.source)
			for _, purpose := range profile.purposes {
				fixture.insertLegacy(t, purpose, "1", 0)
				fixture.insertLegacy(t, purpose, "18446744073709551615", 64)
			}
			before := fixture.rows(t)
			originalConstraints := fixture.constraints(t)
			prior, err := profile.source.Load(fixture.ctx)
			if err != nil {
				t.Fatal(err)
			}
			source := SSOOIDCJITFactorMigrationSource{Base: profile.source, Version: 7, ValidationVersion: 8, IndexVersion: 9}
			history, err := source.Load(fixture.ctx)
			if err != nil {
				t.Fatal(err)
			}
			for i, step := range history[len(prior):] {
				fixture.apply(t, step)
				if !reflect.DeepEqual(fixture.rows(t), before) {
					t.Fatal("JIT migration rewrote existing factor generations, enrollment or provenance")
				}
				currentConstraints := fixture.constraints(t)
				for name, old := range originalConstraints {
					if currentConstraints[name] != old {
						t.Fatal("JIT migration replaced an existing CHECK, foreign key or unique constraint", name)
					}
				}
				fixture.requireValidation(t, i > 0)
				var indexPresent bool
				if err := fixture.pool.Raw().QueryRow(fixture.ctx, `SELECT to_regclass('identity_mfa.factor_authorities_sso_oidc_command_unique') IS NOT NULL`).Scan(&indexPresent); err != nil || indexPresent != (i == 2) {
					t.Fatal("concurrent uniqueness did not remain a separate final step", err)
				}
			}
			var validUnique bool
			if err := fixture.pool.Raw().QueryRow(fixture.ctx, `SELECT indisvalid AND indisready AND indisunique FROM pg_index WHERE indexrelid='identity_mfa.factor_authorities_sso_oidc_command_unique'::regclass`).Scan(&validUnique); err != nil || !validUnique {
				t.Fatal("concurrent JIT unique index is not usable", err)
			}
			for _, purpose := range profile.purposes {
				fixture.insertLegacy(t, purpose, "1", 0)
			}
			_, originalCommand, err := fixture.insertProvenance(t, "identity.sso.oidc-callback", nil, "identity.sso.oidc-callback")
			if err != nil {
				t.Fatal("separate SSO provenance rejected native initialization", err)
			}
			for _, invalid := range []struct {
				name, commandPurpose string
				legacy, sso          any
				code, constraint     string
			}{
				{"both", "identity.sso.oidc-callback", "identity.password.signup", "identity.sso.oidc-callback", "23514", "factor_authorities_initialization_provenance_v1"},
				{"neither", "identity.sso.oidc-callback", nil, nil, "23514", "factor_authorities_initialization_provenance_v1"},
				{"unsupported-sso", "identity.unselected", nil, "identity.unselected", "23514", "factor_authorities_initialization_provenance_v1"},
				{"wrong-command", "identity.password.signup", nil, "identity.sso.oidc-callback", "23503", "factor_authorities_sso_oidc_command_fkey"},
				{"unsupported-legacy", "identity.unselected", "identity.unselected", nil, "23514", profile.constraint},
				{"misfiled-callback", "identity.sso.oidc-callback", "identity.sso.oidc-callback", nil, "23514", profile.constraint},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					_, _, err := fixture.insertProvenance(t, invalid.commandPurpose, invalid.legacy, invalid.sso)
					requireSSOOIDCJITFactorPostgresError(t, err, invalid.code, invalid.constraint)
				})
			}
			duplicateUser, _ := fixture.prepare(t, "identity.sso.oidc-callback")
			_, err = fixture.pool.Raw().Exec(fixture.ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,sso_oidc_initialized_purpose) VALUES('tenant-a',$1,1,0,$2,'identity.sso.oidc-callback')`, duplicateUser, originalCommand)
			requireSSOOIDCJITFactorPostgresError(t, err, "23505", "factor_authorities_sso_oidc_command_unique")
		})
	}
}

func TestSSOOIDCJITFactorLegacySignupCoexistencePostgres(t *testing.T) {
	base := MigrationSource{Version: 1}
	fixture := newSSOOIDCJITFactorMigrationFixture(t, base)
	fixture.insertLegacy(t, "identity.password.signup", "6", 1)
	jit := SSOOIDCJITFactorMigrationSource{Base: base, Version: 2, ValidationVersion: 3, IndexVersion: 4}
	history, err := jit.Load(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history[1:] {
		fixture.apply(t, step)
	}
	_, _, err = fixture.insertProvenance(t, "identity.sso.oidc-callback", nil, "identity.sso.oidc-callback")
	if err != nil {
		t.Fatal("populate real JIT before optional signup migrations", err)
	}
	magic := MagicLinkSignupMigrationSource{Base: jit, Version: 5}
	username := UsernameSignupMigrationSource{Base: magic, Version: 6}
	passkey := PasskeySignupMigrationSource{Base: username, Version: 7}
	for _, later := range []struct {
		source     migrations.Source
		purpose    string
		constraint string
	}{
		{magic, "identity.magic-link.consume", "factor_authorities_initialized_purpose_v2"},
		{username, "identity.username.signup", "factor_authorities_initialized_purpose_v3"},
		{passkey, "identity.passkey.register-verify", "factor_authorities_initialized_purpose_v4"},
	} {
		before := fixture.rows(t)
		steps, err := later.source.Load(fixture.ctx)
		if err != nil {
			t.Fatal(err)
		}
		fixture.apply(t, steps[len(steps)-1])
		if !reflect.DeepEqual(fixture.rows(t), before) {
			t.Fatal("untouched optional signup migration changed legacy or JIT provenance")
		}
		if _, exists := fixture.constraints(t)[later.constraint]; !exists {
			t.Fatal("actual optional signup predecessor name was not retained")
		}
		fixture.insertLegacy(t, later.purpose, "1", 0)
		if _, _, err := fixture.insertProvenance(t, "identity.sso.oidc-callback", nil, "identity.sso.oidc-callback"); err != nil {
			t.Fatal("later optional signup migration rejected independent JIT provenance", err)
		}
		_, _, err = fixture.insertProvenance(t, "identity.unselected", "identity.unselected", nil)
		requireSSOOIDCJITFactorPostgresError(t, err, "23514", later.constraint)
		fixture.requireValidation(t, true)
	}
}

type ssoOIDCJITFactorMigrationFixture struct {
	ctx      context.Context
	pool     *database.Pool
	sequence byte
}

func newSSOOIDCJITFactorMigrationFixture(t *testing.T, source migrations.Source) *ssoOIDCJITFactorMigrationFixture {
	t.Helper()
	ctx, pool, _ := newOAuthSigninFactorStore(t)
	// Replace only the fixture's empty authority install. Its real kernel
	// users and command foreign keys remain installed throughout.
	if _, err := pool.Raw().Exec(ctx, `DROP TABLE identity_mfa.factor_authorities; DROP SCHEMA identity_mfa`); err != nil {
		t.Fatal("replace empty fixture authority with actual native history", err)
	}
	fixture := &ssoOIDCJITFactorMigrationFixture{ctx: ctx, pool: pool}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		fixture.apply(t, step)
	}
	return fixture
}

func (f *ssoOIDCJITFactorMigrationFixture) apply(t *testing.T, step migrations.Migration) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
		t.Fatal("apply actual native migration", step.Version(), err)
	}
}

func (f *ssoOIDCJITFactorMigrationFixture) prepare(t *testing.T, purpose string) (string, []byte) {
	t.Helper()
	f.sequence++
	user := fmt.Sprintf("jit-migration-%d", f.sequence)
	command := make([]byte, 16)
	command[0], command[15] = 0x4a, f.sequence
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a',$1,'active',1)`, user); err != nil {
		t.Fatal("insert actual initialization user", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, command, purpose); err != nil {
		t.Fatal("insert original command claim", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, command, purpose); err != nil {
		t.Fatal("insert original initialization command", err)
	}
	return user, command
}

func (f *ssoOIDCJITFactorMigrationFixture) insertLegacy(t *testing.T, purpose, version string, active int32) {
	t.Helper()
	user, command := f.prepare(t, purpose)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES('tenant-a',$1,$2::numeric,$3,$4,$5)`, user, version, active, command, purpose); err != nil {
		t.Fatal("native legacy factor initialization", err)
	}
}

func (f *ssoOIDCJITFactorMigrationFixture) insertProvenance(t *testing.T, commandPurpose string, legacyPurpose, ssoPurpose any) (string, []byte, error) {
	t.Helper()
	user, command := f.prepare(t, commandPurpose)
	_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose,sso_oidc_initialized_purpose) VALUES('tenant-a',$1,1,0,$2,$3,$4)`, user, command, legacyPurpose, ssoPurpose)
	return user, command, err
}

func (f *ssoOIDCJITFactorMigrationFixture) rows(t *testing.T) []string {
	t.Helper()
	// Normalize the not-yet-added nullable column to JSON null so the same
	// full-row comparison works before and after metadata-only expansion.
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT (to_jsonb(a)||jsonb_build_object('sso_oidc_initialized_purpose',to_jsonb(a)->'sso_oidc_initialized_purpose'))::text FROM identity_mfa.factor_authorities a ORDER BY tenant_id,user_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

func (f *ssoOIDCJITFactorMigrationFixture) constraints(t *testing.T) map[string]string {
	t.Helper()
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT conname,oid::text||':'||convalidated::text||':'||pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='identity_mfa.factor_authorities'::regclass AND contype<>'n'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	values := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			t.Fatal(err)
		}
		values[name] = value
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

func (f *ssoOIDCJITFactorMigrationFixture) requireValidation(t *testing.T, validated bool) {
	t.Helper()
	var total, valid int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE convalidated) FROM pg_constraint WHERE conrelid='identity_mfa.factor_authorities'::regclass AND conname IN('factor_authorities_initialization_provenance_v1','factor_authorities_sso_oidc_command_fkey')`).Scan(&total, &valid); err != nil || total != 2 || validated && valid != 2 || !validated && valid != 0 {
		t.Fatal("SSO provenance constraints lost separate expansion/validation state", err)
	}
}

func requireSSOOIDCJITFactorPostgresError(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code || pg.ConstraintName != constraint {
		t.Fatal("expected exact native provenance constraint rejection", err)
	}
}
