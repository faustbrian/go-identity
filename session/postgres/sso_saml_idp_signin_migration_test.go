package postgres

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSSOSAMLIDPSigninMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, source := range []SSOSAMLIDPSigninMigrationSource{
		{},
		{Schema: "session_store", Version: 0, ValidationVersion: 2},
		{Schema: "session_store", Version: 1, ValidationVersion: 0},
		{Schema: "session_store", Version: 2, ValidationVersion: 2},
		{Schema: "session_store", Version: 2, ValidationVersion: 1},
		{Schema: "session_store", Version: migrations.Version(math.MaxInt64), ValidationVersion: migrations.Version(math.MaxInt64) + 1},
		{Schema: "session_store", Version: 1, ValidationVersion: migrations.Version(math.MaxUint64)},
		{Schema: "session_store", Version: migrations.Version(math.MaxUint64), ValidationVersion: 2},
	} {
		var invalid identity.InvalidInputError
		if history, err := source.Load(t.Context()); !errors.As(err, &invalid) || history != nil || invalid.Field != "session_sso_saml_idp_signin_migration" {
			t.Fatal("invalid version pair returned IdP-initiated SAML issuance history", source, err)
		}
	}
	for _, schema := range []string{"", "public", "identity", "pg_catalog", "information_schema", "SessionStore", "9store", "session_store';--", strings.Repeat("s", 64)} {
		source := SSOSAMLIDPSigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2}
		var invalid identity.InvalidInputError
		if history, err := source.Load(t.Context()); !errors.As(err, &invalid) || history != nil {
			t.Fatal("invalid schema returned IdP-initiated SAML issuance history", schema, err)
		}
	}

	source := SSOSAMLIDPSigninMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101}
	var invalid identity.InvalidInputError
	if history, err := source.Load(nil); !errors.As(err, &invalid) || history != nil {
		t.Fatal("nil context returned IdP-initiated SAML issuance history", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial IdP-initiated SAML issuance history", err)
	}
}

func TestSSOSAMLIDPSigninMigrationReturnsOrderedForwardOnlyHistory(t *testing.T) {
	for _, source := range []SSOSAMLIDPSigninMigrationSource{
		{Schema: "session_store", Version: 1, ValidationVersion: 2},
		{Schema: "session_store", Version: 100, ValidationVersion: 101},
		{Schema: strings.Repeat("s", 63), Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64)},
	} {
		history, err := source.Load(t.Context())
		if err != nil || len(history) != 2 {
			t.Fatal("supported version pair did not return separate expansion and validation", source, err)
		}
		versions := []migrations.Version{source.Version, source.ValidationVersion}
		names := []string{"identity_session_sso_saml_idp_expand", "identity_session_sso_saml_idp_validate"}
		for i, migration := range history {
			if migration.Version() != versions[i] || migration.Name() != names[i] {
				t.Fatal("IdP-initiated SAML issuance history changed its caller-selected identity", i, migration.Version(), migration.Name())
			}
			if migration.TransactionMode() != migrations.TransactionModeDefault || !strings.HasPrefix(migration.UpSQL(), "SET LOCAL lock_timeout = '5s';") {
				t.Fatal("IdP-initiated SAML issuance migration does not bound lock acquisition to its transaction", i)
			}
			if migration.DownSQL() != "" {
				t.Fatal("IdP-initiated SAML issuance migration supplied destructive rollback history", i)
			}
		}
	}
}

func TestSSOSAMLIDPSigninMigrationSelectsExactValidatedSAMLAuthority(t *testing.T) {
	history, err := (SSOSAMLIDPSigninMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101}).Load(t.Context())
	if err != nil || len(history) != 2 {
		t.Fatal("load IdP-initiated SAML issuance migration history", err)
	}
	expansion := history[0].UpSQL()
	for _, required := range []string{
		`LOCK TABLE "session_store".session_issuances IN ACCESS EXCLUSIVE MODE;`,
		`WHERE c.conrelid='"session_store".session_issuances'::pg_catalog.regclass`,
		`AND c.conname='session_issuances_purpose_sso_saml_v1' AND c.contype='c' AND c.convalidated`,
		`AND c.conkey=ARRAY[a.attnum]`,
		`IF previous_predicate IS NULL THEN`,
		`RAISE EXCEPTION USING ERRCODE='55000'`,
		`ADD CONSTRAINT session_issuances_purpose_sso_saml_idp_v1 CHECK ((%s) OR purpose=%L) NOT VALID`,
		`'session_store',previous_predicate,'identity.sso.saml-idp-init'`,
		`DROP CONSTRAINT %I','session_store','session_issuances_purpose_sso_saml_v1'`,
	} {
		if !strings.Contains(expansion, required) {
			t.Fatal("generated expansion lost the selected predecessor or exact IdP-initiated SAML allowance", required)
		}
	}
	for _, forbidden := range []string{
		"@", "session_issuances_purpose_sso_oidc_v1", "session_issuances_purpose_sso_oauth2_v1",
		"identity.sso.oidc-callback", "identity.sso.saml-acs", "VALIDATE CONSTRAINT",
		"UPDATE ", "DELETE ", "INSERT ", "CREATE TABLE", "DROP TABLE", "ADD COLUMN", "DROP COLUMN",
	} {
		if strings.Contains(expansion, forbidden) {
			t.Fatal("generated expansion retained a template authority or changed more than the purpose constraint", forbidden)
		}
	}
	const validation = `SET LOCAL lock_timeout = '5s';
ALTER TABLE "session_store".session_issuances VALIDATE CONSTRAINT session_issuances_purpose_sso_saml_idp_v1;`
	if history[1].UpSQL() != validation {
		t.Fatal("IdP-initiated SAML issuance constraint validation was not isolated in its own migration")
	}
}

func TestSSOSAMLIDPSigninMigrationDoesNotChangeSPInitiatedHistory(t *testing.T) {
	history, err := (SSOSAMLSigninMigrationSource{Schema: "session_store", Version: 98, ValidationVersion: 99}).Load(t.Context())
	if err != nil || len(history) != 2 {
		t.Fatal("load existing SP-initiated SAML issuance migration history", err)
	}
	for _, migration := range history {
		if strings.Contains(migration.UpSQL(), "identity.sso.saml-idp-init") || strings.Contains(migration.UpSQL(), "session_issuances_purpose_sso_saml_idp_v1") {
			t.Fatal("existing SP-initiated SAML history admitted IdP-initiated issuance without opting in")
		}
	}
	if !strings.Contains(history[0].UpSQL(), "'session_store',previous_predicate,'identity.sso.saml-acs'") ||
		!strings.Contains(history[0].UpSQL(), "AND c.conname='session_issuances_purpose_sso_oauth2_v1' AND c.contype='c' AND c.convalidated") {
		t.Fatal("existing SP-initiated SAML history changed its purpose or validated OAuth2 predecessor")
	}
}
