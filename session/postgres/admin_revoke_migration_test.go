package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestAdminRevokeMigrationSeparatesExpansionAndValidation(t *testing.T) {
	for _, predecessor := range []string{
		"session_revocations_purpose_check",
		"session_revocations_purpose_oidc_v1",
		ssoOIDCLogoutRevocationConstraint,
		ssoSAMLLogoutStartRevocationConstraint,
	} {
		t.Run(predecessor, func(t *testing.T) {
			source := AdminRevokeMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101, PreviousConstraint: predecessor}
			var migrationSource migrations.Source = source
			history, err := migrationSource.Load(t.Context())
			if err != nil || len(history) != 2 {
				t.Fatal("supported predecessor did not produce separate expansion and validation", err)
			}
			for i, name := range []string{"identity_session_admin_revoke_expand", "identity_session_admin_revoke_validate"} {
				migration := history[i]
				if migration.Version() != migrations.Version(100+i) || migration.Name() != name {
					t.Fatal("admin revocation changed the caller-allocated migration identity", i, migration.Version(), migration.Name())
				}
				if migration.TransactionMode() != migrations.TransactionModeDefault || !strings.HasPrefix(migration.UpSQL(), "SET LOCAL lock_timeout = '5s';") {
					t.Fatal("admin revocation does not bound lock acquisition to the migration transaction", i)
				}
				if migration.DownSQL() != "" {
					t.Fatal("admin revocation supplied a destructive downgrade", i)
				}
				if strings.Contains(migration.UpSQL(), "@") {
					t.Fatal("unresolved SQL template placeholder", i)
				}
			}

			expansion := history[0].UpSQL()
			if strings.Contains(expansion, "VALIDATE CONSTRAINT") {
				t.Fatal("validation scan shares the metadata-lock transaction")
			}
			validation := "SET LOCAL lock_timeout = '5s';\nALTER TABLE \"session_store\".session_revocations VALIDATE CONSTRAINT " + predecessor + ";"
			if history[1].UpSQL() != validation {
				t.Fatal("separate validation did not target the exact retained predecessor name", history[1].UpSQL())
			}
		})
	}
}

func TestAdminRevokeMigrationPreservesValidatedPurposePredicateAndName(t *testing.T) {
	for _, predecessor := range []string{
		"session_revocations_purpose_check",
		"session_revocations_purpose_oidc_v1",
		ssoOIDCLogoutRevocationConstraint,
		ssoSAMLLogoutStartRevocationConstraint,
	} {
		t.Run(predecessor, func(t *testing.T) {
			history, err := (AdminRevokeMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101, PreviousConstraint: predecessor}).Load(t.Context())
			if err != nil || len(history) != 2 {
				t.Fatal("load admin revocation migration", err)
			}
			expansion := history[0].UpSQL()
			for _, required := range []string{
				`LOCK TABLE "session_store".session_revocations IN ACCESS EXCLUSIVE MODE;`,
				"pg_catalog.pg_get_expr(c.conbin,c.conrelid)",
				"FROM pg_catalog.pg_constraint c",
				"a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped",
				`c.conrelid='"session_store".session_revocations'::pg_catalog.regclass`,
				"c.conname='" + predecessor + "' AND c.contype='c' AND c.convalidated",
				"c.conkey=ARRAY[a.attnum]",
				"IF previous_predicate IS NULL THEN",
				"RAISE EXCEPTION USING ERRCODE='55000'",
				"DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((%s) OR purpose=%L) NOT VALID",
				"'session_store','" + predecessor + "','" + predecessor + "',previous_predicate,'identity.admin.session-revoke'",
			} {
				if !strings.Contains(expansion, required) {
					t.Fatal("admin revocation lost its fail-closed, predicate-preserving expansion contract", required)
				}
			}
			lockAt := strings.Index(expansion, "LOCK TABLE ")
			catalogAt := strings.Index(expansion, "SELECT pg_catalog.pg_get_expr")
			replaceAt := strings.Index(expansion, "EXECUTE pg_catalog.format")
			if lockAt >= catalogAt || catalogAt >= replaceAt {
				t.Fatal("catalog validation and replacement are not protected by the same metadata lock")
			}
			for _, forbidden := range []string{"CREATE TABLE", "DROP TABLE", "TRUNCATE ", "UPDATE ", "DELETE ", "INSERT ", "CASCADE", "IF EXISTS", "IF NOT EXISTS"} {
				if strings.Contains(expansion, forbidden) {
					t.Fatal("admin revocation rewrites rows, creates another journal, or hides a predecessor mismatch", forbidden)
				}
			}
		})
	}
}

func TestAdminRevokeMigrationRejectsInvalidAllocationAndPredecessor(t *testing.T) {
	valid := AdminRevokeMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101, PreviousConstraint: "session_revocations_purpose_check"}
	tests := map[string]AdminRevokeMigrationSource{"zero source": {}}
	for _, schema := range []string{"", "public", "identity", "pg_catalog", "information_schema", "SessionStore", "9store", "session_store';--", strings.Repeat("s", 64)} {
		source := valid
		source.Schema = schema
		tests["schema "+schema] = source
	}
	for _, predecessor := range []string{"foreign_check", "session_revocations_purpose_admin_v1", "session_revocations_purpose_check';--"} {
		source := valid
		source.PreviousConstraint = predecessor
		tests["predecessor "+predecessor] = source
	}
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		source := valid
		source.Version = version
		tests["expansion "+strconv.FormatUint(uint64(version), 10)] = source
	}
	for _, version := range []migrations.Version{0, 99, 100, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		source := valid
		source.ValidationVersion = version
		tests["validation "+strconv.FormatUint(uint64(version), 10)] = source
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			var invalid identity.InvalidInputError
			if history, err := source.Load(t.Context()); !errors.As(err, &invalid) || history != nil || invalid.Field != "session_admin_revoke_migration" {
				t.Fatal("invalid history did not fail before producing migrations", err)
			}
		})
	}

	var invalid identity.InvalidInputError
	if history, err := valid.Load(nil); !errors.As(err, &invalid) || history != nil {
		t.Fatal("nil context produced migrations", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := valid.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancelled context produced migrations or lost its cause", err)
	}
}

func TestAdminRevokeMigrationAcceptsMaximumSupportedAllocation(t *testing.T) {
	source := AdminRevokeMigrationSource{
		Schema: strings.Repeat("s", 63), Version: migrations.Version(math.MaxInt64) - 1,
		ValidationVersion: migrations.Version(math.MaxInt64), PreviousConstraint: "session_revocations_purpose_check",
	}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != 2 || history[0].Version() != source.Version || history[1].Version() != source.ValidationVersion {
		t.Fatal("valid maximum schema/version allocation rejected", err)
	}
}

func TestAdminRevokeMigrationEmptySelectorPreservesStableHistoryAcrossProfiles(t *testing.T) {
	source := AdminRevokeMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != 2 {
		t.Fatal("empty selector did not return catalog-selected expansion and validation", err)
	}
	again, err := source.Load(t.Context())
	if err != nil || len(again) != 2 {
		t.Fatal("reload stable catalog-selected history", err)
	}
	for i, name := range []string{"identity_session_admin_revoke_expand", "identity_session_admin_revoke_validate"} {
		migration := history[i]
		if migration.Version() != migrations.Version(100+i) || migration.Name() != name || migration.TransactionMode() != migrations.TransactionModeDefault || migration.DownSQL() != "" {
			t.Fatal("catalog-selected history changed phase identity or supplied a downgrade", i)
		}
		if migration.UpSQL() != again[i].UpSQL() || migration.Checksum() != again[i].Checksum() {
			t.Fatal("catalog-selected history is not stable between loads", i)
		}
		if !strings.HasPrefix(migration.UpSQL(), "SET LOCAL lock_timeout = '5s';") || strings.Contains(migration.UpSQL(), "@") {
			t.Fatal("catalog-selected history has unbounded locking or unresolved placeholders", i)
		}
		for _, required := range []string{
			"SELECT count(*), min(c.conname::text) INTO predecessor_count, previous_constraint",
			"c.conname IN ('session_revocations_purpose_check','session_revocations_purpose_oidc_v1','session_revocations_purpose_sso_oidc_v1','session_revocations_purpose_sso_saml_v1')",
			"IF predecessor_count<>1 THEN",
			"c.conname=previous_constraint AND c.contype='c'",
			"a.attname='purpose' AND NOT a.attisdropped",
			"c.conkey=ARRAY[a.attnum]",
			"RAISE EXCEPTION USING ERRCODE='55000'",
		} {
			if !strings.Contains(migration.UpSQL(), required) {
				t.Fatal("catalog-selected phase does not reject absent, ambiguous, or malformed known guards", i, required)
			}
		}
	}

	expansion := history[0].UpSQL()
	for _, required := range []string{
		`LOCK TABLE "session_store".session_revocations IN ACCESS EXCLUSIVE MODE;`,
		"c.conname=previous_constraint AND c.contype='c' AND c.convalidated",
		"IF previous_predicate IS NULL THEN",
		"DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((%s) OR purpose=%L) NOT VALID",
		"'session_store',previous_constraint,previous_constraint,previous_predicate,'identity.admin.session-revoke'",
	} {
		if !strings.Contains(expansion, required) {
			t.Fatal("catalog-selected expansion does not preserve the sole validated guard", required)
		}
	}
	if strings.Contains(expansion, "VALIDATE CONSTRAINT") {
		t.Fatal("catalog-selected validation shares the exclusive metadata-lock phase")
	}

	validation := history[1].UpSQL()
	for _, required := range []string{
		`LOCK TABLE "session_store".session_revocations IN SHARE UPDATE EXCLUSIVE MODE;`,
		"previous_predicate IS NULL OR pg_catalog.strpos(previous_predicate,pg_catalog.quote_literal('identity.admin.session-revoke'))=0",
		"ALTER TABLE %I.session_revocations VALIDATE CONSTRAINT %I",
		"'session_store',previous_constraint",
	} {
		if !strings.Contains(validation, required) {
			t.Fatal("catalog-selected validation does not require and validate the exact administrative guard", required)
		}
	}
	for _, forbidden := range []string{"ACCESS EXCLUSIVE MODE", "DROP CONSTRAINT", "ADD CONSTRAINT", "AND c.convalidated"} {
		if strings.Contains(validation, forbidden) {
			t.Fatal("validation rewrites the guard, blocks writers, or rejects its NOT VALID predecessor", forbidden)
		}
	}
}
