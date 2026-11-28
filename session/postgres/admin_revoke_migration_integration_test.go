//go:build integration

package postgres

import (
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAdminRevokeJournalExpansionPreservesExistingLogoutPurposes(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const admin = "identity.admin.session-revoke"
	const self = "identity.session.revoke-one"
	const oidc = "identity.sso.oidc-logout"
	const saml = "identity.sso.saml-logout-start"
	for _, fixture := range []struct {
		schema         string
		adminAfterSAML bool
	}{
		{schema: "admin_revoke_first"},
		{schema: "admin_revoke_after", adminAfterSAML: true},
	} {
		t.Run(fixture.schema, func(t *testing.T) {
			schema := fixture.schema
			if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`;
CREATE TABLE `+schema+`.session_revocations(marker bigint PRIMARY KEY,purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.revoke-one'));
INSERT INTO `+schema+`.session_revocations SELECT n,'identity.session.revoke-one' FROM generate_series(1,2000) AS n`); err != nil {
				t.Fatal(err)
			}
			apply := func(steps []migrations.Migration) {
				t.Helper()
				for _, step := range steps {
					if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
						t.Fatal("journal migration failed", step.Version(), err)
					}
				}
			}
			insert := func(marker int, purpose string) error {
				_, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_revocations(marker,purpose) VALUES($1,$2)`, marker, purpose)
				return err
			}
			reject := func(purpose string) {
				t.Helper()
				var pgErr *pgconn.PgError
				if err := insert(-1, purpose); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
					t.Fatal("unknown purpose admitted", purpose, err)
				}
			}
			adminSteps, err := (AdminRevokeMigrationSource{Schema: schema, Version: 60, ValidationVersion: 61}).Load(ctx)
			if err != nil || len(adminSteps) != 2 {
				t.Fatal("invalid admin history", err)
			}
			enterprise := func() {
				t.Helper()
				oidcSteps, err := (SSOOIDCLogoutMigrationSource{Schema: schema, Version: 62, ValidationVersion: 63, PreviousConstraint: "session_revocations_purpose_check"}).Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				apply(oidcSteps)
				samlSteps, err := (SSOSAMLLogoutStartMigrationSource{Schema: schema, Version: 64, ValidationVersion: 65, PreviousConstraint: ssoOIDCLogoutRevocationConstraint}).Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				apply(samlSteps)
			}
			reject(admin)
			current := "session_revocations_purpose_check"
			if fixture.adminAfterSAML {
				enterprise()
				current = ssoSAMLLogoutStartRevocationConstraint
				reject(admin)
			}
			apply(adminSteps[:1])
			var validated bool
			constraint := `SELECT convalidated FROM pg_catalog.pg_constraint WHERE conrelid=$1::regclass AND conname=$2`
			if err := pool.Raw().QueryRow(ctx, constraint, schema+".session_revocations", current).Scan(&validated); err != nil || validated {
				t.Fatal("expansion unexpectedly validated retained history", err)
			}
			if err := insert(2001, admin); err != nil {
				t.Fatal("new exact purpose denied after expansion", err)
			}
			reject("identity.admin.session-revoke-all")
			apply(adminSteps[1:])
			if err := pool.Raw().QueryRow(ctx, constraint, schema+".session_revocations", current).Scan(&validated); err != nil || !validated {
				t.Fatal("separate validation did not mark the existing guard", err)
			}
			if !fixture.adminAfterSAML {
				enterprise()
			}
			for i, purpose := range []string{admin, self, oidc, saml, "identity.oauth-server.end-session"} {
				if err := insert(2002+i, purpose); err != nil {
					t.Fatal("composed purpose was not retained", purpose, err)
				}
			}
			reject("identity.admin.session-revoke-all")
			var kept int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_revocations WHERE marker<=2000 AND purpose=$1`, self).Scan(&kept); err != nil || kept != 2000 {
				t.Fatal("existing revocation evidence was changed", kept, err)
			}
		})
	}
}
