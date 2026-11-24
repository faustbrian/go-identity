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

func TestSSOSAMLIDPLogoutMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, source := range []SSOSAMLIDPLogoutMigrationSource{
		{},
		{Schema: "session_store", Version: 0},
		{Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1},
		{Schema: "session_store", Version: migrations.Version(math.MaxUint64)},
	} {
		var invalid identity.InvalidInputError
		if history, err := source.Load(t.Context()); !errors.As(err, &invalid) || history != nil || invalid.Field != "session_sso_saml_idp_logout_migration" {
			t.Fatal("invalid allocation returned IdP-initiated SAML logout history", source, err)
		}
	}
	for _, schema := range []string{"", "public", "identity", "pg_catalog", "information_schema", "SessionStore", "9store", "session_store';--", strings.Repeat("s", 64)} {
		source := SSOSAMLIDPLogoutMigrationSource{Schema: schema, Version: 1}
		var invalid identity.InvalidInputError
		if history, err := source.Load(t.Context()); !errors.As(err, &invalid) || history != nil {
			t.Fatal("invalid schema returned IdP-initiated SAML logout history", schema, err)
		}
	}

	source := SSOSAMLIDPLogoutMigrationSource{Schema: "session_store", Version: 100}
	var invalid identity.InvalidInputError
	if history, err := source.Load(nil); !errors.As(err, &invalid) || history != nil {
		t.Fatal("nil context returned IdP-initiated SAML logout history", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial IdP-initiated SAML logout history", err)
	}
}

func TestSSOSAMLIDPLogoutMigrationReturnsAdditiveForwardOnlyHistory(t *testing.T) {
	for _, source := range []SSOSAMLIDPLogoutMigrationSource{
		{Schema: "session_store", Version: 1},
		{Schema: "session_store", Version: 100},
		{Schema: strings.Repeat("s", 63), Version: migrations.Version(math.MaxInt64)},
	} {
		var migrationSource migrations.Source = source
		history, err := migrationSource.Load(t.Context())
		if err != nil || len(history) != 1 {
			t.Fatal("supported allocation did not return one additive migration", source, err)
		}
		migration := history[0]
		if migration.Version() != source.Version || migration.Name() != "identity_session_sso_saml_idp_logout" {
			t.Fatal("IdP-initiated SAML logout history changed its caller-selected identity", migration.Version(), migration.Name())
		}
		if migration.TransactionMode() != migrations.TransactionModeDefault || !strings.HasPrefix(migration.UpSQL(), "SET LOCAL lock_timeout = '5s';") {
			t.Fatal("IdP-initiated SAML logout migration does not bound lock acquisition to its transaction")
		}
		if migration.DownSQL() != "" {
			t.Fatal("IdP-initiated SAML logout migration supplied destructive rollback history")
		}
		if !strings.Contains(migration.UpSQL(), `CREATE TABLE "`+source.Schema+`".saml_idp_logout_revocations(`) || strings.Contains(migration.UpSQL(), "@") {
			t.Fatal("IdP-initiated SAML logout migration did not select its dedicated schema")
		}
	}
}

func TestSSOSAMLIDPLogoutMigrationRetainsOnlyBoundedCommandEvidence(t *testing.T) {
	history, err := (SSOSAMLIDPLogoutMigrationSource{Schema: "session_store", Version: 100}).Load(t.Context())
	if err != nil || len(history) != 1 {
		t.Fatal("load IdP-initiated SAML logout migration history", err)
	}
	sql := history[0].UpSQL()
	for _, required := range []string{
		`tenant_id "session_store".scope_id NOT NULL`,
		`command_id bytea NOT NULL CHECK(octet_length(command_id)=16)`,
		`purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.sso.saml-slo')`,
		`user_id "session_store".scope_id NOT NULL`,
		`binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32)`,
		`intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32)`,
		`target_count integer NOT NULL CHECK(target_count BETWEEN 1 AND 128)`,
		`PRIMARY KEY(tenant_id,command_id)`,
		`FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)`,
	} {
		if !strings.Contains(sql, required) {
			t.Fatal("generated logout migration lost a bounded command-evidence invariant", required)
		}
	}
	if strings.Count(sql, "CREATE TABLE ") != 1 {
		t.Fatal("logout migration must create only its owned evidence table")
	}
	for _, forbidden := range []string{
		"ALTER TABLE", "CREATE INDEX", "DROP ", "UPDATE ", "DELETE ", "INSERT ",
		"IF NOT EXISTS", "session_id", "session_revocations", "REFERENCES \"session_store\"", "token", "timestamp", "created_at", "expires_at",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatal("logout migration changed existing storage or retained session payload", forbidden)
		}
	}
}
