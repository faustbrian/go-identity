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

func TestAdminRevokeAllMigrationSeparatesEvidenceAndOnlineIndex(t *testing.T) {
	source := AdminRevokeAllMigrationSource{Schema: "session_store", Version: 100, IndexVersion: 102}
	var migrationSource migrations.Source = source
	history, err := migrationSource.Load(t.Context())
	if err != nil || len(history) != 2 {
		t.Fatal("administrative revoke-all history must contain evidence and a separate online index", err)
	}
	for i, want := range []struct {
		version migrations.Version
		name    string
		mode    migrations.TransactionMode
	}{
		{100, "identity_session_admin_set_revocations", migrations.TransactionModeDefault},
		{102, "identity_session_admin_active_subject_order", migrations.TransactionModeNone},
	} {
		step := history[i]
		if step.Version() != want.version || step.Name() != want.name || step.TransactionMode() != want.mode || step.DownSQL() != "" {
			t.Fatal("migration changed the allocated identity, execution mode, or forward-only contract", i)
		}
		if strings.Contains(step.UpSQL(), "@") || strings.Contains(step.UpSQL(), "IF NOT EXISTS") {
			t.Fatal("migration contains an unresolved template or silently adopts existing objects", i)
		}
	}
	const indexSQL = `CREATE INDEX CONCURRENTLY session_admin_active_subject_order ON "session_store".sessions(tenant_id,user_id,session_id) WHERE state='active';`
	if history[1].UpSQL() != indexSQL {
		t.Fatal("online index does not exclusively own its administrative active-subject order", history[1].UpSQL())
	}
	if strings.Contains(history[0].UpSQL(), "CREATE INDEX") {
		t.Fatal("live-session index build shares the evidence-table transaction")
	}

	again, err := source.Load(t.Context())
	if err != nil || len(again) != 2 || again[0] != history[0] || again[1] != history[1] {
		t.Fatal("migration source did not return stable immutable history", err)
	}
	history[0] = migrations.Migration{}
	reloaded, err := source.Load(t.Context())
	if err != nil || len(reloaded) != 2 || reloaded[0] != again[0] {
		t.Fatal("migration history aliases caller-owned storage", err)
	}
}

func TestAdminRevokeAllMigrationOwnsOnlyCanonicalCommandEvidence(t *testing.T) {
	history, err := (AdminRevokeAllMigrationSource{Schema: "session_store", Version: 100, IndexVersion: 101}).Load(t.Context())
	if err != nil || len(history) != 2 {
		t.Fatal("load administrative revoke-all evidence", err)
	}
	sql := history[0].UpSQL()
	for _, required := range []string{
		`CREATE TABLE "session_store".admin_set_revocations(`,
		`tenant_id "session_store".scope_id NOT NULL`,
		`command_id bytea NOT NULL CHECK(octet_length(command_id)=16)`,
		`purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.admin.session-revoke-all')`,
		`user_id "session_store".scope_id NOT NULL`,
		`before_version numeric NOT NULL CHECK(before_version>=0 AND before_version<=18446744073709551614 AND scale(before_version)=0)`,
		`subject_version "session_store".version NOT NULL`,
		`revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 0 AND 100000)`,
		`binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32)`,
		`result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32)`,
		`PRIMARY KEY(tenant_id,command_id)`,
		`UNIQUE(tenant_id,user_id,subject_version)`,
		`FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)`,
		`CHECK(subject_version=before_version+1)`,
	} {
		if !strings.Contains(sql, required) {
			t.Fatal("administrative evidence lost its canonical scope, version, count, digest, or command binding", required)
		}
	}
	if strings.Count(sql, "CREATE TABLE") != 1 || strings.Count(sql, "FOREIGN KEY") != 1 || strings.Count(sql, "REFERENCES ") != 1 {
		t.Fatal("administrative evidence introduces another owner or a prunable-payload dependency")
	}
	for _, forbidden := range []string{"ALTER TABLE", "DROP ", "TRUNCATE ", "UPDATE ", "DELETE ", "INSERT ", "CASCADE", "CREATE SCHEMA", ".set_revocations", ".session_revocations", "record jsonb", "source_id", "include_current"} {
		if strings.Contains(sql, forbidden) {
			t.Fatal("administrative evidence changes existing authority or retains session payload", forbidden)
		}
	}
}

func TestAdminRevokeAllMigrationOfflineSelectionChangesOnlyUninstalledIndex(t *testing.T) {
	source := AdminRevokeAllMigrationSource{Schema: "session_store", Version: 100, IndexVersion: 101}
	native, err := source.Load(t.Context())
	if err != nil || len(native) != 2 {
		t.Fatal("load online history", err)
	}
	offline, err := source.LoadOffline(t.Context())
	if err != nil || len(offline) != 2 || offline[0] != native[0] {
		t.Fatal("offline selection changed evidence history", err)
	}
	const sql = "SET LOCAL lock_timeout = '5s';\nCREATE INDEX session_admin_active_subject_order ON \"session_store\".sessions(tenant_id,user_id,session_id) WHERE state='active';"
	index, err := migrations.NewMigration(native[1].Version(), native[1].Name(), migrations.TransactionModeDefault, sql, "")
	if err != nil || offline[1] != index || offline[1].Checksum() == native[1].Checksum() {
		t.Fatal("offline selection did not allocate distinct transactional index history", err)
	}
	again, err := source.Load(t.Context())
	if err != nil || len(again) != 2 || again[0] != native[0] || again[1] != native[1] {
		t.Fatal("offline selection changed subsequent online history", err)
	}
}

func TestAdminRevokeAllMigrationRejectsInvalidInputBeforeHistory(t *testing.T) {
	valid := AdminRevokeAllMigrationSource{Schema: "session_store", Version: 100, IndexVersion: 101}
	cases := map[string]AdminRevokeAllMigrationSource{"zero": {}}
	for _, schema := range []string{"", "public", "identity", "pg_catalog", "information_schema", "SessionStore", "9store", "session_store';--", strings.Repeat("s", 64)} {
		source := valid
		source.Schema = schema
		cases["schema "+schema] = source
	}
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		source := valid
		source.Version = version
		cases["table "+strconv.FormatUint(uint64(version), 10)] = source
	}
	for _, version := range []migrations.Version{0, 99, 100, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		source := valid
		source.IndexVersion = version
		cases["index "+strconv.FormatUint(uint64(version), 10)] = source
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			for _, load := range []func(context.Context) ([]migrations.Migration, error){source.Load, source.LoadOffline} {
				var invalid identity.InvalidInputError
				if history, err := load(t.Context()); !errors.As(err, &invalid) || invalid.Field != "session_admin_revoke_all_migration" || history != nil {
					t.Fatal("invalid allocation produced history or lost its classified error", err)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, load := range []func(context.Context) ([]migrations.Migration, error){valid.Load, valid.LoadOffline} {
		var invalid identity.InvalidInputError
		if history, err := load(nil); !errors.As(err, &invalid) || history != nil {
			t.Fatal("nil context produced history", err)
		}
		if history, err := load(ctx); !errors.Is(err, context.Canceled) || history != nil {
			t.Fatal("cancelled context produced history or lost cancellation", err)
		}
	}
}

func TestAdminRevokeAllMigrationAcceptsMaximumAllocation(t *testing.T) {
	source := AdminRevokeAllMigrationSource{Schema: strings.Repeat("s", 63), Version: migrations.Version(math.MaxInt64) - 1, IndexVersion: migrations.Version(math.MaxInt64)}
	for _, load := range []func(context.Context) ([]migrations.Migration, error){source.Load, source.LoadOffline} {
		history, err := load(t.Context())
		if err != nil || len(history) != 2 || history[0].Version() != source.Version || history[1].Version() != source.IndexVersion {
			t.Fatal("maximum supported schema/version allocation was rejected", err)
		}
	}
}
