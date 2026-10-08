package reference

import (
	"context"
	"io"
	"io/fs"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// Module ownership is distinct from physical ledger ownership. The shared
// history retains its original allocation; independent owners retain theirs.
type migrationHistory struct {
	namespace string
	history   []migrations.Migration
	owners    map[migrations.Version]ModuleID
	guards    []migrationGuard
	preflight string // native fresh-install policy; never exposed as executable SQL
}

type migrationGuard struct {
	version   migrations.Version
	schema    string
	tables    []string
	roles     []string
	columns   []string // table.column; only columns first introduced by this step
	functions []string
}

func (s StoreSet) migrationCatalog(ctx context.Context) ([]migrationHistory, error) {
	history, err := s.MigrationSource().Load(ctx)
	if err != nil {
		return nil, err
	}
	shared := migrationHistory{history: history, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{
		{version: 1, schema: "identity"}, {version: 1000, schema: s.state.config.Schema},
	}}
	shared.guards = append(shared.guards, sharedSuffixGuards(s.state.config.Schema)...)
	for _, step := range history {
		v := step.Version()
		var owner ModuleID
		switch {
		case v <= 9 || v >= 1012 && v <= 1018:
			owner = "identity/postgres"
		case v >= 1000 && v <= 1011:
			owner = "identity/risk/postgres"
		case v >= 1100 && v <= 1103:
			owner = "identity/otp/postgres"
		case v >= 1200 && v <= 1210:
			owner = "identity/session/postgres"
		case v >= 1250 && v <= 1260:
			owner = "identity/delivery/postgres"
		case v == 1300:
			owner = "authorization/postgres"
		default:
			return nil, identity.InvalidInputError{Field: "reference_catalog"}
		}
		shared.owners[v] = owner
	}
	catalog := []migrationHistory{shared}
	if s.state.features == nil {
		return catalog, nil
	}
	c := s.state.features.migrations
	catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1100, schema: c.otpSchema},
		migrationGuard{version: 1250, schema: "identity", tables: []string{"delivery_intents"}},
		migrationGuard{version: 1300, schema: "public", tables: []string{"authorization_subject_authorities"}})
	catalog[0].guards = append(catalog[0].guards,
		migrationGuard{version: 1101, schema: c.otpSchema, tables: []string{"lockout_key_binding", "lockouts", "otp_lockout_expiry"}, functions: []string{"guard_lockout", "guard_lockout_key"}},
		migrationGuard{version: 1102, schema: c.otpSchema, tables: []string{"send_families"}, functions: []string{"guard_send_family"}},
		migrationGuard{version: 1103, schema: c.otpSchema, tables: []string{"otp_issuance_family_live", "otp_issuance_family_reserved", "otp_legacy_issuance_live", "otp_legacy_issuance_reserved"}, columns: []string{"challenges.send_family_digest"}, functions: []string{"guard_issuance_family"}},
		migrationGuard{version: 1201, schema: c.sessionSchema, tables: []string{"preauth_transactions", "preauth_expiry_order"}})
	if c.sessionSchema != "" {
		catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1200, schema: c.sessionSchema})
	}
	if c.authenticatedSchema != "" && c.authenticatedSchema != c.sessionSchema {
		catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1210, schema: c.authenticatedSchema})
	}
	for _, source := range []struct {
		owner     ModuleID
		namespace string
		files     fs.FS
		guard     migrationGuard
	}{
		{"audit/postgres", "audit", auditpg.Migrations(), migrationGuard{version: 1, schema: "audit", roles: []string{"audit_writer", "audit_reader", "audit_retention"}}},
		{"outbox/postgres", "outbox", outboxpg.Migrations(), migrationGuard{version: 1, schema: "public", tables: []string{"outbox_messages", "outbox_replay_audit"}}},
		{"outbox/postgres/identity", "identity_outbox", lifecyclepg.Migrations(), migrationGuard{version: 1, schema: "public", tables: []string{"identity_outbox_bindings"}}},
	} {
		native, err := migrations.NewFSSource(ownedMigrationFiles{source.files}, ".")
		if err != nil {
			return nil, err
		}
		steps, err := native.Load(ctx)
		if err != nil {
			return nil, err
		}
		owned := migrationHistory{namespace: source.namespace, history: steps, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{source.guard}}
		if source.owner == "audit/postgres" {
			owned.preflight = auditpg.FreshInstallPreflightSQL()
			owned.guards = append(owned.guards,
				migrationGuard{version: 2, schema: "audit", tables: []string{"records_accepted_order_idx", "retention_events_record_order_idx"}, columns: []string{"records.accepted_order", "retention_events.accepted_order"}},
				migrationGuard{version: 4, schema: "audit", tables: []string{"record_identities"}, functions: []string{"reject_record_identity_change", "canonical_json_string", "canonical_timestamp", "canonical_string_map", "canonical_actor", "canonical_record", "validate_record", "capture_record_identity"}},
				migrationGuard{version: 5, schema: "audit", tables: []string{"identity_command_bindings"}, functions: []string{"append_identity_record"}},
				migrationGuard{version: 6, schema: "audit", functions: []string{"identity_record_status"}})
		}
		for _, step := range steps {
			owned.owners[step.Version()] = source.owner
		}
		catalog = append(catalog, owned)
	}
	return catalog, nil
}

func (g migrationGuard) exists(ctx context.Context, s *storeState) (bool, error) {
	var exists bool
	// Catalog presence is discovery metadata, not migration DDL. Empty schemas
	// collide too. Tables-only owners must not claim the shared public namespace.
	err := s.pool.Raw().QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1 AND $2::boolean)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=ANY($3::text[]))
	 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=ANY($4::text[]))
	 OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT a.attisdropped AND (c.relname::text||'.'||a.attname::text)=ANY($5::text[]))
	 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname=ANY($6::text[]))`, g.schema, len(g.tables) == 0 && len(g.columns) == 0 && len(g.functions) == 0, g.tables, g.roles, g.columns, g.functions).Scan(&exists)
	return exists, err
}

// Only immutable embedded files supplied by the selected upstream owners enter
// this adapter. No caller filesystem, path, SQL parser or runner is introduced.
// The native source retains filename/directive/checksum validation; these
// methods enforce its budgets before retaining content and preserve cancellation.
type ownedMigrationFiles struct{ files fs.FS }

func (f ownedMigrationFiles) ReadDir(ctx context.Context, root string, limits migrations.SourceDirectoryLimits) ([]migrations.SourceEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(f.files, root)
	if err != nil {
		return nil, err
	}
	if len(entries) > limits.MaxEntries {
		return nil, migrations.ErrSourceLimit
	}
	result := make([]migrations.SourceEntry, 0, len(entries))
	total := 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > limits.MaxNameBytes || len(name) > limits.MaxTotalNameBytes-total {
			return nil, migrations.ErrSourceLimit
		}
		total += len(name)
		result = append(result, migrations.SourceEntry{Name: name, Directory: entry.IsDir()})
	}
	return result, ctx.Err()
}

func (f ownedMigrationFiles) ReadFile(ctx context.Context, name string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := f.files.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(limit) || info.Size() < 0 {
		return nil, migrations.ErrSourceLimit
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > limit {
		return nil, migrations.ErrSourceLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return wire, nil
}
