package reference

import (
	"context"
	"io"
	"io/fs"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
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
	version     migrations.Version
	schema      string
	tables      []string
	roles       []string
	columns     []string // table.column; only columns first introduced by this step
	functions   []string
	constraints []string // table.constraint; only constraints introduced by this step
	// constraintValue distinguishes a new allowance when the native migration
	// deliberately reuses an existing CHECK name instead of creating an object.
	constraintValue string
}

func (s StoreSet) migrationCatalog(ctx context.Context) ([]migrationHistory, error) {
	catalog, err := s.baseMigrationCatalog(ctx)
	if err != nil {
		return nil, err
	}
	catalog, err = s.usernameMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phoneMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phoneSigninMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phoneOTPSigninMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phoneRemovalMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phoneChangeMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = s.phonePasswordResetMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	return s.anonymousMigrationCatalog(ctx, catalog)
}

func (s StoreSet) baseMigrationCatalog(ctx context.Context) ([]migrationHistory, error) {
	history, err := s.MigrationSource().Load(ctx)
	if err != nil {
		return nil, err
	}
	shared := migrationHistory{history: history, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{
		{version: 1, schema: "identity"}, {version: 1000, schema: s.state.config.Schema},
	}}
	shared.guards = append(shared.guards, sharedSuffixGuards(s.state.config.Schema)...)
	if s.state.features != nil && s.state.features.migrations.magicTOTP && s.state.features.verificationSessionLineage != VerificationBeforeMFA {
		shared.guards = append(shared.guards, migrationGuard{version: 1019, schema: "identity", columns: []string{"commands.preparation_declaration"}})
	}
	for _, step := range history {
		v := step.Version()
		var owner ModuleID
		switch {
		case v <= 9 || v >= 1012 && v <= 1019:
			owner = "identity/postgres"
		case v >= 1000 && v <= 1011:
			owner = "identity/risk/postgres"
		case v >= 1100 && v <= 1103 || v == 1400:
			owner = "identity/otp/postgres"
		case v >= 1200 && v <= 1210 || v >= 1410 && v <= 1417:
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
	if s.state.durable {
		steps, err := (riskpg.DurableCounterMigrationSource{Schema: s.state.config.Schema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_durable_admission", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}, guards: []migrationGuard{{version: 1, schema: s.state.config.Schema, tables: []string{"durable_counter_scopes", "durable_counter_keys", "durable_counter_windows", "durable_counter_aliases", "durable_counter_attempts"}}}})
	}
	if s.state.httpRate != nil {
		// Keep the native owner's version/SQL and an independent ledger. Enabling
		// admission later must not rewrite an already-applied identity prefix.
		native := ratepg.SchemaMigration()
		step, err := migrations.NewMigration(migrations.Version(native.Version), native.Name, migrations.TransactionModeDefault, native.Up, native.Down)
		if err != nil {
			return nil, err
		}
		owned := migrationHistory{namespace: "identity_http_rate", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): "rate-limit/postgres"}, guards: []migrationGuard{{version: step.Version(), schema: "public", tables: []string{"rate_limit_states", "rate_limit_states_expires_at_idx"}}}}
		if s.state.features != nil && (s.state.features.httpAnonymous != nil && s.state.features.httpAnonymous.secret != nil || s.state.features.httpUsername != nil && s.state.features.httpUsername.rate != nil || s.state.features.httpPasswordReset != nil || s.state.features.httpPhonePasswordReset != nil || s.state.features.httpRegistrationVerification != nil || s.state.features.httpPasswordVerification != nil || s.state.features.httpPasswordChange != nil || s.state.features.httpEmailRequests != nil && s.state.features.httpEmailRequests.secret != nil || s.state.features.httpEmailOTPVerification != nil || s.state.features.httpPhoneVerification != nil || s.state.features.httpPhoneRemoval != nil || s.state.features.httpPhoneChange != nil || s.state.features.httpMagicLink != nil && s.state.features.httpMagicLink.config.Consume) {
			native := ratepg.AtomicSchemaMigration()
			atomic, err := migrations.NewMigration(migrations.Version(native.Version), native.Name, migrations.TransactionModeDefault, native.Up, native.Down)
			if err != nil {
				return nil, err
			}
			owned.history = append(owned.history, atomic)
			owned.owners[atomic.Version()] = "rate-limit/postgres"
			owned.guards = append(owned.guards, migrationGuard{version: atomic.Version(), schema: "public", tables: []string{"rate_limit_atomic_commands"}})
		}
		catalog = append(catalog, owned)
	}
	if s.state.features == nil {
		return catalog, nil
	}
	c := s.state.features.migrations
	if c.signinSchema == "" && c.passwordSigninSchema != "" {
		c.signinSchema = c.passwordSigninSchema
	}
	if c.preauthIssue {
		// Initiation and consuming Signin are independently selectable. A later
		// shared-ledger allocation would prevent enabling earlier Signin steps
		// on an initiation-first deployment. Native namespaces retain one global
		// command/lock owner without rewriting the original shared history.
		steps, err := (sessionpg.PreAuthIssueMigrationSource{Schema: c.sessionSchema, Version: 1420}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_preauth", history: steps,
			owners: map[migrations.Version]ModuleID{1420: "identity/session/postgres"},
			guards: []migrationGuard{{version: 1420, schema: c.sessionSchema, tables: []string{"preauth_issuances"}}}})
	}
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
	if c.signinSchema != "" || s.state.features.email != nil && (s.state.features.email.otpVerification != nil || s.state.features.email.otpChange != nil) {
		catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1400, schema: c.otpSchema, columns: []string{"challenges.consumer_envelope", "challenges.consumer_owner", "challenges.consumer_record_requirement", "challenges.consumer_subject_requirement"}, functions: []string{"guard_original_custody"}})
	}
	if c.signinSchema != "" {
		catalog[0].guards = append(catalog[0].guards,
			migrationGuard{version: 1411, schema: c.signinSchema, tables: []string{"family_revocations"}},
			migrationGuard{version: 1412, schema: c.signinSchema, tables: []string{"session_issuances"}})
		if c.signinSchema != c.sessionSchema && c.signinSchema != c.authenticatedSchema {
			catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1410, schema: c.signinSchema})
		}
	}
	if c.singleSessionRevocation {
		catalog[0].guards = append(catalog[0].guards, migrationGuard{version: 1417, schema: c.signinSchema, tables: []string{"session_revocations"}})
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
	if c.resetSchema != "" {
		reset, err := passwordResetMigrationCatalog(ctx, shared.history, c.resetSchema)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, reset...)
	}
	if c.passwordSigninSchema != "" {
		// Password material has one physical owner shared with reset. Selecting
		// either workflow first must leave its installed checksums unchanged.
		if c.resetSchema == "" {
			steps, err := (passwordpg.MigrationSource{}).Load(ctx)
			if err != nil {
				return nil, err
			}
			owned := migrationHistory{namespace: "identity_password", history: steps, owners: make(map[migrations.Version]ModuleID), guards: []migrationGuard{{version: 1, schema: "identity_password"}}}
			for _, step := range steps {
				owned.owners[step.Version()] = "identity/password/postgres"
			}
			catalog = append(catalog, owned)
		}
		steps, err := (sessionpg.PasswordSigninMigrationSource{Schema: c.passwordSigninSchema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_password_session", history: steps,
			owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"},
			guards: []migrationGuard{{version: 1, schema: c.passwordSigninSchema, constraints: []string{"session_issuances.session_issuances_purpose_v3"}}}})
	}
	if s.state.features.passwordSignup != nil {
		catalog, err = passwordSignupMigrationCatalog(ctx, catalog, s.state.config.Schema)
		if err != nil {
			return nil, err
		}
	}
	if c.otpSigninFactors {
		catalog, err = emailOTPFactorMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
	}
	if e := s.state.features.email; e != nil {
		catalog, err = emailMigrationCatalog(ctx, catalog, s.state.config.Schema, e.verification != nil || e.change != nil || e.removal != nil, e.change != nil)
		if err != nil {
			return nil, err
		}
		if e.removal != nil {
			catalog, err = emailRemovalMigrationCatalog(ctx, catalog)
			if err != nil {
				return nil, err
			}
		}
		if e.otpVerification != nil || e.otpChange != nil {
			catalog, err = emailOTPFactorMigrationCatalog(ctx, catalog)
			if err != nil {
				return nil, err
			}
		}
	}
	if s.state.features.passwordChange != nil {
		catalog, err = passwordChangeMigrationCatalog(ctx, catalog, c.passwordSigninSchema)
		if err != nil {
			return nil, err
		}
	}
	if s.state.features.magicRequest != nil {
		catalog, err = magicLinkMigrationCatalog(ctx, catalog, c.magicSessionSchema, c.magicMFAChallenge)
		if err != nil {
			return nil, err
		}
		if c.magicSignup {
			catalog, err = magicLinkSignupMigrationCatalog(ctx, catalog)
			if err != nil {
				return nil, err
			}
		}
		if c.magicTOTP {
			catalog, err = magicLinkTOTPRequiredMigrations(ctx, catalog, c.magicSessionSchema, s.state.config.Schema, s.state.features.verificationSessionLineage == VerificationBeforeMFA)
			if err != nil {
				return nil, err
			}
		}
	}
	if u := s.state.features.username; u != nil && u.signup != nil && !(s.state.features.magicRequest != nil && c.magicSignup) {
		// Install the retained registration/factor-purpose predecessor before
		// later MFA history, without enabling a magic-link service. Username's
		// final superset must never be replaced by this older suffix afterward.
		catalog, err = magicLinkSignupMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
	}
	if c.passwordMFA {
		catalog, err = passwordTOTPMigrationCatalog(ctx, catalog, c.passwordSigninSchema, s.state.config.Schema, c.passwordTOTP || c.passwordRecovery || c.passwordOTP, s.state.features.verificationSessionLineage == VerificationBeforeMFA)
		if err != nil {
			return nil, err
		}
		if c.passwordRecovery || c.passwordOTP {
			catalog, err = recoveryCompletionMigrationCatalog(ctx, catalog, c.passwordSigninSchema, s.state.config.Schema, s.state.features.email != nil && s.state.features.email.change != nil)
			if err != nil {
				return nil, err
			}
		}
		if c.passwordOTP {
			catalog, err = passwordOTPMigrationCatalog(ctx, catalog, c.passwordSigninSchema, s.state.config.Schema)
			if err != nil {
				return nil, err
			}
		}
		catalog, err = s.activeStepUpMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
		return s.verificationSigninMigrationCatalog(ctx, catalog)
	}
	if s.state.features.mfaEnrollment != nil {
		catalog, err = mfaEnrollmentMigrationCatalog(ctx, catalog, s.state.config.Schema)
		if err != nil {
			return nil, err
		}
		catalog, err = s.activeStepUpMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
		return s.verificationSigninMigrationCatalog(ctx, catalog)
	}
	return s.verificationSigninMigrationCatalog(ctx, catalog)
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
	 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname=ANY($6::text[]))
	 OR EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND (c.relname::text||'.'||k.conname::text)=ANY($7::text[]) AND ($8::text='' OR position($8::text IN pg_catalog.pg_get_constraintdef(k.oid))>0))`, g.schema, len(g.tables) == 0 && len(g.columns) == 0 && len(g.functions) == 0 && len(g.constraints) == 0, g.tables, g.roles, g.columns, g.functions, g.constraints, g.constraintValue).Scan(&exists)
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
