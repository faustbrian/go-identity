package reference

import (
	"context"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// Only successful native recovery creates this immutable original-journal
// checker. Publication/invalidation share storeState.mu with the counter owner.
// Pointer identity detects replacement while a probe is outside the graph lock.
type velocityHealth struct{ check func(context.Context) error }

type readinessTenant struct {
	tenant *tenantRecovery
	health *velocityHealth
}

func (s *Server) readiness(ctx context.Context) Readiness {
	deny := func(code ReadinessCode) Readiness { return Readiness{Failures: []ReadinessCode{code}} }
	if s == nil || s.state == nil || ctx == nil || ctx.Err() != nil {
		return deny("server_unavailable")
	}
	state := s.state
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return deny("server_unavailable")
	}
	if state.features == nil || !state.features.ready || state.features.initializing {
		state.mu.Unlock()
		return deny("not_initialized")
	}
	if len(state.tenants) == 0 {
		state.mu.Unlock()
		return deny("native_unavailable")
	}
	selected := make([]readinessTenant, 0, len(state.tenants))
	for _, tenant := range state.tenants {
		if tenant.busy || tenant.counter == nil || tenant.health == nil || tenant.health.check == nil {
			state.mu.Unlock()
			return deny("native_unavailable")
		}
		selected = append(selected, readinessTenant{tenant, tenant.health})
	}
	if state.active == 0 {
		state.drained = make(chan struct{})
	}
	state.active++
	state.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, s.budget)
	stop := context.AfterFunc(state.lifetime, cancel)
	defer func() {
		stop()
		cancel()
		state.mu.Lock()
		state.active--
		if state.active == 0 {
			close(state.drained)
		}
		state.mu.Unlock()
	}()

	// All selected native histories participate, including independent owner
	// ledgers. Discovery reads compatibility; it never applies or repairs them.
	stores := StoreSet{state: state}
	catalog, err := stores.migrationCatalog(bounded)
	if err != nil {
		return deny("schema_unavailable")
	}
	unique := make(map[ModuleID]bool)
	for _, history := range catalog {
		for _, owner := range history.owners {
			unique[owner] = true
		}
	}
	modules := make([]ModuleID, 0, len(unique))
	for owner := range unique {
		modules = append(modules, owner)
	}
	slices.Sort(modules)
	status, err := stores.ReferenceMigrationCheck(bounded, ReferenceMigrationCheckRequest{Modules: modules})
	if err != nil || len(status.Statuses) != len(modules) {
		return deny("schema_unavailable")
	}
	for _, owner := range status.Statuses {
		if owner.Compatibility != MigrationCompatible {
			return deny("schema_incompatible")
		}
	}
	// Ledger compatibility is not live catalog presence: migration discovery's
	// collision guards intentionally check only unapplied steps. Readiness also
	// requires the selected owners' expected objects to remain present.
	present, err := readinessSchemaPresent(bounded, state, catalog)
	if err != nil {
		return deny("schema_unavailable")
	}
	if !present {
		return deny("schema_incompatible")
	}
	for _, tenant := range selected {
		if err := tenant.health.check(bounded); err != nil {
			return deny("native_unavailable")
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if bounded.Err() != nil || state.closed || !state.features.ready || state.features.initializing {
		return deny("server_unavailable")
	}
	for _, tenant := range selected {
		if tenant.tenant.busy || tenant.tenant.health != tenant.health || tenant.tenant.counter == nil {
			return deny("native_unavailable")
		}
	}
	return Readiness{Ready: true}
}

func readinessSchemaPresent(ctx context.Context, state *storeState, catalog []migrationHistory) (bool, error) {
	schemas, tables, roles, columns, functions, constraints := []string{}, []string{}, []string{}, []string{}, []string{}, []string{}
	for _, history := range catalog {
		for _, guard := range readinessCatalogGuards(state, history) {
			if _, selected := history.owners[guard.version]; !selected {
				continue
			}
			schemas = append(schemas, guard.schema)
			roles = append(roles, guard.roles...)
			for _, table := range guard.tables {
				tables = append(tables, guard.schema+"."+table)
			}
			for _, column := range guard.columns {
				columns = append(columns, guard.schema+"."+column)
			}
			for _, function := range guard.functions {
				functions = append(functions, guard.schema+"."+function)
			}
			for _, constraint := range guard.constraints {
				constraints = append(constraints, guard.schema+"."+constraint)
			}
		}
	}
	// One bounded catalog observation, rather than one round-trip per object.
	// Catalog identities come solely from the immutable selected native sources.
	var present bool
	err := state.pool.Raw().QueryRow(ctx, `SELECT
 NOT EXISTS(SELECT 1 FROM unnest($1::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname=x))
 AND NOT EXISTS(SELECT 1 FROM unnest($2::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname::text||'.'||c.relname::text=x))
 AND NOT EXISTS(SELECT 1 FROM unnest($3::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=x))
 AND NOT EXISTS(SELECT 1 FROM unnest($4::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE NOT a.attisdropped AND n.nspname::text||'.'||c.relname::text||'.'||a.attname::text=x))
	 AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname::text||'.'||p.proname::text=x))
	 AND NOT EXISTS(SELECT 1 FROM unnest($6::text[]) x WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname::text||'.'||c.relname::text||'.'||k.conname::text=x))`, schemas, tables, roles, columns, functions, constraints).Scan(&present)
	return present, err
}

// Collision discovery deliberately needs only enough identities to detect an
// unmanaged installation. Runtime presence additionally needs the base objects
// consumed by each selected owner. Keep these names aligned with the native
// sources assembled in migrations.go; do not infer SQL or copy migration DDL.
func readinessCatalogGuards(state *storeState, history migrationHistory) []migrationGuard {
	guards := slices.Clone(history.guards)
	if state.features != nil && state.features.verificationSigninMFA {
		for i := range guards {
			if guards[i].schema != "identity_mfa" {
				continue
			}
			guards[i].constraints = slices.Clone(guards[i].constraints)
			for j, name := range guards[i].constraints {
				if name == "continuations.continuations_origin_purpose_check" {
					guards[i].constraints[j] = "continuations.continuations_origin_purpose_v2"
				}
			}
		}
	}
	if state.features != nil && (state.features.migrations.magicSessionSchema != "" || state.features.migrations.passwordTOTP || state.features.migrations.passwordRecovery || state.features.verificationSignin != nil) {
		schema := state.features.migrations.magicSessionSchema
		if schema == "" {
			schema = state.features.migrations.passwordSigninSchema
		}
		// The selected magic-link suffix replaces the earlier purpose and
		// continuation constraints, preserving their older migration checksums.
		// Require the actual successors, never the removed predecessor names;
		// collision discovery must still retain the original history guards.
		for i := range guards {
			if guards[i].schema != schema {
				continue
			}
			guards[i].constraints = slices.Clone(guards[i].constraints)
			for j, constraint := range guards[i].constraints {
				switch constraint {
				case "session_issuances.session_issuances_purpose_v3", "session_issuances.session_issuances_purpose_v4":
					guards[i].constraints[j] = "session_issuances.session_issuances_purpose_v5"
				case "sessions.session_credential_continuation_v1":
					guards[i].constraints[j] = "sessions.session_credential_continuation_v2"
				}
				if state.features.migrations.magicTOTP || state.features.migrations.passwordTOTP || state.features.migrations.passwordRecovery || state.features.verificationTOTP != nil {
					switch guards[i].constraints[j] {
					case "session_issuances.session_issuances_purpose_v5":
						guards[i].constraints[j] = "session_issuances.session_issuances_purpose_v6"
					case "sessions.session_credential_continuation_v2":
						guards[i].constraints[j] = "sessions.session_credential_continuation_v3"
					case "sessions.session_record_binding_v5":
						guards[i].constraints[j] = "sessions.session_record_binding_v6"
					}
				}
				if state.features.migrations.passwordTOTP || state.features.migrations.passwordRecovery {
					switch guards[i].constraints[j] {
					case "sessions.session_record_binding_v6":
						guards[i].constraints[j] = "sessions.session_record_binding_v7"
					case "sessions.session_credential_continuation_v3":
						guards[i].constraints[j] = "sessions.session_credential_continuation_v4"
					}
				}
				if state.features.migrations.passwordRecovery {
					switch guards[i].constraints[j] {
					case "sessions.session_record_binding_v7":
						guards[i].constraints[j] = "sessions.session_record_binding_v8"
					case "sessions.session_credential_continuation_v4":
						guards[i].constraints[j] = "sessions.session_credential_continuation_v5"
					}
				}
				if state.features.verificationSignin != nil {
					switch guards[i].constraints[j] {
					case "session_issuances.session_issuances_purpose_v5", "session_issuances.session_issuances_purpose_v6":
						guards[i].constraints[j] = "session_issuances.session_issuances_purpose_v7"
					}
				}
				if state.features.verificationSessionLineage == VerificationBeforeMFA && (state.features.verificationTOTP != nil || state.features.migrations.magicTOTP || state.features.migrations.passwordTOTP || state.features.migrations.passwordRecovery || state.features.migrations.passwordOTP) {
					switch guards[i].constraints[j] {
					case "session_issuances.session_issuances_purpose_v5", "session_issuances.session_issuances_purpose_v6", "session_issuances.session_issuances_purpose_v7":
						guards[i].constraints[j] = "session_issuances.session_issuances_purpose_v8"
					}
				}
			}
		}
	}
	switch history.namespace {
	case "":
		guards = append(guards,
			migrationGuard{version: 1, schema: "identity", tables: []string{"users", "identity_users_status_order"}},
			migrationGuard{version: 1000, schema: state.config.Schema, tables: []string{"issued_evidence", "risk_issued_expiry_order", "risk_issued_subject_order"}})
		if state.features == nil {
			break
		}
		c := state.features.migrations
		guards = append(guards,
			migrationGuard{version: 1100, schema: c.otpSchema, tables: []string{"digest_keys", "challenges", "otp_issued_expiry", "otp_terminal_retention", "otp_consuming_owner"}, functions: []string{"guard_challenge"}},
			migrationGuard{version: 1250, schema: "identity", tables: []string{"identity_delivery_due"}, functions: []string{"delivery_intent_immutable"}})
		for _, profile := range []struct {
			version uint64
			schema  string
		}{{1200, c.sessionSchema}, {1210, c.authenticatedSchema}, {1410, c.signinSchema}} {
			guards = append(guards, migrationGuard{version: migrations.Version(profile.version), schema: profile.schema, tables: []string{"families", "sessions", "session_owner_order", "session_family_order", "session_expiry_order"}, columns: []string{"sessions.digest"}})
		}
	case "audit":
		// Version 2 replaces the original retention time index with the order
		// index already represented by its suffix guard. Require only identities
		// retained by the fully selected history, never a superseded object.
		guards = append(guards, migrationGuard{version: 1, schema: "audit", tables: []string{"records", "retention_events", "records_tenant_time_idx", "records_actor_time_idx", "records_subject_time_idx", "records_action_time_idx", "records_correlation_time_idx", "records_time_idx"}, functions: []string{"lock_retention_event", "prune_record", "reject_record_update", "append_record"}})
	case "identity_password":
		guards = append(guards,
			migrationGuard{version: 1, schema: "identity_password", tables: []string{"credentials"}},
			migrationGuard{version: 2, schema: "identity_password", tables: []string{"replacements"}},
			migrationGuard{version: 3, schema: "identity_password", tables: []string{"reauthentication_records"}},
			migrationGuard{version: 5, schema: "identity_password", tables: []string{"signin_records"}})
	}
	if state.features != nil && state.features.username != nil {
		u := state.features.username
		for i := range guards {
			guards[i].constraints = slices.Clone(guards[i].constraints)
			for j, name := range guards[i].constraints {
				// Native forward migrations replace only these named predecessor
				// constraints. Require the actual installed successor; do not
				// alter historical collision guards or accept a missing constraint.
				if u.signup != nil && guards[i].schema == "identity" {
					switch name {
					case "registration_bindings.identity_registration_purpose_v2":
						guards[i].constraints[j] = "registration_bindings.identity_registration_purpose_v3"
					case "registration_bindings.identity_registration_disposition_v2":
						guards[i].constraints[j] = "registration_bindings.identity_registration_disposition_v3"
					}
				}
				if u.signup != nil && guards[i].schema == "identity_mfa" && name == "factor_authorities.factor_authorities_initialized_purpose_v2" {
					guards[i].constraints[j] = "factor_authorities.factor_authorities_initialized_purpose_v3"
				}
				if u.totp != nil && guards[i].schema == "identity_mfa" && (name == "continuations.continuations_origin_purpose_check" || name == "continuations.continuations_origin_purpose_v2") {
					guards[i].constraints[j] = "continuations.continuations_origin_purpose_username_v1"
				}
				if u.totp != nil && guards[i].schema == "identity_password" && name == "mfa_primary_records.mfa_primary_records_purpose_check" {
					guards[i].constraints[j] = "mfa_primary_records.mfa_primary_records_purpose_v2"
				}
				if u.signin != nil && guards[i].schema == state.features.migrations.passwordSigninSchema {
					switch name {
					case "session_issuances.session_issuances_purpose_v3", "session_issuances.session_issuances_purpose_v4", "session_issuances.session_issuances_purpose_v5", "session_issuances.session_issuances_purpose_v6", "session_issuances.session_issuances_purpose_v7", "session_issuances.session_issuances_purpose_v8":
						guards[i].constraints[j] = "session_issuances.session_issuances_purpose_username_v1"
					}
				}
			}
		}
	}
	if state.features != nil && state.features.phoneSignin != nil {
		for i := range guards {
			guards[i].constraints = slices.Clone(guards[i].constraints)
			for j, name := range guards[i].constraints {
				// The phone suffix replaces both provenance constraints. Keep
				// predecessor histories immutable but require their real installed
				// successors, including the username password-record guard.
				if guards[i].schema == "identity_password" && name == "signin_records.signin_records_purpose_v2" {
					guards[i].constraints[j] = "signin_records.signin_records_purpose_phone_v1"
				}
				if guards[i].schema != state.features.migrations.passwordSigninSchema {
					continue
				}
				switch name {
				case "session_issuances.session_issuances_purpose_v3", "session_issuances.session_issuances_purpose_v4", "session_issuances.session_issuances_purpose_v5", "session_issuances.session_issuances_purpose_v6", "session_issuances.session_issuances_purpose_v7", "session_issuances.session_issuances_purpose_v8", "session_issuances.session_issuances_purpose_username_v1":
					guards[i].constraints[j] = "session_issuances.session_issuances_purpose_phone_password_v1"
				}
			}
		}
	}
	if state.features != nil && state.features.phoneOTPSignin != nil {
		for i := range guards {
			if guards[i].schema != state.features.migrations.signinSchema {
				continue
			}
			guards[i].constraints = slices.Clone(guards[i].constraints)
			for j, name := range guards[i].constraints {
				switch name {
				case "session_issuances.session_issuances_purpose_v2", "session_issuances.session_issuances_purpose_v3", "session_issuances.session_issuances_purpose_v4", "session_issuances.session_issuances_purpose_v5", "session_issuances.session_issuances_purpose_v6", "session_issuances.session_issuances_purpose_v7", "session_issuances.session_issuances_purpose_v8", "session_issuances.session_issuances_purpose_username_v1", "session_issuances.session_issuances_purpose_phone_password_v1":
					guards[i].constraints[j] = "session_issuances.session_issuances_purpose_phone_otp_v1"
				}
			}
		}
	}
	return guards
}
