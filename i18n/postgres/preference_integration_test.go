//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-authorization/v3/rbac"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/i18n"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Risk plan: real primary session/CSRF and policy admission, preference CAS,
// immutable command replay, journal-owned unknown-outcome reconciliation,
// lifecycle fences and atomic update/audit/outbox/checkpoint persistence.
// Audit/outbox test participants exercise the kernel phases, not the separate
// third-party adapter interoperability/release gates.
func TestPreferenceNativeDurabilityAndAuthority(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	pool, c, credentials := preferenceFixture(t, ctx)
	store, err := NewPreferenceStore(pool, c, credentials)
	if err != nil {
		t.Fatal("construct native preference store", err)
	}
	key := i18n.PreferenceKey{TenantID: "locale-tenant", SubjectID: "locale-user"}
	command := func(id byte, expected uint64, locale string) i18n.PreferenceCommand {
		var raw [16]byte
		raw[0] = id
		return i18n.PreferenceCommand{Key: key, ExpectedVersion: expected, Locale: locale, ConsentNoticeVersion: 7, CommandID: identity.CommandID(base64.RawURLEncoding.EncodeToString(raw[:]))}
	}
	if value, err := store.GetPreference(ctx, key); !errors.As(err, new(i18n.PreferenceNotFoundError)) || value != (i18n.Preference{}) {
		t.Fatal("absence became a preference", err)
	}
	first := command(1, 0, "fi")
	want, err := store.SetPreference(ctx, first)
	if err != nil || want.Locale != "fi" || want.Version != 1 || want.ConsentNoticeVersion != 7 {
		t.Fatal("authenticated explicit notice acceptance failed", err)
	}
	second := command(2, 1, "en")
	if value, err := store.SetPreference(ctx, second); err != nil || value.Locale != "en" || value.Version != 2 {
		t.Fatal("second durable mutation failed", err)
	}
	// A reconstructed caller/store must read durable primary state, not a cache.
	restarted, err := NewPreferenceStore(pool, c, credentials)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := restarted.GetPreference(ctx, key); err != nil || value.Locale != "en" || value.Version != 2 {
		t.Fatal("restart did not read current preference", err)
	}
	en, _ := i18n.NewCatalog("en", []i18n.Message{{ID: "locale-test", Template: "Denied"}})
	fi, _ := i18n.NewCatalog("fi", []i18n.Message{{ID: "locale-test", Template: "Estetty"}})
	registry := i18n.NewErrorRegistry()
	if err := registry.Register("locale-test-error", "locale-test", i18n.ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	resolver, err := i18n.NewResolver([]i18n.Catalog{en, fi}, []string{"en", "fi"}, registry, restarted)
	if err != nil {
		t.Fatal(err)
	}
	public := resolver.(i18n.PreferenceResolver)
	durable, err := public.GetPreference(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	localized, err := public.Resolve(ctx, i18n.ResolveInput{Session: durable.Locale, AcceptLanguage: "fi", Default: "fi", Error: preferenceMessageError{}})
	if err != nil || localized.Locale != "en" || localized.Message != "Denied" {
		t.Fatal("public resolver did not use authenticated durable preference", err)
	}
	if replay, err := restarted.SetPreference(ctx, first); err != nil || replay != want {
		t.Fatal("exact command replay followed newer projection", err)
	}
	for name, change := range map[string]func(*i18n.PreferenceCommand){
		"altered locale":   func(p *i18n.PreferenceCommand) { p.Locale = "en" },
		"altered expected": func(p *i18n.PreferenceCommand) { p.ExpectedVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			altered := first
			change(&altered)
			if value, err := restarted.SetPreference(ctx, altered); !errors.As(err, new(i18n.PreferenceConflictError)) || value != (i18n.Preference{}) {
				t.Fatal("altered same-command intent admitted", err)
			}
		})
	}
	for name, change := range map[string]func(*i18n.PreferenceCommand){
		"missing notice":      func(p *i18n.PreferenceCommand) { p.ConsentNoticeVersion = 0 },
		"wrong notice":        func(p *i18n.PreferenceCommand) { p.ConsentNoticeVersion = 6 },
		"unsupported locale":  func(p *i18n.PreferenceCommand) { p.Locale = "sv" },
		"noncanonical locale": func(p *i18n.PreferenceCommand) { p.Locale = "EN" },
		"foreign tenant":      func(p *i18n.PreferenceCommand) { p.Key.TenantID = "foreign" },
		"foreign subject":     func(p *i18n.PreferenceCommand) { p.Key.SubjectID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			input := command(3, 2, "fi")
			change(&input)
			if value, err := store.SetPreference(ctx, input); err == nil || value != (i18n.Preference{}) {
				t.Fatal("invalid policy/scope input admitted")
			}
		})
	}
	if _, err := store.SetPreference(ctx, command(4, 0, "fi")); !errors.As(err, new(i18n.PreferenceConflictError)) {
		t.Fatal("stale CAS admitted", err)
	}
	// Lost acknowledgement after the real commit must reconcile the original
	// command, not infer its result from the now-newer current preference.
	unknown := command(5, 2, "fi")
	store.commit = func(coordinator *kernel.Coordinator, w kernel.Work, result identity.CommandResult) (identity.CommandResult, error) {
		committed, err := coordinator.Commit(w, result)
		if err != nil || committed.Outcome != identity.CommitOutcomeCommitted {
			return committed, err
		}
		return identity.CommandResult{Binding: result.Binding, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: preferenceOperation()}}, identity.UnknownCommitError{CommandID: result.Binding.CommandID}
	}
	if _, err := store.SetPreference(ctx, unknown); !errors.As(err, new(i18n.PreferenceOutcomeUnknownError)) {
		t.Fatal("lost commit acknowledgement was not unknown", err)
	}
	if _, err := restarted.SetPreference(ctx, command(6, 3, "en")); err != nil {
		t.Fatal("newer write after unknown commit", err)
	}
	if recovered, err := restarted.SetPreference(ctx, unknown); err != nil || recovered.Locale != "fi" || recovered.Version != 3 {
		t.Fatal("same-command unknown recovery changed original result", err)
	}
	var updates, checkpoint, audits, lifecycle int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_i18n.preference_updates), checkpoint, (SELECT count(*) FROM preference_test_audits WHERE outcome='committed'), (SELECT count(*) FROM preference_test_outbox) FROM identity_i18n.preferences WHERE tenant_id='locale-tenant' AND subject_id='locale-user'`).Scan(&updates, &checkpoint, &audits, &lifecycle); err != nil || updates != 4 || checkpoint != 4 || audits != 4 || lifecycle != 4 {
		t.Fatal("mutation/checkpoint/audit/outbox atomicity or replay failed", err)
	}
	for _, denial := range []string{"csrf", "session", "credential", "authorization", "user", "lifecycle"} {
		t.Run(denial, func(t *testing.T) {
			deniedCredentials := credentials
			var reset string
			switch denial {
			case "csrf":
				deniedCredentials.CSRF, _ = session.NewCSRFToken()
			case "session":
				preferenceExec(t, ctx, pool, `UPDATE locale_sessions.sessions SET state='revoked'`)
				reset = `UPDATE locale_sessions.sessions SET state='active'`
			case "credential":
				preferenceExec(t, ctx, pool, `UPDATE identity.credential_references SET enabled=false`)
				reset = `UPDATE identity.credential_references SET enabled=true`
			case "authorization":
				preferenceExec(t, ctx, pool, `UPDATE authorization_subject_authorities SET version=2`)
				reset = `UPDATE authorization_subject_authorities SET version=1`
			case "user":
				preferenceExec(t, ctx, pool, `UPDATE identity.users SET status='deleted'`)
				reset = `UPDATE identity.users SET status='active'`
			case "lifecycle":
				preferenceExec(t, ctx, pool, `UPDATE identity_i18n.preferences SET closed=true`)
				reset = `UPDATE identity_i18n.preferences SET closed=false`
			}
			if reset != "" {
				defer preferenceExec(t, ctx, pool, reset)
			}
			denied, err := NewPreferenceStore(pool, c, deniedCredentials)
			if err != nil {
				t.Fatal(err)
			}
			if value, err := denied.SetPreference(ctx, first); err == nil || value != (i18n.Preference{}) {
				t.Fatal("revoked authority disclosed historical write")
			}
			if denial != "csrf" {
				if value, err := denied.GetPreference(ctx, key); err == nil || value != (i18n.Preference{}) {
					t.Fatal("revoked authority disclosed preference")
				}
			}
		})
	}
	t.Run("lifecycle failure rolls back preference and checkpoint", func(t *testing.T) {
		failing := c
		failing.Lifecycle = preferenceLifecycle{fail: true}
		broken, err := NewPreferenceStore(pool, failing, credentials)
		if err != nil {
			t.Fatal(err)
		}
		if value, err := broken.SetPreference(ctx, command(7, 4, "fi")); err == nil || value != (i18n.Preference{}) {
			t.Fatal("failed lifecycle reported success")
		}
		current, err := restarted.GetPreference(ctx, key)
		if err != nil || current.Version != 4 || current.Locale != "en" {
			t.Fatal("failed lifecycle committed preference", err)
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_i18n.preference_updates`).Scan(&count); err != nil || count != 4 {
			t.Fatal("rollback retained update checkpoint", err)
		}
	})
	t.Run("concurrent CAS has one successor", func(t *testing.T) {
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, id := range []byte{8, 9} {
			go func(id byte) { <-start; _, err := restarted.SetPreference(ctx, command(id, 4, "fi")); results <- err }(id)
		}
		close(start)
		committed, conflicted := 0, 0
		for range 2 {
			err := <-results
			if err == nil {
				committed++
			} else if errors.As(err, new(i18n.PreferenceConflictError)) {
				conflicted++
			} else {
				t.Fatal("unexpected concurrent outcome", err)
			}
		}
		if committed != 1 || conflicted != 1 {
			t.Fatal("concurrent writers did not CAS")
		}
	})
	for _, drift := range []string{"notice", "supported locales", "policy revision", "current session"} {
		t.Run("exact committed retry after "+drift, func(t *testing.T) {
			changed, auth := c, credentials
			switch drift {
			case "notice":
				changed.CurrentNoticeVersion = 8
			case "supported locales":
				changed.Supported = []i18n.Locale{"en"}
			case "policy revision":
				changed.PolicyVersion = 2
				changed.Authorization = preferencePolicies(t, 2)
			case "current session":
				auth = preferenceAnotherSession(t, ctx, pool, c, credentials, true)
			}
			current, err := NewPreferenceStore(pool, changed, auth)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := current.SetPreference(ctx, first); err != nil || result != want {
				t.Fatal("current authorized retry lost immutable original result", err)
			}
			altered := first
			altered.ExpectedVersion = 1
			if _, err := current.SetPreference(ctx, altered); !errors.As(err, new(i18n.PreferenceConflictError)) {
				t.Fatal("changed historical intent admitted", err)
			}
		})
	}
}

func TestPreferenceBusyOriginalStaysUnknownAndExact(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	pool, c, credentials := preferenceFixture(t, ctx)
	store, err := NewPreferenceStore(pool, c, credentials)
	if err != nil {
		t.Fatal(err)
	}
	key := i18n.PreferenceKey{TenantID: "locale-tenant", SubjectID: "locale-user"}
	cmd := i18n.PreferenceCommand{Key: key, Locale: "fi", ConsentNoticeVersion: 7, CommandID: "AQAAAAAAAAAAAAAAAAAAAA"}
	observed, _, err := store.authenticate(ctx, key, preferenceAction)
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: cmd.CommandID, TenantID: key.TenantID, UserID: key.SubjectID, ActorID: identity.ActorID(key.SubjectID), ActorKind: authorization.SubjectUser, OperationID: preferenceAction, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, SchemaID: preferenceOperation().SchemaID, SchemaVersion: 1, CorrelationID: string(cmd.CommandID), RecordID: string(key.SubjectID)}
	fields, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, identity.FeatureField{Name: "preference.locale", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "fi"}}, identity.FeatureField{Name: "preference.expected-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 0}}, identity.FeatureField{Name: "preference.notice-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}}, identity.FeatureField{Name: "preference.generation", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}, identity.FeatureField{Name: "preference.privacy-epoch", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}})
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: preferenceOperation(), Fields: fields}, credentials.Bearer)
	if err != nil {
		t.Fatal(err)
	}
	phase := &preferencePhase{store: store, input: cmd, binding: b, command: command, observed: observed, generation: 1, privacyEpoch: 1}
	coordinator, registry, err := store.coordinator(phase)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := phase.plan(ctx, coordinator, registry)
	if err != nil {
		t.Fatal(err)
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) || result.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("real live reservation missing", err)
	}
	if _, err := store.SetPreference(ctx, cmd); !errors.As(err, new(i18n.PreferenceOutcomeUnknownError)) {
		t.Fatal("busy original falsely reported denial or conflict", err)
	}
	for _, drift := range []string{"notice", "supported locales", "policy revision", "current session"} {
		t.Run("live original after "+drift, func(t *testing.T) {
			changed, auth := c, credentials
			switch drift {
			case "notice":
				changed.CurrentNoticeVersion = 8
			case "supported locales":
				changed.Supported = []i18n.Locale{"en"}
			case "policy revision":
				changed.PolicyVersion = 2
				changed.Authorization = preferencePolicies(t, 2)
			case "current session":
				auth = preferenceAnotherSession(t, ctx, pool, c, credentials, false)
			}
			current, err := NewPreferenceStore(pool, changed, auth)
			if err != nil {
				t.Fatal(err)
			}
			var unknown i18n.PreferenceOutcomeUnknownError
			if value, err := current.SetPreference(ctx, cmd); !errors.As(err, &unknown) || unknown.CommandID != cmd.CommandID || value != (i18n.Preference{}) {
				t.Fatal("changed admission claimed terminal outcome for live original", err)
			}
		})
	}
	changed := cmd
	changed.Locale = "en"
	if _, err := store.SetPreference(ctx, changed); !errors.As(err, new(i18n.PreferenceOutcomeUnknownError)) {
		t.Fatal("unconfirmable live intent did not remain unknown", err)
	}
	var state string
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}).Scan(&state); err != nil || state != "pending" {
		t.Fatal("retry changed live original", err)
	}
	var updates int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_i18n.preference_updates`).Scan(&updates); err != nil || updates != 0 {
		t.Fatal("busy retry applied a new preference", err)
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal("original reservation could not settle", err)
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		t.Fatal("original owner could not apply", err)
	}
	settled, err := coordinator.Commit(work, provisional)
	if err != nil || settled.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original owner did not commit", err)
	}
	if value, err := store.SetPreference(ctx, cmd); err != nil || value.Locale != "fi" || value.Version != 1 {
		t.Fatal("settled original did not replay exactly", err)
	}
	if _, err := store.SetPreference(ctx, changed); !errors.As(err, new(i18n.PreferenceConflictError)) {
		t.Fatal("settled original failed to reject altered retry", err)
	}
}

func TestPreferenceRepresentativeAccessPaths(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	pool, _, _ := preferenceFixture(t, ctx)
	// Synthetic context: 12,000 dense-tenant subjects, 128 sparse-tenant
	// subjects and 8 retained updates per dense subject. No production-scale
	// latency claim follows from this isolated bounded workload.
	preferenceExec(t, ctx, pool, `INSERT INTO identity.users(tenant_id,user_id,status,version) SELECT 'locale-tenant','synthetic-'||n,'active',1 FROM generate_series(1,12000) n;
 INSERT INTO identity.users(tenant_id,user_id,status,version) SELECT 'sparse','synthetic-'||n,'active',1 FROM generate_series(1,128) n;
 INSERT INTO identity_i18n.preferences(tenant_id,subject_id,locale,version,notice_version,checkpoint) SELECT tenant_id,user_id,'en',8,7,8 FROM identity.users WHERE user_id LIKE 'synthetic-%';
 INSERT INTO identity_i18n.preference_updates(command_id,tenant_id,subject_id,locale,version,notice_version,checkpoint,generation,privacy_epoch,fingerprint)
 SELECT 'perf-'||p.tenant_id||'-'||p.subject_id||'-'||n,p.tenant_id,p.subject_id,'en',n,7,n,1,1,decode(repeat('01',32),'hex') FROM identity_i18n.preferences p CROSS JOIN generate_series(1,8) n;
 ANALYZE identity_i18n.preferences; ANALYZE identity_i18n.preference_updates; ANALYZE identity.users;`)
	var server string
	if err := pool.Raw().QueryRow(ctx, `SHOW server_version`).Scan(&server); err != nil {
		t.Fatal(err)
	}
	t.Log("synthetic PostgreSQL", server, "preferences=12128 retained updates=97024")
	for _, test := range []struct {
		name, sql string
		args      []any
	}{
		{"dense hit", preferenceCurrentSQL, []any{"locale-tenant", "synthetic-12000"}},
		{"sparse hit", preferenceCurrentSQL, []any{"sparse", "synthetic-128"}},
		{"missing subject", preferenceCurrentSQL, []any{"locale-tenant", "absent"}},
		{"missing tenant", preferenceCurrentSQL, []any{"absent", "synthetic-1"}},
		{"old replay", preferenceReplaySQL, []any{"perf-locale-tenant-synthetic-12000-1", "locale-tenant", "synthetic-12000"}},
		{"missing replay", preferenceReplaySQL, []any{"absent", "locale-tenant", "synthetic-12000"}},
		{"new subject slot", preferenceInsertSQL, []any{"locale-tenant", "locale-user"}},
		{"existing subject slot", preferenceInsertSQL, []any{"locale-tenant", "synthetic-12000"}},
		{"subject lock", preferenceLockSQL, []any{"locale-tenant", "synthetic-12000"}},
		{"missing subject lock", preferenceLockSQL, []any{"locale-tenant", "absent"}},
		{"CAS successor", preferenceUpdateSQL, []any{"locale-tenant", "synthetic-12000", "fi", "9", "7", "9", "8", "1", "1"}},
		{"stale CAS", preferenceUpdateSQL, []any{"locale-tenant", "synthetic-12000", "fi", "9", "7", "9", "7", "1", "1"}},
		{"retained result", preferenceRetainSQL, []any{"perf-new-command", "locale-tenant", "synthetic-12000", "fi", "9", "7", "9", "1", "1", "1", make([]byte, 32)}},
		{"recovery hit", preferenceRecoverySQL, []any{"perf-locale-tenant-synthetic-12000-1"}},
		{"recovery miss", preferenceRecoverySQL, []any{"absent"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := time.Now()
			for range 5 {
				// Roll back each measured write/lock so repeated observations have
				// identical input. This isolated schema has no external effects.
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := preferenceExplain(ctx, tx, test.sql, test.args)
				if err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				rollbackErr := tx.Rollback(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if rollbackErr != nil {
					t.Fatal(rollbackErr)
				}
				if strings.Contains(plan, "Seq Scan on preferences") || strings.Contains(plan, "Seq Scan on preference_updates") || strings.Contains(plan, "Seq Scan on users") {
					t.Fatal("point lookup lost indexed access", plan)
				}
				t.Log(plan)
			}
			t.Log("5 native string-bound statements elapsed", time.Since(start))
		})
	}
}

func preferenceExplain(ctx context.Context, tx pgx.Tx, sql string, args []any) (string, error) {
	if sql == preferenceCurrentSQL || sql == preferenceReplaySQL {
		// These read ports use pgx's ordinary inferred-parameter path, not
		// Work. Preserve that actual production driver behavior here too.
		rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT TEXT) "+sql, args...)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return "", err
			}
			plan.WriteString(line)
			plan.WriteByte('\n')
		}
		return plan.String(), rows.Err()
	}
	// Match Work's real extended-protocol framing: strings are binary text
	// (OID25), bytes are binary bytea (OID17), never inferred numeric OIDs.
	values, oids, formats := make([][]byte, len(args)), make([]uint32, len(args)), make([]int16, len(args))
	codecs := pgtype.NewMap()
	for i, value := range args {
		oids[i], formats[i] = pgtype.TextOID, pgtype.BinaryFormatCode
		if _, ok := value.([]byte); ok {
			oids[i] = pgtype.ByteaOID
		}
		encoded, err := codecs.Encode(oids[i], formats[i], value, make([]byte, 0))
		if err != nil {
			return "", err
		}
		values[i] = encoded
	}
	result := tx.Conn().PgConn().ExecParams(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT TEXT) "+sql, values, oids, formats, nil).Read()
	if result.Err != nil {
		return "", result.Err
	}
	var plan strings.Builder
	for _, row := range result.Rows {
		plan.Write(row[0])
		plan.WriteByte('\n')
	}
	return plan.String(), nil
}

type preferenceMessageError struct{}

func (preferenceMessageError) Error() string                        { return "original untranslated identity" }
func (preferenceMessageError) ErrorIdentity() i18n.ErrorIdentity    { return "locale-test-error" }
func (preferenceMessageError) SafeParameters() []i18n.SafeParameter { return nil }

func preferenceFixture(t *testing.T, ctx context.Context) (*database.Pool, PreferenceStoreConfig, PreferenceCredentials) {
	t.Helper()
	dsn := os.Getenv("IDENTITY_I18N_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("isolated PostgreSQL unavailable")
	}
	id, _ := identity.NewSubjectID()
	name := "i18n_test_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("isolated database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("isolated database cleanup failed")
		}
		_ = admin.Close(cleanup)
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("pool cleanup failed")
		}
	})
	base := kernel.DirectoryAuthorityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "locale-deployment", TenantIDs: []identity.TenantID{"locale-tenant"}}
	for _, source := range []migrations.Source{base, sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "locale_sessions", Version: 20}, Version: 21}, sessionpg.CSRFMigrationSource{Schema: "locale_sessions", Version: 22}, PreferenceMigrationSource{Version: 30}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			preferenceExec(t, ctx, pool, step.UpSQL())
		}
	}
	policyMigration, err := authority.AuthoritySchemaMigration(31)
	if err != nil {
		t.Fatal(err)
	}
	preferenceExec(t, ctx, pool, policyMigration.Up)
	preferenceExec(t, ctx, pool, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('locale-tenant','locale-user','active',1); INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('locale-tenant','locale-user','password',1,'identity/password',1,true); CREATE TABLE preference_test_audits(command_id text,outcome text); CREATE TABLE preference_test_outbox(command_id text PRIMARY KEY)`)
	scope := authority.AuthorityScope{TenantID: "locale-tenant", SubjectID: "locale-user", PolicyNamespace: "users"}
	if _, err := authority.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	lookup, _ := session.NewDigestKey(1, []byte("11111111111111111111111111111111"))
	csrfKey, _ := session.NewCSRFKey(1, []byte("22222222222222222222222222222222"))
	csrfToken, _ := session.NewCSRFToken()
	csrf, _ := csrfToken.Digest(csrfKey, session.CSRFBinding{TenantID: "locale-tenant", SessionID: "locale-session", SessionVersion: 1})
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 15 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "locale-deployment", TenantID: "locale-tenant"}, "locale-user")
	sk, _ := sessionpg.SessionAuthorityKeys("locale-tenant", "locale-user", "locale-family", "locale-session")
	pk, _ := scope.Key()
	b := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
	vector, _ := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(keys.Global), Tenant: b(keys.Tenant), User: b(keys.User), Identifier: b(keys.Identifier), Credential: b(keys.Credential), SessionFamily: b(sk.Family), Session: b(sk.Session), Authorization: b(pk)})
	digest, _ := token.Digest(lookup, "locale-tenant")
	spec := session.SessionSpec{TenantID: "locale-tenant", UserID: "locale-user", SessionID: "locale-session", FamilyID: "locale-family", Audience: "locale-app", Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "locale-tenant", Subject: "locale-user", Purpose: "session-issue", Audience: "locale-app", Method: "password", Assurance: authentication.AssuranceSingleFactor, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}}
	record, err := session.NewSessionWithCSRF(spec, csrf)
	if err != nil {
		t.Fatal(err)
	}
	// Native primary fixtures use the session owner's documented closed stored
	// projection; all live admission still executes its real public reader.
	rp, _ := remember.Bindings()
	av, _ := vector.Bindings()
	cs, _ := csrf.Bindings()
	payload, err := json.Marshal(struct {
		Schema                   uint32
		SessionID, FamilyID      string
		TenantID                 identity.TenantID
		UserID                   identity.UserID
		Audience                 string
		Version, FamilyVersion   uint64
		Remember                 session.RememberPolicySpec
		Authority                session.AuthoritySnapshotSpec
		Lookup                   session.TokenDigest
		Authentication           session.AuthenticationMetadata
		IssuedAt, LastActivityAt time.Time
		CSRF                     *session.CSRFStateSpec
	}{2, spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID, spec.Audience, 1, 1, rp, av, digest, spec.Authentication, now, now, &cs})
	if err != nil {
		t.Fatal(err)
	}
	life, _ := record.Lifetime(now)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO locale_sessions.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES('locale-tenant','locale-family','locale-user',1,'active',$1);`, now.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO locale_sessions.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('locale-tenant','locale-session','locale-user','locale-family',1,1,'active',1,$1,$2,$3)`, digest.Sum[:], life.ExpiresAt.Format("2006-01-02T15:04:05.000000000Z"), payload); err != nil {
		t.Fatal(err)
	}
	policies := preferencePolicies(t, 1)
	c := PreferenceStoreConfig{Supported: []i18n.Locale{"en", "fi"}, CurrentNoticeVersion: 7, PolicyID: "locale-policy", PolicyVersion: 1, AuditRetentionVersion: 1, Authorization: policies, Clock: clock.System{}, CSRFKey: csrfKey, Audit: preferenceAudit{}, Lifecycle: preferenceLifecycle{}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 4 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Session: sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "locale_sessions", MaximumDuration: time.Second}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "locale-deployment", PolicyNamespace: "users", Audience: "locale-app", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "locale-app", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}}}
	return pool, c, PreferenceCredentials{Bearer: authentication.NewBearerCredential(wire), CSRF: csrfToken}
}

func preferencePolicies(t *testing.T, revision authorization.Revision) authorization.Service {
	t.Helper()
	model, err := rbac.New([]rbac.Role{{ID: "locale-self", Tenant: "locale-tenant"}}, []rbac.Permission{{ID: "locale-read", RoleID: "locale-self", Tenant: "locale-tenant", Action: "identity.i18n.get", ResourceType: "locale_preference", Effect: authorization.Allow}, {ID: "locale-write", RoleID: "locale-self", Tenant: "locale-tenant", Action: "identity.i18n.set", ResourceType: "locale_preference", Effect: authorization.Allow}, {ID: "locale-command-read", RoleID: "locale-self", Tenant: "locale-tenant", Action: "identity.i18n.set", ResourceType: "identity.user", Effect: authorization.Allow}}, []rbac.Assignment{{ID: "locale-user-role", Subject: authorization.Subject{ID: "locale-user", Kind: authorization.SubjectUser}, RoleID: "locale-self", Tenant: "locale-tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(revision, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "locale-policy", Evaluator: model})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policies, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	return policies
}

func preferenceAnotherSession(t *testing.T, ctx context.Context, pool *database.Pool, c PreferenceStoreConfig, original PreferenceCredentials, revokeOriginal bool) PreferenceCredentials {
	t.Helper()
	reader, err := sessionpg.NewSessionService(pool, c.Session)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseToken(original.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := reader.Get(ctx, session.GetRequest{TenantID: "locale-tenant", Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("original native session missing", err)
	}
	spec, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	spec.SessionID = "locale-new-session"
	spec.Lookup, err = token.Digest(c.Session.Validation.LookupKeys[0], string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := sessionpg.SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := spec.Authority.Bindings()
	vector.Session = session.AuthorityBinding{ScopeKey: keys.Session, Version: 1}
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	state, err := csrf.Digest(c.CSRFKey, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	newRecord, err := session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	var originalPayload []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record::text FROM locale_sessions.sessions WHERE session_id='locale-session'`).Scan(&originalPayload); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(originalPayload, &fields); err != nil {
		t.Fatal(err)
	}
	csrfSpec, _ := state.Bindings()
	for key, value := range map[string]any{"SessionID": spec.SessionID, "Lookup": spec.Lookup, "Authority": vector, "CSRF": csrfSpec} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		fields[key] = encoded
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, err := newRecord.Lifetime(c.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO locale_sessions.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8)`, string(spec.TenantID), spec.SessionID, string(spec.UserID), spec.FamilyID, int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], lifetime.ExpiresAt.Format("2006-01-02T15:04:05.000000000Z"), payload); err != nil {
		t.Fatal(err)
	}
	if revokeOriginal {
		preferenceExec(t, ctx, pool, `UPDATE locale_sessions.sessions SET state='revoked' WHERE session_id='locale-session'`)
	}
	return PreferenceCredentials{Bearer: authentication.NewBearerCredential(wire), CSRF: csrf}
}

func preferenceExec(t *testing.T, ctx context.Context, pool *database.Pool, sql string) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, sql); err != nil {
		t.Fatal("fixture SQL", err)
	}
}

type preferenceAudit struct{}

func (preferenceAudit) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}
func (preferenceAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	entries, err := w.StagedAudits()
	if err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		outcome := entry.Record.Attributes()["aggregate.after_version"]
		if _, err := strconv.ParseUint(outcome, 10, 64); err != nil {
			return err
		}
		class := "aborted"
		if entry.Record.Outcome() == audit.OutcomeSucceeded {
			class = "committed"
		}
		if _, err := w.Exec(ctx, `INSERT INTO preference_test_audits VALUES($1,$2)`, string(b.CommandID), class); err != nil {
			return err
		}
	}
	return nil
}
func (preferenceAudit) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return preferenceEvidence(ctx, w, "SELECT EXISTS(SELECT 1 FROM preference_test_audits WHERE command_id=$1)")
}

type preferenceLifecycle struct{ fail bool }

func (preferenceLifecycle) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (p preferenceLifecycle) PersistLifecycle(ctx context.Context, w kernel.Work) error {
	entries, err := w.StagedLifecycle()
	if err != nil || len(entries) != 1 {
		return identity.UnavailableError{}
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO preference_test_outbox VALUES($1)`, string(b.CommandID))
	if err == nil && p.fail {
		return identity.UnavailableError{}
	}
	return err
}
func (preferenceLifecycle) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return preferenceEvidence(ctx, w, "SELECT EXISTS(SELECT 1 FROM preference_test_outbox WHERE command_id=$1)")
}
func preferenceEvidence(ctx context.Context, w kernel.RecoveryWork, sql string) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, sql, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Scan(&exists); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}
