//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

type publicSendPolicy struct{}

func (publicSendPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

// SEND-01/02/05/06: the public workflow uses real kernel, domain, encrypted
// delivery, mandatory audit and lifecycle owners. Counter/source boundaries are
// explicit doubles; these assertions do not certify real Valkey or counter
// durability. The decision audit is a real PostgreSQL audit sink.
func TestPublicSendPostgresIssuanceSuppressionAndRestart(t *testing.T) {
	testPublicSendPostgres(t, false, false)
}

func TestPublicSendPreAuthUserChecks(t *testing.T) {
	testPublicSendPostgres(t, false, false, true)
}

func TestPublicSendPostgresMaximumSendsIsEnumerationSafe(t *testing.T) {
	testPublicSendPostgres(t, true, false)
}

func TestPublicSendPostgresLegacyPredecessorIsEnumerationSafe(t *testing.T) {
	testPublicSendPostgres(t, false, true)
}

func testPublicSendPostgres(t *testing.T, exhausted, legacy bool, preAuthUser ...bool) {
	ctx, db, _ := otpDatabase(t)
	store, original, _ := canonicalAuthenticationSendFixture(t)
	r, _, err := store.originalPreparedSend(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := r.continuation.Bindings()
	authorizationRecord, _ := cb.Authorization.AuthenticatedSession()
	s, _ := authorizationRecord.Bindings()
	directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"AAAAAAAAAAAAAAAAAAAAAQ"}}
	preparation := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
	keyed := kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 15}, Version: 16}
	for _, source := range []migrations.Source{preparation, directory, keyed, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, SendFamilyMigrationSource{Schema: "otp_store", Version: 102}, IssuanceMigrationSource{Schema: "otp_store", Version: 103}, sessionpg.MigrationSource{Schema: "session_store", Version: 200}, sessionpg.PreAuthMigrationSource{Schema: "session_store", Version: 201}, deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 250}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if m.Version() >= 10 {
				if legacy && m.Version() == 103 {
					// Populate the genuine prior schema, then apply the real
					// forward migration; never disable or bypass its guards.
					if _, err := db.Exec(ctx, `INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1')`); err != nil {
						t.Fatal(err)
					}
					for i, subject := range []string{"AAAAAAAAAAAAAAAAAAAAAg", ""} {
						issue := otpCommand(t, ctx, db, "AAAAAAAAAAAAAAAAAAAAAQ", byte(61+i))
						fp := bytes.Repeat([]byte{byte(61 + i)}, 32)
						if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=$2,lease_until=instant.now,heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now,result_version=1,terminal_class='committed',result=$2,terminal_at=instant.now FROM instant WHERE command_id=$1`, issue, issue); err != nil {
							t.Fatal(err)
						}
						if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) INSERT INTO otp_store.challenges(tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version) SELECT 'AAAAAAAAAAAAAAAAAAAAAQ',$1,$2,$5::text,$3,'identity.otp.send',$4,3,$4,$4,7,1,'0123456789',6,300000000,30000000,3,3,'replace',true,2,60000000,now,now+interval '5 minutes','issued',1 FROM instant`, "legacy-"+string(rune('a'+i)), subject, issue, fp, string(cb.Scope.Purpose)); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
					t.Fatal("owned migrations", err)
				}
			}
		}
	}
	// This cluster is disposable and the public test owns its fixed audit roles.
	var roleCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN('audit_writer','audit_reader','audit_retention')`).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if roleCount == 0 {
		if _, err := db.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
			t.Fatal(err)
		}
	} else if roleCount != 3 {
		t.Fatal("partial owned audit roles")
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		files, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			wire, err := fs.ReadFile(source, f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
				t.Fatal("native effects migration", err)
			}
		}
	}
	migration, err := authoritypg.AuthoritySchemaMigration(300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3;
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',7,4,5,6);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','credential',1,'identity/password',14,true);
INSERT INTO authorization_subject_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','users','AAAAAAAAAAAAAAAAAAAAAg',9)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'email','email',$3,true,true,9,2,3,$4)`, s.TenantID, s.UserID, cb.Scope.Destination.Value(), r.issuedAt); err != nil {
		t.Fatal(err)
	}
	remember, _ := s.Remember.Bindings()
	vector, _ := s.Authority.Bindings()
	payload, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": s.SessionID, "FamilyID": s.FamilyID, "TenantID": s.TenantID, "UserID": s.UserID, "Audience": s.Audience, "Version": s.Version, "FamilyVersion": s.FamilyVersion, "Remember": remember, "Authority": vector, "Lookup": s.Lookup, "Authentication": s.Authentication, "IssuedAt": s.IssuedAt, "LastActivityAt": s.LastActivityAt})
	if err != nil {
		t.Fatal(err)
	}
	lifetime, _ := authorizationRecord.Lifetime(s.LastActivityAt)
	const instant = "2006-01-02T15:04:05.000000000Z"
	if _, err := db.Exec(ctx, `INSERT INTO session_store.families VALUES($1,$2,$3,$4,'active',$5)`, s.TenantID, s.FamilyID, s.UserID, s.FamilyVersion, s.IssuedAt.Format(instant)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO session_store.sessions VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10::jsonb)`, s.TenantID, s.SessionID, s.UserID, s.FamilyID, s.Version, s.FamilyVersion, s.Lookup.KeyVersion, s.Lookup.Sum[:], lifetime.ExpiresAt.Format(instant), payload); err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"issue-envelope": bytes.Repeat([]byte{0x71}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("otp-public-test", [32]byte{0x41}, kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: publicSendPolicy{}, PolicyVersion: 9})
	if err != nil {
		t.Fatal(err)
	}
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = nil
	native.PreAuth = sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	native.PreAuthCookieKeys = map[uint32][]byte{3: bytes.Repeat([]byte{0x57}, 32)}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	riskConfig, calls := publicSendRisk(t, sink)
	config := SendConfig{Store: native.ContributorConfig, Codec: codecConfig(), Session: native.Session,
		Delivery:    deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {0x72}}, ActiveEnvelopeKeyID: "issue-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "test-sender", PolicyVersion: 1}}},
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 4 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, RequestKeys: requestKeys, Risk: riskConfig, Policy: store.send.policy, TemplateID: store.send.template, TemplateVersion: store.send.templateVersion, LocaleChain: store.send.locales, Templates: preparedSendTemplates("{{.code}}"), ProviderVersion: 1, PolicyID: "otp-policy", PolicyVersion: 7, PreAuthAction: "identity.otp.signin", IntentKey: [32]byte{0x67}, IdentifierKey: [32]byte{0x68}, Timeout: 3 * time.Second}
	service, err := NewSendService(pool, config, crypto)
	if err != nil {
		t.Fatal("public composition", err)
	}
	if err := service.Initialize(ctx); err != nil {
		t.Fatal("owned stable key registration", err)
	}
	bearer, _ := original.SessionToken()
	flow, err := otp.NewSessionSendFlow(s.SessionID, bearer)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.UserID)}, Tenant: authorization.TenantID(s.TenantID), Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}}}
	preAuthID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	preAuthBinding := session.PreAuthBinding{ID: preAuthID, Intent: session.PreAuthIntent{TenantID: s.TenantID, Action: config.PreAuthAction, Origin: "https://identity.example.invalid", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	cookieKey, err := session.NewDigestKey(3, bytes.Repeat([]byte{0x57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookieDigest, err := token.PreAuthDigest(cookieKey, preAuthBinding)
	if err != nil {
		t.Fatal(err)
	}
	preAuthRecord, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: preAuthBinding, Cookie: cookieDigest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	preAuthProfile, err := newPreAuthProfile(native.PreAuth, native.PreAuthCookieKeys)
	if err != nil {
		t.Fatal(err)
	}
	admissionInsert(t, ctx, db, preAuthProfile, preAuthRecord)
	preAuthFlow, err := otp.NewPreAuthSendFlow(preAuthID, bearer)
	if err != nil {
		t.Fatal(err)
	}
	expectedChallenges, expectedAudits, expectedLifecycle := 0, 0, 0
	var acceptedRequests []otp.SendRequest
	for _, anonymous := range []bool{false, true} {
		for _, suppressed := range []bool{false, true} {
			destination := cb.Scope.Destination
			if suppressed {
				destination, err = otp.NewDestinationInput("missing@example.invalid")
				if err != nil {
					t.Fatal(err)
				}
			}
			key, _ := identity.NewIdempotencyKey([]byte("eligible"))
			if suppressed {
				key, _ = identity.NewIdempotencyKey([]byte("suppressed"))
			}
			request := otp.SendRequest{TenantID: s.TenantID, UserID: s.UserID, Caller: caller, Flow: flow, Channel: otp.ChannelEmail, Destination: destination, Purpose: cb.Scope.Purpose, TargetID: cb.Scope.TargetID, Network: "192.0.2.8", Device: "public-device", IdempotencyKey: key}
			if len(preAuthUser) == 1 && preAuthUser[0] {
				request.Flow = preAuthFlow
			}
			if anonymous {
				request.UserID, request.Flow = "", preAuthFlow
				request.Caller = caller.Clone()
				request.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
				request.Caller.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAAAw"
			}
			if legacy {
				before := *calls
				denied, err := service.Send(ctx, request)
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) || denied.Outcome != identity.CommitOutcomeNotCommitted || *calls != before+1 {
					t.Errorf("legacy recipient-dependent result anonymous=%v suppressed=%v outcome=%v error=%T", anonymous, suppressed, denied.Outcome, err)
				}
				var effects int
				if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges WHERE send_family_digest IS NOT NULL)+(SELECT count(*) FROM identity.delivery_intents)`).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("legacy denial produced new protected effects", err)
				}
				continue
			}
			if exhausted {
				// Install valid populated historical state through the native
				// window writer with its monotonic guard still enabled. No sleeps,
				// allowance resets or disabled triggers are needed.
				scope := cb.Scope
				scope.SubjectID, scope.Destination = string(request.UserID), destination
				profile, _, err := config.Policy.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				query, exec := sqlChallengeQuery(tx), sqlChallengeExec(tx)
				lockout := service.owner.store.lockout
				if err := lockout.initializeSendFamily(ctx, query, exec, "otp_store", scope); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				var primaryNow time.Time
				if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primaryNow); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				for i := uint32(0); i < profile.MaximumSends; i++ {
					row, err := lockout.loadSendFamily(ctx, query, "otp_store", scope)
					if err != nil {
						_ = tx.Rollback(ctx)
						t.Fatal(err)
					}
					at := primaryNow.Add(-time.Duration(profile.MaximumSends-i)*profile.ResendInterval - time.Microsecond)
					if err := persistSendWindow(ctx, exec, row, mustIssueProfile(profile), at); err != nil {
						_ = tx.Rollback(ctx)
						t.Fatal(err)
					}
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				before := *calls
				denied, err := service.Send(ctx, request)
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) || denied.Outcome != identity.CommitOutcomeNotCommitted || *calls != before+1 {
					t.Fatalf("recipient-dependent send-cap result anonymous=%v suppressed=%v outcome=%v error=%T", anonymous, suppressed, denied.Outcome, err)
				}
				var effects int
				if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges)+(SELECT count(*) FROM identity.delivery_intents)`).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("exhausted family issued protected effects", err)
				}
				continue
			}
			result, err := service.Send(ctx, request)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" {
				t.Fatal("public Send did not accept", "anonymous", anonymous, "suppressed", suppressed, result, err, "counter calls", *calls)
			}
			acceptedRequests = append(acceptedRequests, request)
			var action, subjectType, subjectID, retention string
			if err := db.QueryRow(ctx, `SELECT r.action,r.subject_type,r.subject_id,convert_from(r.canonical_record,'UTF8')::jsonb->'attributes'->>'retention.class' FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE convert_from(r.canonical_record,'UTF8')::jsonb->'attributes'->>'command.id'=$1`, string(result.CommandID)).Scan(&action, &subjectType, &subjectID, &retention); err != nil {
				t.Fatal(err)
			}
			if action != "identity.otp.request" || retention != "standard" {
				t.Errorf("noncanonical public OTP audit action=%q retention=%q", action, retention)
			}
			if suppressed && anonymous && (subjectType != "authentication_attempt" || subjectID != string(preAuthID)) {
				t.Errorf("unknown-recipient audit subject type=%q matches preauth=%v", subjectType, subjectID == string(preAuthID))
			}
			counted := *calls
			var challenges, effects, audits, lifecycle int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM audit.records),(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&challenges, &effects, &audits, &lifecycle); err != nil {
				t.Fatal(err)
			}
			if !suppressed {
				expectedChallenges++
			}
			expectedAudits += 2
			expectedLifecycle++
			if challenges != expectedChallenges || effects != expectedChallenges || lifecycle != expectedLifecycle || audits != expectedAudits {
				t.Fatalf("non-atomic public effects anonymous=%v suppressed=%v challenge=%d delivery=%d audit=%d lifecycle=%d", anonymous, suppressed, challenges, effects, audits, lifecycle)
			}
			restarted, err := NewSendService(pool, config, crypto)
			if err != nil {
				t.Fatal(err)
			}
			again, err := restarted.Send(ctx, request)
			if err != nil || again != result || *calls != counted {
				t.Fatal("public replay refreshed or repeated original", err)
			}
			changed := request
			changed.Device = "changed-device"
			conflict, err := restarted.Send(ctx, changed)
			var conflictError identity.ConflictError
			if !errors.As(err, &conflictError) || conflict.Outcome != identity.CommitOutcomeConflict || *calls != counted {
				t.Fatal("changed intent did not conflict", err)
			}
			wrong := request
			wrongFlow, err := otp.NewSessionSendFlow(s.SessionID, auth.NewBearerCredential(strings.Repeat("A", 43)))
			if err != nil {
				t.Fatal(err)
			}
			if anonymous {
				wrongFlow, err = otp.NewPreAuthSendFlow(preAuthID, auth.NewBearerCredential(strings.Repeat("A", 43)))
				if err != nil {
					t.Fatal(err)
				}
			}
			wrong.Flow = wrongFlow
			if denied, err := restarted.Send(ctx, wrong); err == nil || denied.Outcome == identity.CommitOutcomeCommitted || *calls != counted {
				t.Fatal("wrong bearer recovered protected result")
			}
			// A fresh key cannot short-circuit at changed-intent conflict: the
			// submitted possession must deny before risk or protected effects.
			wrong.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("wrong-bearer-fresh"))
			if err != nil {
				t.Fatal(err)
			}
			if denied, err := restarted.Send(ctx, wrong); err == nil || denied.Outcome == identity.CommitOutcomeCommitted || *calls != counted {
				t.Fatal("fresh-key wrong possession reached risk or acceptance")
			}
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM audit.records),(SELECT count(*) FROM public.identity_outbox_bindings)`).Scan(&challenges, &effects, &audits, &lifecycle); err != nil {
				t.Fatal(err)
			}
			if challenges != expectedChallenges || effects != expectedChallenges || lifecycle != expectedLifecycle || audits != expectedAudits {
				t.Fatal("wrong possession changed protected effects")
			}
		}
	}
	if exhausted || legacy {
		return
	}
	// Under allowing risk, cooldown rejects fresh-key retries equivalently
	// for issued and absent recipients. The independent populated-state test
	// above proves maximum sends without changing the active history here.
	for index, request := range acceptedRequests {
		key := "fresh-cooldown"
		key += "." + string(rune('a'+index))
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		before := *calls
		denied, err := service.Send(ctx, request)
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || denied.Outcome != identity.CommitOutcomeNotCommitted || *calls != before+1 {
			t.Errorf("recipient-dependent cooldown result outcome=%v error=%T counted=%d", denied.Outcome, err, *calls-before)
		}
	}
	for _, request := range acceptedRequests {
		if request.Destination == cb.Scope.Destination {
			testPublicCheckAndRecovery(t, ctx, db, service, config, request)
		}
	}
}

func publicSendRisk(t *testing.T, sink audit.Sink) (risk.AuthenticationAdmissionCustodyConfig, *int) {
	t.Helper()
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for i := range profiles {
		profiles[i].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	calls := new(int)
	counter, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}, Clock: time.Now, Timeout: time.Second, Store: authenticationCounterStore(func(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		*calls++
		b := c.Bindings()
		if b.Operation != "identity.otp.send" || b.Tenant != "AAAAAAAAAAAAAAAAAAAAAQ" {
			t.Fatal("foreign public risk scope")
		}
		if _, err := identity.ParseCommandID(b.Attempt); err != nil {
			t.Fatal("not server command", err)
		}
		var snapshots []risk.Counter
		for _, target := range b.Targets {
			snapshots = append(snapshots, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
		}
		return risk.NewCounterResult(c, risk.CounterCommitted, snapshots)
	})})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counter, Clock: time.Now, Timeout: 5 * time.Second, Sources: []risk.Source{{Name: "status", Version: "status-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", Trust: risk.ServerVerified, State: risk.SignalClean, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
	}}}, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: "AAAAAAAAAAAAAAAAAAAAAQ", Timeout: time.Second, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }, Delivery: audit.RecorderConfig{Mode: audit.DeliveryFailClosed, Sink: sink}}})
	if err != nil {
		t.Fatal(err)
	}
	integrity, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "public-otp-v1", Keys: []risk.EvidenceKey{integrity}}, calls
}
