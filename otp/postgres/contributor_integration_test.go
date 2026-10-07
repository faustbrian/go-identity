//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Only audit persistence and the unexecuted owning feature are SQL seams.
// OTP cryptography, primary admission, counters and command replay are real
// production participants. This does not certify audit/outbox interoperability.
type contributorAudit struct{ fail bool }

// Receipt disclosure is a deliberate policy-service seam, not historical
// command scope conferring authority. The coordinator still validates scope.
type contributorQueryPolicy struct{}

func (contributorQueryPolicy) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
}

func (*contributorAudit) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}
func (*contributorAudit) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return contributorEvidence(ctx, w, "public.native_otp_audits")
}
func (a *contributorAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := w.Exec(ctx, `INSERT INTO public.native_otp_audits(event_id,command_id,outcome) VALUES($1,$2,$3)`, r.Record.ID(), r.Record.Attributes()["command.id"], strconv.Itoa(int(r.Record.Outcome()))); err != nil {
			return err
		}
	}
	if a.fail {
		return identity.UnavailableError{}
	}
	return nil
}

type contributorLifecycle struct{ apply bool }

func (*contributorLifecycle) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (*contributorLifecycle) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return contributorEvidence(ctx, w, "public.native_otp_lifecycle")
}
func (p *contributorLifecycle) PersistLifecycle(ctx context.Context, w kernel.Work) error {
	if !p.apply {
		return errors.New("denial executed lifecycle")
	}
	events, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, e := range events {
		if _, err = w.Exec(ctx, `INSERT INTO public.native_otp_lifecycle(command_id,event_id) VALUES($1,$2)`, string(e.CommandID), e.ID); err != nil {
			return err
		}
	}
	return nil
}

type contributorFeature struct {
	op    identity.FeatureOperation
	apply bool
	fail  bool
}

func (p *contributorFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: p.op.Owner + "/postgres", ContractID: strings.ReplaceAll(p.op.Owner, "/", "."), Version: 1}
}
func (p *contributorFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*contributorFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return contributorEvidence(ctx, w, "public.native_otp_domain")
}
func (p *contributorFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	s, ok := c.Feature()
	if !ok || s.Operation != p.op {
		return identity.InvalidInputError{Field: "feature"}
	}
	return nil
}
func (p *contributorFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.apply {
		return identity.FeatureReceipt{}, errors.New("denial executed feature")
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	if _, err := w.Exec(ctx, `INSERT INTO public.native_otp_domain(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}

// Domain/audit/outbox remain test SQL seams, not email/session implementations.
func contributorEvidence(ctx context.Context, w kernel.RecoveryWork, table string) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

func contributorCommand(t *testing.T, now time.Time, submitted string, profile ...string) (*Contributor, identity.Command, kernel.OTPAttemptPlan, session.PreAuthTransaction, otp.AttemptCommand) {
	t.Helper()
	c, old, plan, original, wire := admissionFixture(t, now)
	prior, err := c.restoreAttempt(old, plan)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := prior.Bindings()
	cb, _ := ab.Continuation.Bindings()
	spec, _ := old.Feature()
	spec.Operation.Owner, spec.Operation.OperationID, spec.Operation.SchemaID = "identity/session", "identity.session.issue", "identity-session-issue"
	if len(profile) > 0 && strings.HasPrefix(profile[0], "native-") {
		// The separate sign-in-proof/session-issuance profile is deliberately
		// closed to generic OTP reservation. Exercise protected email ownership,
		// not a bypass of that authenticated entry point.
		spec.Operation.Owner, spec.Operation.OperationID, spec.Operation.SchemaID = "identity/email", "identity.email.verify", "identity-email-verify"
		cb.Scope.Purpose, cb.RememberPolicy = otp.PurposeEmailVerification, session.RememberPolicy{}
	}
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = []identity.FeatureField{{Name: "feature.flag", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}
	originalAuthority := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3}}
	if len(profile) != 0 && (strings.HasPrefix(profile[0], "user-") || strings.Contains(profile[0], "credential-")) {
		spec.Binding.UserID, spec.Binding.AnonymousFlowID = "user", ""
		spec.Operation.SubjectRequirement = identity.FeatureSubjectUser
		cb.Scope.SubjectID = "user"
		originalAuthority.UserAuthorityVersion, originalAuthority.IdentifierAuthorityVersion, originalAuthority.CredentialAuthorityVersion = 11, 13, 17
		originalAuthority.UserAuthorization = kernel.UserAuthorizationAdmission{Scope: authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, Version: 1}
		if strings.Contains(profile[0], "credential-") {
			originalAuthority.Credential = identity.CredentialRef{ID: "ref", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}
		}
	}
	rb, _ := original.Bindings()
	rb.Binding.Intent.Action = spec.Operation.OperationID
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	digest, err := token.PreAuthDigest(key, rb.Binding)
	if err != nil {
		t.Fatal(err)
	}
	original, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: rb.Binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundPreAuthAuthorization(original)
	if err != nil {
		t.Fatal(err)
	}
	cb.Scope.AuthorizationBinding = [32]byte{}
	continuation, err := otp.NewContinuation(cb.Scope, flow, cb.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode(submitted)
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	a, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	command, plan, err := c.MapPreAuthWithAuthority(context.Background(), a, 3, spec, auth.NewBearerCredential(wire), originalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewContributor(ContributorConfig{Schema: "otp_store", Codec: c, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return p, command, plan, original, a
}

func contributorPlan(t *testing.T, r *kernel.ContributorRegistry, command identity.Command, attempt kernel.OTPAttemptPlan) kernel.CommandPlan {
	t.Helper()
	s, _ := command.Feature()
	b := s.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "session.issue", Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := kernel.FeatureAuditBindingDigest(b, s.Operation, "session", record)
	if err != nil {
		t.Fatal(err)
	}
	f := r.FeatureOperations()[0]
	return kernel.CommandPlan{Feature: &f, SubjectType: "session", Contributors: r.Descriptors(), OTP: &attempt, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "session.issue", SchemaVersion: 1, BindingDigest: d, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true, RetentionClass: "protected"}}}
}

func TestContributorNativeDenialComposition(t *testing.T) {
	for _, mode := range []string{"native-reserve", "native-consume", "native-takeover", "native-rollback", "native-stale-directory", "native-flow-lock-expiry", "native-credential-lock-expiry", "native-recovery", "native-recovery-unknown", "wrong-replay", "correct-rollback", "audit-rollback", "stale-directory", "missing-flow", "expired-flow", "flow-lock-expiry", "exhaustion", "user-valid", "user-blocked", "user-epoch", "user-identifier-epoch", "user-credential-epoch", "user-authorization-epoch", "credential-valid", "credential-stale", "credential-disabled", "credential-lock-expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer, preauth := admissionDatabase(t)
			base := kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}
			credentials := kernel.CredentialMigrationSource{Base: base, Version: 13}
			directory := kernel.DirectoryAuthorityMigrationSource{Base: credentials, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
			for index, source := range []migrations.Source{directory, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, ConsumingMigrationSource{Schema: "otp_store", Version: 102}, sessionpg.PreAuthReleaseMigrationSource{Schema: "session_store", Version: 202}} {
				h, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range h {
					if index == 0 && m.Version() < 12 {
						continue
					}
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3; INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1'); CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL); CREATE TABLE public.native_otp_domain(command_id text PRIMARY KEY); CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			code := "654321"
			if mode == "correct-rollback" || strings.HasPrefix(mode, "native-") {
				code = "123456"
			}
			p, command, attempt, flow, a := contributorCommand(t, now.Add(-time.Second), code, mode)
			if mode == "native-flow-lock-expiry" {
				p, command, attempt, flow, a = contributorCommand(t, now.Add(-5*time.Minute+time.Second), code, mode)
			}
			if mode == "flow-lock-expiry" {
				p, command, attempt, flow, a = contributorCommand(t, now.Add(-5*time.Minute+time.Second), code)
			}
			if strings.HasPrefix(mode, "user-") || strings.Contains(mode, "credential-") {
				m, err := authoritypg.AuthoritySchemaMigration(300)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(ctx, m.Up); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','user','active',101,11,13,17)`); err != nil {
					t.Fatal(err)
				}
				tx := admissionBegin(t, ctx, db)
				if _, err := authoritypg.InitializeAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, time.Second); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(mode, "credential-") {
					if _, err := db.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','user','ref',1,'identity/password',7,true)`); err != nil {
						t.Fatal(err)
					}
				}
				change := map[string]string{
					"user-blocked":          `UPDATE identity.users SET status='banned'`,
					"user-epoch":            `UPDATE identity.users SET authority_version=12`,
					"user-identifier-epoch": `UPDATE identity.users SET identifier_version=14`,
					"user-credential-epoch": `UPDATE identity.users SET credential_version=18`,
					"credential-stale":      `UPDATE identity.credential_references SET version=8`,
					"credential-disabled":   `UPDATE identity.credential_references SET enabled=false`,
				}[mode]
				if change != "" {
					if _, err := db.Exec(ctx, change); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "user-authorization-epoch" {
					tx := admissionBegin(t, ctx, db)
					if _, err := authoritypg.AdvanceAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, 1, time.Second); err != nil {
						t.Fatal(err)
					}
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
			}
			admissionInsert(t, ctx, db, preauth, flow)
			if mode == "missing-flow" {
				if _, err := db.Exec(ctx, `DELETE FROM session_store.preauth_transactions`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "expired-flow" {
				// Preserve coherent canonical intent; submit original custody for an
				// already-expired original flow, rather than corrupting storage.
				if _, err := db.Exec(ctx, `DELETE FROM session_store.preauth_transactions`); err != nil {
					t.Fatal(err)
				}
				p, command, attempt, flow, a = contributorCommand(t, now.Add(-6*time.Minute), code)
				admissionInsert(t, ctx, db, preauth, flow)
			}
			keyBinding := p.lockout.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, keyBinding[:]); err != nil {
				t.Fatal(err)
			}
			ab, _ := a.Bindings()
			cb, _ := ab.Continuation.Bindings()
			tx := admissionBegin(t, ctx, db)
			if err := p.lockout.initializeLockouts(ctx, sqlChallengeQuery(tx.Tx), sqlChallengeExec(tx.Tx), "otp_store", cb.Scope); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			scope, _ := ab.Continuation.DigestScope()
			good, _ := auth.NewOneTimeCode("123456")
			// Digest must use the original selected key, not the codec current key.
			v, _ := otp.NewVerifier(3, codecConfig().CodeKeys)
			digest, _ := v.Digest(scope, good)
			stored := digest.Storage()
			sd, _ := v.ScopeDigest(scope, 3)
			issue := otpCommand(t, ctx, db, "tenant", 77)
			if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=$2,lease_until=instant.now,heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now,result_version=1,terminal_class='committed',result=$2,terminal_at=instant.now FROM instant WHERE command_id=$1`, issue, bytes.Repeat([]byte{77}, 16)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.challenges(tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version) VALUES('tenant','challenge',$6,$7,$1,'identity.otp.send',$2,3,$3,$4,11,12,'0123456789',6,60000000,30000000,3,3,'retain',true,2,60000000,$5::timestamptz,$5::timestamptz+interval '60 seconds','issued',1)`, issue, bytes.Repeat([]byte{77}, 32), stored.Value[:], sd.Value[:], now, cb.Scope.SubjectID, string(cb.Scope.Purpose)); err != nil {
				t.Fatal(err)
			}
			if mode == "stale-directory" {
				if _, err := db.Exec(ctx, `UPDATE identity.tenant_authorities SET version=4`); err != nil {
					t.Fatal(err)
				}
			}
			pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			spec, _ := command.Feature()
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{fail: mode == "audit-rollback"}, &contributorLifecycle{apply: strings.HasPrefix(mode, "native-")}, &contributorFeature{op: spec.Operation, apply: strings.HasPrefix(mode, "native-"), fail: mode == "native-rollback"}, p})
			if err != nil {
				t.Fatal(err)
			}
			lease := time.Second
			if mode == "native-credential-lock-expiry" {
				// Cross credential expiry without also expiring journal ownership;
				// lease loss correctly retains ambiguous custody instead of release.
				lease = 3 * time.Second
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: lease, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareOTPAttemptPlan(spec.Binding, command, contributorPlan(t, registry, command, attempt))
			if err != nil {
				t.Fatal("prepare", err)
			}
			if strings.HasPrefix(mode, "native-") {
				plan, err = coordinator.PrepareOTPReservationPlan(spec.Binding, command, contributorPlan(t, registry, command, attempt))
				if err != nil {
					t.Fatal("native consuming preparation", err)
				}
				probe, probeErr := coordinator.PrepareOTPReservationPlan(spec.Binding, command, plan)
				if probeErr != nil || probe.Digest != plan.Digest {
					t.Fatal("prepared reservation changed before SQL", probeErr)
				}
				if mode == "native-flow-lock-expiry" {
					blocker, err := peer.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer blocker.Rollback(context.Background())
					if _, err := blocker.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges FOR UPDATE`); err != nil {
						t.Fatal(err)
					}
					waitConsumingExpiry(t, ctx, db, now.Add(time.Second), func(run context.Context) error {
						_, _, err := coordinator.ReserveOTPCommand(run, spec.Binding, command, plan)
						return err
					}, func() error { return blocker.Rollback(ctx) })
					var state, flowState string
					var used, failed int
					if err := db.QueryRow(ctx, `SELECT state,used_attempts,failed_attempts FROM otp_store.challenges`).Scan(&state, &used, &failed); err != nil {
						t.Fatal(err)
					}
					if err := db.QueryRow(ctx, `SELECT state FROM session_store.preauth_transactions`).Scan(&flowState); err != nil {
						t.Fatal(err)
					}
					if state != "issued" || flowState != "issued" || used != 0 || failed != 0 {
						t.Fatal("expired reservation leaked prefix", state, flowState, used, failed)
					}
					return
				}
				reservation, _, reserveErr := coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
				err = reserveErr
				if err != nil {
					var invalid identity.InvalidInputError
					if errors.As(err, &invalid) {
						t.Fatal("native reserve", invalid.Field)
					}
					t.Fatal("native reserve", err)
				}
				var state, flowState string
				var used, failed, version int
				if err := db.QueryRow(ctx, `SELECT state,used_attempts,failed_attempts,version FROM otp_store.challenges`).Scan(&state, &used, &failed, &version); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(ctx, `SELECT state FROM session_store.preauth_transactions`).Scan(&flowState); err != nil {
					t.Fatal(err)
				}
				if state != "reserved" || flowState != "reserved" || used != 1 || failed != 0 || version != 2 {
					t.Fatalf("native atomic reservation: otp=%s flow=%s used=%d failed=%d version=%d", state, flowState, used, failed, version)
				}
				assertOriginalCustodyImmutable(t, ctx, db)
				// Live replay must neither consume another attempt nor replace the
				// original encrypted custody or reservation timeline.
				var originalWire []byte
				var originalReservedAt time.Time
				if err := db.QueryRow(ctx, `SELECT consumer_envelope,reserved_at FROM otp_store.challenges`).Scan(&originalWire, &originalReservedAt); err != nil {
					t.Fatal(err)
				}
				_, replay, err := coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("native live replay", err)
				}
				if mode == "native-takeover" {
					id, err := base64.RawURLEncoding.Strict().DecodeString(string(spec.Binding.CommandID))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
						t.Fatal(err)
					}
					previous := reservation
					reservation, _, err = coordinator.ReserveOTPCommand(ctx, spec.Binding, command, plan)
					if err != nil {
						t.Fatal("native exact takeover", err)
					}
					if stale, err := coordinator.Begin(ctx, previous); err == nil {
						coordinator.Abort(stale, identity.UnavailableError{})
						t.Fatal("previous reservation retained authority")
					}
				}
				var retainedWire []byte
				var retainedReservedAt time.Time
				var generation int
				if err := db.QueryRow(ctx, `SELECT consumer_envelope,reserved_at,used_attempts,failed_attempts,consumer_generation FROM otp_store.challenges`).Scan(&retainedWire, &retainedReservedAt, &used, &failed, &generation); err != nil {
					t.Fatal(err)
				}
				wantGeneration := 1
				if mode == "native-takeover" {
					wantGeneration = 2
				}
				if !bytes.Equal(originalWire, retainedWire) || !originalReservedAt.Equal(retainedReservedAt) || used != 1 || failed != 0 || generation != wantGeneration {
					t.Fatal("replay/takeover changed original custody, timeline or charge")
				}
				if err := db.QueryRow(ctx, `SELECT generation FROM session_store.preauth_transactions`).Scan(&generation); err != nil || generation != wantGeneration {
					t.Fatal("OTP and pre-auth generations diverged", err)
				}
				if mode == "native-stale-directory" {
					if _, err := db.Exec(ctx, `UPDATE identity.tenant_authorities SET version=4`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "native-rollback" || mode == "native-stale-directory" || mode == "native-credential-lock-expiry" {
					work, err := coordinator.Begin(ctx, reservation)
					if err != nil {
						t.Fatal("rollback begin", err)
					}
					defer coordinator.Abort(work, identity.UnavailableError{})
					var cause error
					if mode == "native-credential-lock-expiry" {
						var deadline time.Time
						if err := db.QueryRow(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '1 second' RETURNING expires_at`).Scan(&deadline); err != nil {
							t.Fatal(err)
						}
						blocker, err := peer.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer blocker.Rollback(context.Background())
						if _, err := blocker.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges FOR UPDATE`); err != nil {
							t.Fatal(err)
						}
						waitConsumingExpiry(t, ctx, db, deadline, func(run context.Context) error {
							_, cause = coordinator.ApplyFeature(run, work, command)
							return cause
						}, func() error { return blocker.Rollback(ctx) })
					} else {
						_, cause = coordinator.ApplyFeature(ctx, work, command)
					}
					if cause == nil {
						t.Fatal("protected failure was ignored")
					}
					result, err := coordinator.Abort(work, cause)
					if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("proven rollback not terminalized", err, result.Outcome)
					}
					var journal string
					var domains, audits, events int
					id, _ := base64.RawURLEncoding.Strict().DecodeString(string(spec.Binding.CommandID))
					if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions),(SELECT state FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM public.native_otp_audits),(SELECT count(*) FROM public.native_otp_lifecycle)`, id).Scan(&state, &flowState, &journal, &domains, &audits, &events); err != nil {
						t.Fatal(err)
					}
					if state != "released" || flowState != "released" || journal != "aborted" || domains != 0 || audits != 1 || events != 0 {
						t.Fatal("protected rollback escaped or stranded custody", state, flowState, journal, domains, audits, events)
					}
				}
				if strings.HasPrefix(mode, "native-recovery") {
					id, _ := base64.RawURLEncoding.Strict().DecodeString(string(spec.Binding.CommandID))
					if _, err := db.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
						t.Fatal(err)
					}
					if mode == "native-recovery-unknown" {
						if _, err := db.Exec(ctx, `UPDATE session_store.preauth_transactions SET generation=99`); err != nil {
							t.Fatal(err)
						}
					}
					// Construct a new participant/coordinator from deployment config
					// only. Recovery receives no command, submitted code or cookie.
					freshCodec, err := NewAttemptCodec(codecConfig())
					if err != nil {
						t.Fatal(err)
					}
					fresh, err := NewContributor(ContributorConfig{Schema: "otp_store", Codec: freshCodec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}})
					if err != nil {
						t.Fatal(err)
					}
					restartedRegistry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &contributorLifecycle{apply: true}, &contributorFeature{op: spec.Operation, apply: true}, fresh})
					if err != nil {
						t.Fatal(err)
					}
					restarted, err := kernel.NewCoordinator(pool, restartedRegistry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: contributorQueryPolicy{}}})
					if err != nil {
						t.Fatal(err)
					}
					b := spec.Binding
					query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
					caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
					command, reservation = identity.Command{}, kernel.Reservation{}
					observed, recoverErr := restarted.RecoverFeatureCommand(ctx, query, caller)
					want := identity.CommitOutcomeNotCommitted
					if mode == "native-recovery-unknown" {
						want = identity.CommitOutcomeInProgress
					}
					if recoverErr == nil || observed.Outcome != want {
						t.Fatal("restart recovery classification", recoverErr, observed.Outcome)
					}
					var journal string
					var domains, audits, events int
					if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions),(SELECT state FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM public.native_otp_audits),(SELECT count(*) FROM public.native_otp_lifecycle)`, id).Scan(&state, &flowState, &journal, &domains, &audits, &events); err != nil {
						t.Fatal(err)
					}
					if mode == "native-recovery-unknown" {
						if state != "reserved" || flowState != "reserved" || journal != "pending" || domains != 0 || audits != 0 || events != 0 {
							t.Fatal("unknown recovery released custody", state, flowState, journal, domains, audits, events)
						}
					} else if state != "released" || flowState != "released" || journal != "aborted" || domains != 0 || audits != 1 || events != 0 {
						t.Fatal("proven restart rollback not atomic", state, flowState, journal, domains, audits, events)
					}
				}
				if mode == "native-consume" || mode == "native-takeover" {
					work, err := coordinator.Begin(ctx, reservation)
					if err != nil {
						t.Fatal("native protected begin", err)
					}
					defer coordinator.Abort(work, identity.UnavailableError{})
					result, err := coordinator.ApplyFeature(ctx, work, command)
					if err != nil {
						t.Fatal("native protected apply", err)
					}
					if _, err = coordinator.Commit(work, result); err != nil {
						t.Fatal("native protected commit", err)
					}
					if err := db.QueryRow(ctx, `SELECT state FROM otp_store.challenges`).Scan(&state); err != nil {
						t.Fatal(err)
					}
					if err := db.QueryRow(ctx, `SELECT state FROM session_store.preauth_transactions`).Scan(&flowState); err != nil {
						t.Fatal(err)
					}
					if state != "finalized" || flowState != "consumed" {
						t.Fatal("native atomic finalization", state, flowState)
					}
					// Durable custody remains immutable even after protected
					// terminalization, not merely because application code preserves it.
					assertOriginalCustodyImmutable(t, ctx, db)
					var domains, audits, events int
					if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM public.native_otp_audits WHERE outcome=$1),(SELECT count(*) FROM public.native_otp_lifecycle)`, strconv.Itoa(int(audit.OutcomeSucceeded))).Scan(&domains, &audits, &events); err != nil {
						t.Fatal(err)
					}
					if domains != 1 || audits != 1 || events != 1 {
						t.Fatal("protected commit omitted domain, audit or lifecycle", domains, audits, events)
					}
				}
				return
			}
			var result identity.CommandResult
			if mode == "flow-lock-expiry" || mode == "credential-lock-expiry" {
				deadline := now.Add(time.Second)
				if mode == "credential-lock-expiry" {
					if _, err := db.Exec(ctx, `UPDATE identity.credential_references SET expires_at=$1`, deadline); err != nil {
						t.Fatal(err)
					}
				}
				blocker, lockErr := peer.Begin(ctx)
				if lockErr != nil {
					t.Fatal(lockErr)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_ = blocker.Rollback(cleanup)
				})
				if _, err := blocker.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges WHERE challenge_id='challenge' FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				type outcome struct {
					result identity.CommandResult
					err    error
				}
				done := make(chan outcome, 1)
				runCtx, stopRun := context.WithCancel(ctx)
				joined := false
				t.Cleanup(func() {
					stopRun()
					if !joined {
						select {
						case <-done:
						case <-time.After(3 * time.Second):
							t.Error("native denial goroutine did not stop")
						}
					}
				})
				go func() {
					r, e := coordinator.RecordOTPAttemptDenial(runCtx, spec.Binding, command, plan)
					done <- outcome{r, e}
				}()
				// Prove the submission reached the locked challenge before expiry;
				// polling alone does not infer phase progress from elapsed time.
				wait := time.NewTicker(5 * time.Millisecond)
				defer wait.Stop()
				observed := false
				for !observed {
					if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%otp_store%challenges%FOR UPDATE%')`).Scan(&observed); err != nil {
						t.Fatal(err)
					}
					if observed {
						break
					}
					select {
					case <-wait.C:
					case out := <-done:
						joined = true
						t.Fatalf("submission did not reach challenge lock: %v %v", out.result.Outcome, out.err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				for {
					var instant time.Time
					if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&instant); err != nil {
						t.Fatal(err)
					}
					if !instant.Before(deadline) {
						break
					}
					select {
					case <-wait.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				if err := blocker.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case out := <-done:
					joined = true
					result, err = out.result, out.err
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			} else {
				result, err = coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
			}
			if err == nil {
				t.Fatal("denial granted successful authentication")
			}
			if mode == "wrong-replay" {
				var denied identity.ForbiddenError
				if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &denied) {
					t.Fatal("wrong attempt not durably denied", result.Outcome, err)
				}
				// Historical denial must not read or compare the current challenge.
				if _, err := db.Exec(ctx, `UPDATE identity.tenant_authorities SET enabled=false`); err != nil {
					t.Fatal(err)
				}
				result, err = coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
				if result.Outcome != identity.CommitOutcomeNotCommitted || err != nil {
					t.Fatal("stable replay lost", result.Outcome, err)
				}
			}
			if mode == "exhaustion" {
				for version := uint64(2); version <= 3; version++ {
					ab, _ := a.Bindings()
					spec, _ = command.Feature()
					spec.Binding.CommandID, err = identity.NewCommandID()
					if err != nil {
						t.Fatal(err)
					}
					spec.Fields = []identity.FeatureField{{Name: "feature.flag", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}}
					issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
					wrong, _ := auth.NewOneTimeCode("654321")
					a, err = issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, ab.Continuation, otp.AttemptModeConsume, version, wrong)
					if err != nil {
						t.Fatal(err)
					}
					cookie, _ := command.PreAuthCookie()
					command, attempt, err = p.codec.MapPreAuthWithAuthority(ctx, a, 3, spec, cookie, AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3}})
					if err != nil {
						t.Fatal(err)
					}
					plan, err = coordinator.PrepareOTPAttemptPlan(spec.Binding, command, contributorPlan(t, registry, command, attempt))
					if err != nil {
						t.Fatal(err)
					}
					result, err = coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
					var denied identity.ForbiddenError
					if result.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, &denied) {
						t.Fatal("exhaustion not committed", version, result.Outcome, err)
					}
				}
				var locked bool
				if err := db.QueryRow(ctx, `SELECT bool_and(blocked_until>clock_timestamp()) FROM otp_store.lockouts`).Scan(&locked); err != nil || !locked {
					t.Fatal("exhaustion did not lock shared destination", err)
				}
			}
			var used, failed, version, audits int
			if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,version FROM otp_store.challenges WHERE challenge_id='challenge'`).Scan(&used, &failed, &version); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(ctx, `SELECT count(*) FROM public.native_otp_audits`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "wrong-replay" || mode == "user-valid" || mode == "credential-valid" {
				want = 1
			}
			if mode == "exhaustion" {
				want = 3
			}
			if used != want || failed != want || version != 1+want || audits != want {
				t.Fatalf("charge/receipt atomicity: used=%d failed=%d version=%d audits=%d", used, failed, version, audits)
			}
			var state string
			if err := db.QueryRow(ctx, `SELECT state FROM otp_store.challenges WHERE challenge_id='challenge'`).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if mode == "exhaustion" && state != "exhausted" || mode != "exhaustion" && state != "issued" {
				t.Fatal("challenge transition", state)
			}
			if mode != "exhaustion" {
				var extended int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM otp_store.lockouts WHERE blocked_until IS NOT NULL`).Scan(&extended); err != nil {
					t.Fatal(err)
				}
				if extended != 0 {
					t.Fatal("failed admission/ordinary denial extended lockout", extended)
				}
				id, _ := base64.RawURLEncoding.DecodeString(string(spec.Binding.CommandID))
				var journals int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1 AND state='aborted'`, id).Scan(&journals); err != nil {
					t.Fatal(err)
				}
				if journals != want {
					t.Fatal("denial receipt not atomic", journals, want)
				}
			}
		})
	}
}
