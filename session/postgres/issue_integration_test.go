//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	policyStore "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"io/fs"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type issueProofSource struct {
	record authentication.SignedSignInRecord
}

func (*issueProofSource) CurrentValidity(context.Context, authentication.ValidityRequest) (authentication.SignedValidityEvidence, error) {
	return authentication.SignedValidityEvidence{}, errors.New("unused")
}
func (*issueProofSource) PermanentAuthentication(context.Context, authentication.ProofID) (authentication.SignedAuthenticationRecord, error) {
	return authentication.SignedAuthenticationRecord{}, errors.New("unused")
}
func (s *issueProofSource) SignInAuthentication(context.Context, authentication.ProofID) (authentication.SignedSignInRecord, error) {
	return s.record, nil
}

func testNativeIssueIntegration(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('issue','issue-user','active',1);INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('issue','issue-user','password',1,'identity/password',1,true)`); err != nil {
		t.Fatal(err)
	}
	scope := policyStore.AuthorityScope{TenantID: "issue", PolicyNamespace: "users", SubjectID: "issue-user"}
	if _, err := policyStore.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := &issueProofSource{}
	authority, err := authentication.NewAuthorityAuthenticator(authentication.AuthorityConfig{Issuer: "issuer", Environment: "test", Audience: "service-a", Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []authentication.AuthorityKey{{ID: "key", PublicKey: public}}, EvidenceKeys: []authentication.AuthorityKey{{ID: "key", PublicKey: public}}, Source: source, Clock: clock.System{}, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := authentication.AuthenticatedProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	native, err := NewRepositoryWithIssueAdmission(pool, Config{Schema: "session_store", MaximumDuration: time.Second}, IssueAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, outbox := &revokeAudit{}, &revokeOutbox{}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditing, outbox, native})
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, FinalAuthentication: &kernel.FinalAuthenticationConfig{Authority: authority, Namespace: "native-session"}})
	if err != nil {
		t.Fatal(err)
	}
	type inputs struct {
		binding identity.CommandBinding
		command identity.Command
		plan    kernel.CommandPlan
		proof   authentication.AuthenticatedProof
		record  session.Session
	}
	prepare := func(t *testing.T) inputs {
		t.Helper()
		now := time.Now().UTC()
		s, _ := testSession(t).Bindings()
		sessionID, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		familyID, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		proofID, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		s.SessionID, s.FamilyID, s.TenantID, s.UserID, s.Version, s.FamilyVersion = string(sessionID), string(familyID), "issue", "issue-user", 1, 1
		s.IssuedAt, s.LastActivityAt = now, now
		s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: authentication.ProofID(proofID), Tenant: "issue", Subject: "issue-user", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "service-a", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
		_, e = rand.Read(s.Lookup.Sum[:])
		if e != nil {
			t.Fatal(e)
		}
		keys, e := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-issue", TenantID: "issue"}, "issue-user")
		if e != nil {
			t.Fatal(e)
		}
		sessionKeys, e := SessionAuthorityKeys("issue", "issue-user", s.FamilyID, s.SessionID)
		if e != nil {
			t.Fatal(e)
		}
		policyKey, e := scope.Key()
		if e != nil {
			t.Fatal(e)
		}
		b := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
		s.Authority, e = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(keys.Global), Tenant: b(keys.Tenant), User: b(keys.User), Identifier: b(keys.Identifier), Credential: b(keys.Credential), SessionFamily: b(sessionKeys.Family), Session: b(sessionKeys.Session), Authorization: b(policyKey)})
		if e != nil {
			t.Fatal(e)
		}
		record, e := session.NewSession(s)
		if e != nil {
			t.Fatal(e)
		}
		signed := authentication.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: authentication.SignInStateAuthenticated, Proof: s.Authentication.Proof, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1, KeyID: "key"}
		frame, e := signed.SigningBytes()
		if e != nil {
			t.Fatal(e)
		}
		signed.Signature = ed25519.Sign(private, frame)
		source.record = signed
		proof, e := issuer.IssueAuthenticatedProof(ctx, s.Authentication.Proof)
		if e != nil {
			t.Fatal(e)
		}
		binding := revokeBinding()
		binding.TenantID, binding.UserID, binding.ActorID, binding.OperationID, binding.SchemaID, binding.RecordID = "issue", "issue-user", "issue-user", "identity.session.issue", "session-issue", s.SessionID
		binding.CommandID, e = identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		cmd, e := session.NewIssueCommand(binding, record)
		if e != nil {
			t.Fatal(e)
		}
		mapped, e := MapCommand(cmd)
		if e != nil {
			t.Fatal(e)
		}
		builder, e := audit.NewBuilder(audit.BuilderConfig{})
		if e != nil {
			t.Fatal(e)
		}
		seed, e := builder.Build(audit.RecordInput{OccurredAt: now, Action: "identity.session.create", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: s.SessionID}, Context: audit.ContextInput{TenantID: "issue", CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(binding.CommandID), "aggregate.type": "session", "aggregate.id": s.SessionID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "standard"}})
		if e != nil {
			t.Fatal(e)
		}
		digest, e := kernel.FeatureAuditBindingDigest(binding, session.IssueOperation(), "session", seed)
		if e != nil {
			t.Fatal(e)
		}
		plan, e := c.PrepareAuthenticatedCommandPlan(binding, mapped, proof, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: native.Descriptor(), Operation: session.IssueOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.create", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
		if e != nil {
			t.Fatal(e)
		}
		return inputs{binding, mapped, plan, proof, record}
	}
	execute := func(t *testing.T, in inputs) (identity.CommandResult, error) {
		t.Helper()
		r, result, e := c.ReserveAuthenticatedCommand(ctx, in.binding, in.command, in.proof, in.plan)
		if e != nil || result.Outcome != identity.CommitOutcomeInProgress {
			return result, e
		}
		w, e := c.Begin(ctx, r)
		if e != nil {
			return result, e
		}
		defer c.Abort(w, identity.UnavailableError{})
		result, e = c.ApplyFeature(ctx, w, in.command)
		if e != nil {
			return c.Abort(w, e)
		}
		return c.Commit(w, result)
	}
	counts := func(t *testing.T, in inputs, wantSession, wantFamily, wantProof, wantEvidence int) {
		t.Helper()
		spec, _ := in.record.Bindings()
		var a, b, d, e int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id='issue' AND session_id=$1),(SELECT count(*) FROM session_store.families WHERE tenant_id='issue' AND family_id=$2),(SELECT count(*) FROM identity.signin_proof_uses WHERE command_id=$3),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$3)`, spec.SessionID, spec.FamilyID, mustCommandBytes(t, in.binding.CommandID)).Scan(&a, &b, &d, &e)
		if err != nil || a != wantSession || b != wantFamily || d != wantProof || e != wantEvidence {
			t.Fatalf("atomic native rows %d/%d/%d/%d: %v", a, b, d, e, err)
		}
	}
	in := prepare(t)
	result, err := execute(t, in)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native issue commit", err, result.Outcome)
	}
	counts(t, in, 1, 1, 1, 1)
	spec, _ := in.record.Bindings()
	got, err := native.Get(ctx, "issue", spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	original, _, _ := encodeRecord(in.record)
	restored, _, _ := encodeRecord(got.Session)
	if string(original) != string(restored) {
		t.Fatal("persisted original record changed")
	}
	replay, err := execute(t, in)
	if err != nil || replay.AuditEventID != result.AuditEventID {
		t.Fatal("native replay changed", err)
	}
	counts(t, in, 1, 1, 1, 1)
	duplicate := prepare(t)
	duplicateSpec, _ := duplicate.record.Bindings()
	duplicateSpec.Authentication = spec.Authentication
	duplicate.record, err = session.NewSession(duplicateSpec)
	if err != nil {
		t.Fatal(err)
	}
	duplicateNative, err := session.NewIssueCommand(duplicate.binding, duplicate.record)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.command, err = MapCommand(duplicateNative)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.proof = in.proof
	duplicate.plan, err = c.PrepareAuthenticatedCommandPlan(duplicate.binding, duplicate.command, duplicate.proof, duplicate.plan)
	if err != nil {
		t.Fatal(err)
	}
	var conflict identity.ConflictError
	if _, err = execute(t, duplicate); !errors.As(err, &conflict) {
		t.Fatal("original proof reused for another native session", err)
	}
	counts(t, duplicate, 0, 0, 0, 0)
	for _, tc := range []struct {
		name, sql string
		auditFail bool
	}{
		{"blocked user", `UPDATE identity.users SET status='suspended' WHERE tenant_id='issue'`, false},
		{"credential revoked", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='issue'`, false},
		{"authorization changed", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='issue'`, false},
		{"audit rollback", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := prepare(t)
			if tc.sql != "" {
				if _, e := pool.Raw().Exec(ctx, tc.sql); e != nil {
					t.Fatal(e)
				}
			}
			auditing.fail = tc.auditFail
			result, e := execute(t, candidate)
			if e == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied native issuance committed")
			}
			counts(t, candidate, 0, 0, 0, 0)
			auditing.fail = false
			if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='issue';UPDATE identity.credential_references SET enabled=true WHERE tenant_id='issue';UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id='issue'`); e != nil {
				t.Fatal(e)
			}
		})
	}
	t.Run("owned executor with real audit and lifecycle", func(t *testing.T) {
		install, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer install.Rollback(ctx)
		if _, e = install.Exec(ctx, auditpostgres.FreshInstallPreflightSQL()); e != nil {
			t.Fatal("audit preflight", e)
		}
		for _, files := range []fs.FS{auditpostgres.Migrations(), outboxpostgres.Migrations(), identityoutbox.Migrations()} {
			entries, e := fs.ReadDir(files, ".")
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				data, e := fs.ReadFile(files, entry.Name())
				if e != nil {
					t.Fatal(e)
				}
				if _, e = install.Exec(ctx, strings.Split(string(data), "-- +migrations Down")[0]); e != nil {
					t.Fatal("dependency migration", entry.Name(), e)
				}
			}
		}
		if e = install.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		ownedConfig := IssueExecutorConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: *native.issueAdmission, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, FinalAuthentication: &kernel.FinalAuthenticationConfig{Authority: authority, Namespace: "native-session"}}, Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyID: revokeBinding().PolicyID, PolicyVersion: 1, AuditRetentionVersion: 1}
		executor, e := NewIssueExecutor(pool, ownedConfig)
		if e != nil {
			t.Fatal("owned constructor", e)
		}
		candidate := prepare(t)
		command, e := session.NewIssueCommand(candidate.binding, candidate.record)
		if e != nil {
			t.Fatal(e)
		}
		request, e := session.NewAuthenticatedIssueRequest(command, candidate.proof)
		if e != nil {
			t.Fatal(e)
		}
		outcome, e := executor.ExecuteIssue(ctx, request)
		if e != nil || outcome.Receipt.Outcome != identity.CommitOutcomeCommitted || outcome.Replayed || outcome.Session == (session.Session{}) {
			t.Fatal("owned execution", e, outcome.Receipt.Outcome)
		}
		counts(t, candidate, 1, 1, 1, 1)
		var auditRows, lifecycleRows int
		id := mustCommandBytes(t, candidate.binding.CommandID)
		if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&auditRows, &lifecycleRows); e != nil || auditRows != 1 || lifecycleRows != 1 {
			t.Fatal("real protected effects", e, auditRows, lifecycleRows)
		}
		for _, run := range []func(context.Context, session.IssueRequest) (session.IssueExecution, error){executor.ExecuteIssue, executor.RecoverIssue} {
			observed, e := run(ctx, request)
			if e != nil || !observed.Replayed || observed.Receipt.AuditEventID != outcome.Receipt.AuditEventID || observed.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("owned historical observation", e)
			}
			counts(t, candidate, 1, 1, 1, 1)
		}
		t.Run("current denial suppresses execution and historical disclosure", func(t *testing.T) {
			deniedConfig := ownedConfig
			deniedConfig.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
			denied, e := NewIssueExecutor(pool, deniedConfig)
			if e != nil {
				t.Fatal(e)
			}
			for _, run := range []func(context.Context, session.IssueRequest) (session.IssueExecution, error){denied.ExecuteIssue, denied.RecoverIssue} {
				observed, e := run(ctx, request)
				var forbidden identity.ForbiddenError
				if !errors.As(e, &forbidden) || observed.Receipt.Outcome != identity.CommitOutcomeInvalid || observed.Session != (session.Session{}) {
					t.Fatal("denied historical disclosure")
				}
			}
			counts(t, candidate, 1, 1, 1, 1)
		})
		for _, mode := range []string{"missing recovery", "cancelled", "blocked user", "audit rollback"} {
			t.Run(mode, func(t *testing.T) {
				input := prepare(t)
				native, e := session.NewIssueCommand(input.binding, input.record)
				if e != nil {
					t.Fatal(e)
				}
				r, e := session.NewAuthenticatedIssueRequest(native, input.proof)
				if e != nil {
					t.Fatal(e)
				}
				workCtx := ctx
				switch mode {
				case "cancelled":
					var cancel context.CancelFunc
					workCtx, cancel = context.WithCancel(ctx)
					cancel()
				case "blocked user":
					if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id='issue'`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='issue'`); e != nil {
							t.Error("user fixture restoration failed")
						}
					}()
				case "audit rollback":
					if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_owned_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rejection'; END $$; CREATE TRIGGER reject_owned_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_owned_audit()`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER reject_owned_audit ON audit.identity_command_bindings; DROP FUNCTION public.reject_owned_audit()`); e != nil {
							t.Error("audit fixture restoration failed")
						}
					}()
				}
				var observed session.IssueExecution
				if mode == "missing recovery" {
					observed, e = executor.RecoverIssue(workCtx, r)
				} else {
					observed, e = executor.ExecuteIssue(workCtx, r)
				}
				if e == nil || observed.Receipt.Outcome == identity.CommitOutcomeCommitted || observed.Session != (session.Session{}) {
					t.Fatal("unproved session escaped", mode)
				}
				counts(t, input, 0, 0, 0, 0)
				if mode == "missing recovery" || mode == "cancelled" {
					var claims int
					if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, mustCommandBytes(t, input.binding.CommandID)).Scan(&claims); e != nil || claims != 0 {
						t.Fatal("unattempted command reserved")
					}
				}
			})
		}
		t.Run("core issuer delivers only after native commit", func(t *testing.T) {
			candidate := prepare(t)
			spec, _ := candidate.record.Bindings()
			spec.Lookup = session.TokenDigest{}
			keyBytes := make([]byte, 32)
			if _, e := rand.Read(keyBytes); e != nil {
				t.Fatal(e)
			}
			key, e := session.NewDigestKey(1, keyBytes)
			if e != nil {
				t.Fatal(e)
			}
			cookie, e := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			if e != nil {
				t.Fatal(e)
			}
			core, e := session.NewSessionIssuer(executor, session.IssuerConfig{Authority: authority, Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := core.Prepare(candidate.binding, spec, candidate.proof)
			if e != nil {
				t.Fatal(e)
			}
			result, e := core.Issue(ctx, prepared)
			if e != nil || result.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("core native issuance", e)
			}
			if _, e = result.Token.Reveal(); e != nil {
				t.Fatal("committed token withheld")
			}
			if !result.Cookie.Secure || !result.Cookie.HttpOnly || result.Cookie.Value != "" || result.Cookie.Name != "__Host-session" {
				t.Fatal("unsafe committed cookie")
			}
			counts(t, candidate, 1, 1, 1, 1)
			request, ok := prepared.Request()
			if !ok {
				t.Fatal("original request lost")
			}
			observed, e := core.Recover(ctx, request)
			if e != nil || observed.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("core native recovery", e)
			}
			if _, e = observed.Token.Reveal(); e == nil || !reflect.DeepEqual(observed.Cookie, http.Cookie{}) {
				t.Fatal("recovery disclosed credential")
			}
		})
	})
}
