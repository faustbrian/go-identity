//go:build integration

package postgres

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This native test seam proves session-owned atomic effects, not password
// comparison, cookie possession, proof signatures or a complete login journey.
type passwordSigninFeature struct {
	effect    *PasswordSigninEffect
	op        identity.FeatureOperation
	recipient kernel.RecipientRecord
	flow      session.PreAuthTransaction
	fail      bool
}

func (*passwordSigninFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *passwordSigninFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*passwordSigninFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	_, err := PasswordSigninSession(c)
	return err
}
func (p *passwordSigninFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, c, p.recipient, p.flow)
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *passwordSigninFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func testNativePasswordSigninEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('password-effect',1,true);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('password-effect','recipient','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('password-effect','recipient','password-a',1,'identity/password',9,true);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('password-effect','recipient','password-email','email','password-effect@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	scope := policy.AuthorityScope{TenantID: "password-effect", PolicyNamespace: "users", SubjectID: "recipient"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewPasswordSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"known", "anonymous", "csrf", "rollback", "audit-failure", "outbox-failure", "stale-credential", "stale-authorization", "consumed-flow", "wait-expiry", "credential-wait"} {
		t.Run(mode, func(t *testing.T) {
			f, original, secret, cookie := passwordSigninMappingFixture(t, mode != "known", false)
			b := f.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.ActorID = "password-effect", "recipient"
			if mode == "known" {
				b.UserID = "recipient"
			}
			f.Binding = b
			recipient, err := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "password-effect@example.test", Eligibility: kernel.RecipientVerified})
			if err != nil || recipient.Suppressed {
				t.Fatal("recipient unavailable", err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, "recipient", "password-session-"+mode, "password-family-"+mode
			s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
			s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject, s.Authentication.Proof.Audience = string(s.TenantID), string(s.UserID), profile.Audience
			s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = now, now.Add(time.Minute)
			if mode == "wait-expiry" {
				s.Authentication.Proof.ExpiresAt = now.Add(250 * time.Millisecond)
			}
			s.Audience = profile.Audience
			token, _ := session.NewToken(32)
			key, _ := session.NewDigestKey(1, bytes.Repeat([]byte{1}, 32))
			s.Lookup, err = token.Digest(key, string(s.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := scope.Key()
			a := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)})
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSession(s)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "csrf" {
				record = withCSRFState(t, record, 1)
			}
			f.Fields, err = PasswordSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeaturePasswordSigninCommand(f, secret, cookie)
			if err != nil {
				t.Fatal(err)
			}
			flowID, _ := identity.NewPreAuthTransactionID()
			var cookieDigest [32]byte
			copy(cookieDigest[:], []byte(flowID))
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: "https://app.example.test", CallbackURL: "https://app.example.test/callback", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: cookieDigest}, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertPreAuth(ctx, preAuthTestTx{tx}, config, flow); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			if mode == "consumed-flow" {
				use := PreAuthUse{Command: b, Fingerprint: [32]byte{9}, Generation: 1}
				if err := ReservePreAuth(ctx, preAuthTestTx{tx}, config, flow, use); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				if err := FinalizePreAuth(ctx, preAuthTestTx{tx}, config, flow, use); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			feature := &passwordSigninFeature{effect: effect, op: f.Operation, recipient: recipient, flow: flow, fail: mode == "rollback"}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			target := string(b.UserID)
			if target == "" {
				target = b.AnonymousFlowID
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: f.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "stale-credential" || mode == "stale-authorization" {
				table := "identity.credential_references"
				if mode == "stale-authorization" {
					table = "authorization_subject_authorities"
				}
				if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET version=version+1 WHERE tenant_id='password-effect'"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET version=version-1 WHERE tenant_id='password-effect'"); err != nil {
						t.Error(err)
					}
				}()
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			waitUntil := s.Authentication.Proof.ExpiresAt
			if mode == "credential-wait" {
				if err := pool.Raw().QueryRow(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '250 milliseconds' WHERE tenant_id='password-effect' RETURNING expires_at`).Scan(&waitUntil); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=NULL WHERE tenant_id='password-effect'`); err != nil {
						t.Error(err)
					}
				}()
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			var result identity.CommandResult
			if mode == "wait-expiry" || mode == "credential-wait" {
				result, err = applyOTPAfterFamilyWait(t, ctx, pool, coordinator, w, command, s, waitUntil)
			} else {
				result, err = coordinator.ApplyFeature(ctx, w, command)
			}
			want := 0
			if mode == "known" || mode == "anonymous" || mode == "csrf" {
				if err != nil {
					t.Fatal("valid password session effect denied", err)
				}
				result, err = coordinator.Commit(w, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("effect commit failed", err)
				}
				want = 1
			} else {
				if err == nil {
					result, err = coordinator.Commit(w, result)
				} else {
					result, err = coordinator.Abort(w, err)
				}
				wantOutcome := identity.CommitOutcomeNotCommitted
				if mode == "audit-failure" {
					// Persistent audit failure also prevents the detached failure
					// receipt. Domain rollback does not prove terminal noncommit.
					wantOutcome = identity.CommitOutcomeUnknown
				}
				if result.Outcome != wantOutcome || err == nil {
					t.Fatal("denied effects escaped rollback", err)
				}
			}
			var sessions, families, issuances int
			wantFamilies := want
			if mode == "wait-expiry" || mode == "credential-wait" {
				wantFamilies = 1 // The locked pre-existing family survives rollback.
			}
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND family_id=$3),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$4),(SELECT state FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$5)`, string(s.TenantID), s.SessionID, s.FamilyID, mustCommandBytes(t, b.CommandID), string(flowID)).Scan(&sessions, &families, &issuances, &state); err != nil || sessions != want || families != wantFamilies || issuances != want {
				t.Fatalf("atomic effects %d/%d/%d: %v", sessions, families, issuances, err)
			}
			wantState := "issued"
			if want == 1 || mode == "consumed-flow" {
				wantState = "consumed"
			}
			if state != wantState {
				t.Fatal("pre-auth state not conserved")
			}
			if want == 1 {
				native, _ := NewRepository(pool, config)
				stored, err := native.Get(ctx, s.TenantID, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				a, _, _ := encodeRecord(record)
				got, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(a, got) {
					t.Fatal("original session changed")
				}
				_, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted {
					t.Fatal("retained recovery lost original issuance", err)
				}
				if mode == "anonymous" {
					testRetainedPasswordIssuance(t, ctx, pool, b, s)
				}
			}
		})
	}
}

func testRetainedPasswordIssuance(t *testing.T, ctx context.Context, pool *database.Pool, b identity.CommandBinding, s session.SessionSpec) {
	t.Helper()
	read := func(want kernel.RecoveryStatus) {
		t.Helper()
		got, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
		if err != nil || status != want {
			t.Fatalf("retained password status=%v want=%v: %v", status, want, err)
		}
		if want == kernel.RecoveryCommitted {
			if got.UserID != s.UserID || got.SessionID != s.SessionID || got.FamilyID != s.FamilyID {
				t.Fatal("retained password identity changed")
			}
		} else if got != (OTPSigninIdentity{}) {
			t.Fatal("unproven retained identity disclosed")
		}
	}
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	id := mustCommandBytes(t, b.CommandID)
	// Use a real foreign selected user so the FK admits the corruption and the
	// retained commitment decoder, rather than schema enforcement, denies it.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'changed-retained-identity','active',1)`, string(s.TenantID)); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, column := range []string{"user_id", "session_id", "family_id"} {
		if _, err := tx.Exec(ctx, `SAVEPOINT retained_original`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`='changed-retained-identity' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		got, status, err := readNativeIssuanceIdentity(ctx, tx, `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
		if err != nil || status != kernel.RecoveryUnknown || got != (OTPSigninIdentity{}) {
			t.Fatal("corrupt retained tuple fabricated commit", err)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT retained_original`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE session_store.session_issuances SET record_digest=decode(repeat('00',32),'hex') WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	got, status, err := readNativeIssuanceIdentity(ctx, tx, `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
	if err != nil || status != kernel.RecoveryUnknown || got != (OTPSigninIdentity{}) {
		t.Fatal("corrupt retained digest fabricated commit", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	_, status, err = readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, otpIssuanceDigest)
	if err != nil || status != kernel.RecoveryUnknown {
		t.Fatal("OTP digest domain authenticated password evidence", err)
	}
	b.CommandID, _ = identity.NewCommandID()
	read(kernel.RecoveryNotCommitted)
}
