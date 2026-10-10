//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This seam exercises real registration/session ownership, not HIBP, hashing,
// credential possession or the complete password service's policy decision.
type passwordSignupFeature struct {
	domain                                      *kernel.PasswordRegistrationDomain
	effect                                      *PasswordSignupEffect
	intent                                      kernel.PasswordRegistrationIntent
	op                                          identity.FeatureOperation
	recipient                                   kernel.RecipientRecord
	flow                                        session.PreAuthTransaction
	fail, missingRegistration, missingAuthority bool
	foreign, ignoreDenial                       bool
	stage                                       string
}

func (*passwordSignupFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *passwordSignupFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*passwordSignupFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	_, err := PasswordSignupSession(c)
	return err
}
func (p *passwordSignupFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.missingRegistration {
		p.stage = "registration"
		if _, err := p.domain.Apply(ctx, w, p, c, p.intent); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if !p.missingAuthority {
		p.stage = "authorization bootstrap"
		scope := policy.AuthorityScope{TenantID: authorization.TenantID(p.recipient.User.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(p.recipient.User.ID)}
		if _, err := policy.InitializeAuthority(ctx, w, scope, time.Second); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.stage = "session effect"
	if p.foreign {
		s, _ := c.PasswordSignupFeature()
		hash, cookie, _ := c.PasswordSignupCustody()
		c, _ = identity.NewFeaturePasswordSignupCommand(s, hash, cookie)
	}
	r, err := p.effect.Apply(ctx, w, p, c, p.recipient, p.flow)
	if p.ignoreDenial && err != nil {
		return identity.FeatureReceipt{Operation: p.op}, nil
	}
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *passwordSignupFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func testNativePasswordSignupEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('signup-effect',1,true)`); err != nil {
		t.Fatal(err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewPasswordRegistrationDomain(repo, kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewPasswordSignupEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"known", "anonymous", "csrf", "rollback", "audit-failure", "outbox-failure", "missing-registration", "missing-authorization", "wrong-recipient", "expired-proof", "foreign-command", "ignored-custody-denial", "consumed-flow", "wait-expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, original, _, cookie := passwordSigninMappingFixture(t, mode != "known", false)
			b := f.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.ActorID = "signup-effect", "signup-actor"
			user := identity.UserID("signup-user-" + mode)
			if mode == "known" {
				b.UserID = user
			}
			b.OperationID, b.SchemaID = "identity.password.signup", "password-signup"
			f.Binding, f.Operation = b, passwordSignupSessionOperation(b)
			creation := b
			creation.UserID, creation.AnonymousFlowID, creation.OperationID, creation.SchemaID = user, "", "identity.user.create", "signup-user"
			intent := kernel.PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Identifier: identity.Identifier{ID: identity.IdentifierID("signup-email-" + mode), UserID: user, Kind: identity.IdentifierEmail, CanonicalValue: mode + "@signup.example.test", Version: 1}, Credential: identity.CredentialRef{ID: identity.CredentialID("signup-password-" + mode), TenantID: b.TenantID, UserID: user, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
			now := time.Now().UTC().Truncate(time.Microsecond)
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, user, "signup-session-"+mode, "signup-family-"+mode
			s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
			s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject, s.Authentication.Proof.Audience = string(b.TenantID), string(user), profile.Audience
			s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = now, now.Add(time.Minute)
			if mode == "expired-proof" {
				s.IssuedAt, s.LastActivityAt = now.Add(-time.Minute), now.Add(-time.Minute)
				s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = s.IssuedAt, now.Add(-time.Microsecond)
			}
			if mode == "wait-expiry" {
				s.Authentication.Proof.ExpiresAt = now.Add(250 * time.Millisecond)
			}
			s.Authentication.CredentialID, s.Authentication.CredentialVersion = string(intent.Credential.ID), 1
			s.Audience = profile.Audience
			token, _ := session.NewToken(32)
			key, _ := session.NewDigestKey(1, bytes.Repeat([]byte{1}, 32))
			s.Lookup, err = token.Digest(key, string(b.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: b.TenantID}, user)
			sk, _ := SessionAuthorityKeys(b.TenantID, user, s.FamilyID, s.SessionID)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(user)}).Key()
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
			f.Fields, err = PasswordSignupSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			registrationFields, err := kernel.PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			f.Fields = append(f.Fields, registrationFields...)
			command, err := identity.NewFeaturePasswordSignupCommand(f, "$synthetic$prepared-signup", cookie)
			if err != nil {
				t.Fatal(err)
			}
			flowID, _ := identity.NewPreAuthTransactionID()
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: "https://app.example.test", CallbackURL: "https://app.example.test/callback", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte(flowID))}, Version: 1})
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
			recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: intent.Identifier.CanonicalValue, Eligibility: kernel.RecipientPendingOrVerified}, User: identity.User{ID: user, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}, Identifier: intent.Identifier, Verification: identity.Verification{IdentifierID: intent.Identifier.ID, State: identity.VerificationPending, Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1, ObservedAt: now}
			if mode == "wrong-recipient" {
				recipient.Identifier.ID = "different-signup-email"
				recipient.Verification.IdentifierID = recipient.Identifier.ID
			}
			feature := &passwordSignupFeature{domain: domain, effect: effect, intent: intent, op: f.Operation, recipient: recipient, flow: flow, fail: mode == "rollback", missingRegistration: mode == "missing-registration", missingAuthority: mode == "missing-authorization"}
			feature.foreign, feature.ignoreDenial = mode == "foreign-command" || mode == "ignored-custody-denial", mode == "ignored-custody-denial"
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, feature})
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
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "user", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, "user", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "user", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: f.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "user.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			var result identity.CommandResult
			if mode == "wait-expiry" {
				result, err = applySignupAfterPreAuthWait(t, ctx, pool, coordinator, w, command, b.TenantID, flowID, s.Authentication.Proof.ExpiresAt)
			} else {
				result, err = coordinator.ApplyFeature(ctx, w, command)
			}
			want := 0
			if mode == "known" || mode == "anonymous" || mode == "csrf" {
				if err != nil {
					t.Fatal("valid signup account/session effect denied at", feature.stage, err)
				}
				result, err = coordinator.Commit(w, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("signup commit denied", err)
				}
				want = 1
			} else {
				if err == nil {
					result, err = coordinator.Commit(w, result)
				} else {
					result, err = coordinator.Abort(w, err)
				}
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("denied signup committed", err)
				}
			}
			var users, identifiers, credentials, sessions, families, issuances, bindings, authorities int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$3),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND family_id=$4),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1 AND command_id=$5),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND command_id=$5),(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND subject_id=$2),(SELECT state FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$6)`, string(b.TenantID), string(user), s.SessionID, s.FamilyID, mustCommandBytes(t, b.CommandID), string(flowID)).Scan(&users, &identifiers, &credentials, &sessions, &families, &issuances, &bindings, &authorities, &state); err != nil {
				t.Fatal(err)
			}
			wantFamilies := want
			if users != want || identifiers != want || credentials != want || sessions != want || families != wantFamilies || issuances != want || bindings != want || authorities != want {
				t.Fatalf("signup was not atomic: %d/%d/%d/%d/%d/%d/%d/%d want %d", users, identifiers, credentials, sessions, families, issuances, bindings, authorities, want)
			}
			wantState := "issued"
			if want == 1 || mode == "consumed-flow" {
				wantState = "consumed"
			}
			if state != wantState {
				t.Fatal("flow was not atomic")
			}
			if want == 1 {
				native, _ := NewRepository(pool, config)
				stored, err := native.Get(ctx, b.TenantID, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				a, _, _ := encodeRecord(record)
				got, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(a, got) {
					t.Fatal("signup session changed")
				}
				retained, err := native.ReadPasswordSignupIdentity(ctx, b)
				if err != nil || retained.UserID != user || retained.SessionID != s.SessionID || retained.FamilyID != s.FamilyID {
					t.Fatal("signup retained identity lost", err)
				}
				if _, err := native.ReadPasswordSigninIdentity(ctx, b); err == nil {
					t.Fatal("signup relabelled historical signin")
				}
				if _, err := native.ReadOTPSigninIdentity(ctx, b); err == nil {
					t.Fatal("signup relabelled historical OTP")
				}
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), s.SessionID); err != nil {
					t.Fatal(err)
				}
				after, err := native.ReadPasswordSignupIdentity(ctx, b)
				if err != nil || after != retained {
					t.Fatal("payload cleanup lost historical identity", err)
				}
				// The same tuple under signin's digest must not satisfy signup.
				id, binding := revocationEvidence(b, kernel.LifecyclePlan{})
				payload := sha256.Sum256(a)
				foreign := passwordIssuanceDigest(binding, string(user), s.SessionID, s.FamilyID, payload[:])
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET binding_digest=$1 WHERE tenant_id=$2 AND command_id=$3`, foreign[:], string(b.TenantID), id); err != nil {
					t.Fatal(err)
				}
				if out, err := native.ReadPasswordSignupIdentity(ctx, b); err == nil || out != (PasswordSignupIdentity{}) {
					t.Fatal("foreign digest admitted signup identity")
				}
			}
		})
	}
}
