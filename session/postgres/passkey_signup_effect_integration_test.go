//go:build integration

package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Real kernel/MFA/authorization/session owners participate in one Work. This
// controlled native/RP seam is not WebAuthn verification or public signup proof.
type signupSessionFeature struct {
	domain  *kernel.PasskeyRegistrationDomain
	effect  *PasskeySignupEffect
	intent  kernel.PasskeyRegistrationIntent
	command identity.Command
	mode    string
	applied bool
}

func (*signupSessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*signupSessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passkeySignupSessionOperation()}
}
func (p *signupSessionFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	_, err := PasskeySignupSession(c)
	return err
}
func (p *signupSessionFeature) PasskeyRegistration(c identity.Command) (kernel.PasskeyRegistrationIntent, error) {
	if c != p.command {
		return kernel.PasskeyRegistrationIntent{}, identity.ForbiddenError{}
	}
	return p.intent, nil
}
func (p *signupSessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-creation" {
		if _, err := p.domain.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mode != "missing-policy" {
		scope := policy.AuthorityScope{TenantID: authorization.TenantID(p.intent.Creation.Binding.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(p.intent.Creation.Binding.UserID)}
		if _, err := policy.InitializeAuthority(ctx, w, scope, time.Second); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mode != "missing-factors" && p.mode != "missing-creation" {
		if err := mfapg.InitializePasskeySignup(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.mode == "foreign-command" {
		s, _ := c.Feature()
		c, _ = identity.NewFeatureCommand(s)
	}
	r, err := p.effect.Apply(ctx, w, p, c)
	p.applied = err == nil
	if err == nil && p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *signupSessionFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "late-block" {
		if _, err := w.Exec(ctx, `UPDATE identity.users SET status='banned',authority_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID)); err != nil {
			return err
		}
	}
	if p.mode == "late-factor-change" {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID)); err != nil {
			return err
		}
	}
	return p.effect.Check(ctx, w, p, c)
}
func (p *signupSessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

type signupSessionAuthority struct{}

func (*signupSessionAuthority) RequirePasskeySignupSession(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, c identity.Command, namespace string, record session.Session) error {
	if namespace != "rp-a" {
		return identity.ForbiddenError{}
	}
	factors, err := mfapg.RequirePasskeySignupFactors(ctx, w, owner, c)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	v, _ := s.Authority.Bindings()
	if factors.Version() != v.Factor.Binding.Version || v.Passkey.Binding.Version != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

type signupSessionOutbox struct{ revokeOutbox }

func (p *signupSessionOutbox) PersistPasskeyRegistration(ctx context.Context, w kernel.Work) error {
	if err := p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	event, err := w.StagedPasskeyRegistrationLifecycle()
	if err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO revoke_outbox(event_id,command_id,event_type,subject_type,subject_id,before_version,after_version) VALUES($1,$2,$3,$4,$5,'0','1')`, event.ID, string(event.CommandID), event.EventType, event.SubjectType, event.SubjectID)
	return err
}

func TestPasskeySignupSessionAtomicPersistence(t *testing.T) {
	ctx, pool, repo := anonymousSessionDatabase(t)
	base := kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
	history, err := (kernel.PasskeyRegistrationMigrationSource{Base: kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.PasswordRegistrationMigrationSource{Base: base, Version: 31}, Version: 32}, Version: 33}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() > 30 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("signup kernel history", err)
			}
		}
	}
	for _, source := range []migrations.Source{
		mfapg.PasskeySignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2},
		PasskeySignupMigrationSource{Schema: "session_store", Version: 25, PreviousConstraint: "session_issuances_purpose_anonymous_v1"},
	} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("signup owner history", err)
			}
		}
	}
	domain, err := kernel.NewPasskeyRegistrationDomain(repo)
	if err != nil {
		t.Fatal(err)
	}
	profile := PasskeyAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", RPNamespace: "rp-a"}
	effect, err := NewPasskeySignupEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile, &signupSessionAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-creation", "missing-policy", "missing-factors", "foreign-command", "rollback", "audit-failure", "outbox-failure", "late-block", "late-factor-change", "expired-proof"} {
		t.Run(mode, func(t *testing.T) {
			record, seed := passkeySignupSessionFixture(t)
			b := seed.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID = "guest-tenant"
			b.RecordID = "signup-passkey-" + mode
			b.AnonymousFlowID = string(b.CommandID)
			user := identity.UserID("signup-user-" + mode)
			creation := b
			creation.OperationID, creation.SchemaID, creation.UserID, creation.AnonymousFlowID, creation.RecordID = "identity.user.create", "fields", user, "", ""
			intent := kernel.PasskeyRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Credential: identity.CredentialRef{ID: identity.CredentialID(b.RecordID), TenantID: b.TenantID, UserID: user, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}}
			s, _ := record.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, user, "signup-session-"+mode, "signup-family-"+mode
			now := time.Now().UTC().Truncate(time.Microsecond)
			s.IssuedAt, s.LastActivityAt = now, now
			s.Authentication.CredentialID = b.RecordID
			s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject = string(b.TenantID), string(user)
			s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = now, now.Add(time.Minute)
			if mode == "expired-proof" {
				s.IssuedAt, s.LastActivityAt = now.Add(-time.Minute), now.Add(-time.Minute)
				s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = s.IssuedAt, now.Add(-time.Microsecond)
			}
			s.Lookup = session.TokenDigest{KeyVersion: 1, Sum: [32]byte{byte(len(mode)), byte(len(mode) + 1)}}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: b.TenantID}, user)
			sk, _ := SessionAuthorityKeys(b.TenantID, user, s.FamilyID, s.SessionID)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(user)}).Key()
			fk, _ := mfapg.FactorAuthorityKey(b.TenantID, user)
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), Session: a(sk.Session), SessionFamily: a(sk.Family), Authorization: a(pk), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(fk)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: a("passkey:rp-a:" + string(user))}})
			if err != nil {
				t.Fatal(err)
			}
			record, err = session.NewSession(s)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := PasskeySignupSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			creationFields, err := kernel.PasskeyRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			seed.Binding, seed.Fields = b, append(fields, creationFields...)
			command, err := identity.NewFeatureCommand(seed)
			if err != nil {
				t.Fatal(err)
			}
			p := &signupSessionFeature{domain: domain, effect: effect, intent: intent, command: command, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &revokeAudit{fail: mode == "audit-failure"}, &signupSessionOutbox{revokeOutbox{fail: mode == "outbox-failure"}}, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			auditRecord, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: "identity.passkey.create_credential", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			ad, err := kernel.FeatureAuditBindingDigest(b, seed.Operation, "credential", auditRecord)
			if err != nil {
				t.Fatal(err)
			}
			cd, err := kernel.PasskeyRegistrationDigest(intent)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "credential", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: seed.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}, PasskeyRegistration: &kernel.PasskeyRegistrationPlan{UserID: user, CredentialID: intent.Credential.ID, CreationDigest: cd, CreationEventIndex: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.passkey.create_credential", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: ad}}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if applyErr != nil {
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			success := mode == "commit"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("atomic signup session did not commit", err, applyErr)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid signup session committed")
			}
			var users, refs, factors, policies, sessions, families, issuances, audits, events int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND subject_id=$2),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM revoke_audit WHERE command_id=$3 AND outcome=1),(SELECT count(*) FROM revoke_outbox WHERE command_id=$3)`, string(b.TenantID), string(user), string(b.CommandID)).Scan(&users, &refs, &factors, &policies, &sessions, &families, &issuances, &audits, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if users != want || refs != want || factors != want || policies != want || sessions != want || families != want || issuances != want || audits != want || events != 2*want {
				t.Fatal("signup account/session/effects split", users, refs, factors, policies, sessions, families, issuances, audits, events)
			}
			if success {
				reader, err := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				stored, err := reader.Lookup(ctx, b.TenantID, s.Lookup)
				if err != nil {
					t.Fatal("read committed signup session", err)
				}
				got, _ := stored.Session.Bindings()
				if got.UserID != user || got.SessionID != s.SessionID {
					t.Fatal("wrong prospective session")
				}
				originalIDs, err := reader.ReadPasskeySignupIdentity(ctx, b)
				if err != nil || originalIDs.UserID != user || originalIDs.SessionID != s.SessionID || originalIDs.FamilyID != s.FamilyID {
					t.Fatal("original anonymous signup issuance identity lost", err)
				}
				foreign := b
				foreign.RecordID = "another-credential"
				if ids, err := reader.ReadPasskeySignupIdentity(ctx, foreign); err == nil || ids != (PasskeySignupIdentity{}) {
					t.Fatal("foreign credential binding disclosed original signup identity")
				}
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(b.TenantID), s.SessionID); err != nil {
					t.Fatal(err)
				}
				retained, err := reader.ReadPasskeySignupIdentity(ctx, b)
				if err != nil || retained != originalIDs {
					t.Fatal("session pruning erased original signup issuance identity", err)
				}
				_, retry, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || retry.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("signup retry lost receipt", err)
				}
			}
			if (mode == "rollback" || mode == "audit-failure" || mode == "outbox-failure" || mode == "late-block" || mode == "late-factor-change") && !p.applied {
				t.Fatal("late rollback never reached real session write", applyErr)
			}
		})
	}
}
