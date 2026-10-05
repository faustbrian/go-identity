//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication"
	policyStore "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
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
}
