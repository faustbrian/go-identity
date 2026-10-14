package postgres

import (
	"bytes"
	"context"
	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"testing"
	"time"
)

func TestNativeIssueHasOwnedAuthenticationAdmission(t *testing.T) {
	var repo any = &Repository{schema: "session_store"}
	if _, ok := repo.(kernel.AuthenticatedFeatureContributor); !ok {
		t.Fatal("native authenticated issuance participant missing")
	}
}

func TestNativeIssueBindsEveryOriginalProofField(t *testing.T) {
	record, _, profile := identifierSessionFixture(t)
	s, _ := record.Bindings()
	s.Version = 1
	a, _ := s.Authority.Bindings()
	a.Session.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", s.SessionID
	native, err := session.NewIssueCommand(b, record)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := MapCommand(native)
	if err != nil {
		t.Fatal(err)
	}
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	original := authentication.AuthenticatedProofSpec{Proof: s.Authentication.Proof, ProofVersion: s.Authentication.ProofVersion, CredentialID: s.Authentication.CredentialID, CredentialVersion: s.Authentication.CredentialVersion}
	if err = repo.ValidateAuthenticatedFeature(mapped, original); err != nil {
		t.Fatal("exact original rejected", err)
	}
	for _, change := range []func(*authentication.AuthenticatedProofSpec){
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.ID = "zzzzzzzzzzzzzzzzzzzzzz" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Tenant = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Subject = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Method = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Purpose = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Audience = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.Proof.Assurance++ },
		func(p *authentication.AuthenticatedProofSpec) {
			p.Proof.IssuedAt = p.Proof.IssuedAt.Add(time.Nanosecond)
		},
		func(p *authentication.AuthenticatedProofSpec) {
			p.Proof.ExpiresAt = p.Proof.ExpiresAt.Add(time.Nanosecond)
		},
		func(p *authentication.AuthenticatedProofSpec) { p.ProofVersion-- },
		func(p *authentication.AuthenticatedProofSpec) { p.CredentialID = "other" },
		func(p *authentication.AuthenticatedProofSpec) { p.CredentialVersion++ },
	} {
		p := original
		change(&p)
		if repo.ValidateAuthenticatedFeature(mapped, p) == nil {
			t.Fatal("substituted original accepted")
		}
	}
	if repo.ValidateAuthenticatedFeature(identity.Command{}, original) == nil {
		t.Fatal("zero mapped command accepted")
	}
	if err = repo.CheckAuthenticatedFeature(context.Background(), kernel.Work{}, mapped, original, false); err == nil {
		t.Fatal("zero Work admitted")
	}
	if _, err = repo.Apply(context.Background(), kernel.Work{}, native); err == nil {
		t.Fatal("zero Work applied")
	}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: session.IssueOperation()}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.create", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err = repo.ValidateFeatureCommand(mapped, plan); err != nil {
		t.Fatal("complete issue effects rejected", err)
	}
	for _, change := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.SubjectType = "session_family" },
		func(p *kernel.CommandPlan) { p.Lifecycle.EventType = "session.rotated.v1" },
		func(p *kernel.CommandPlan) { p.Lifecycle.BeforeVersion = 1 },
		func(p *kernel.CommandPlan) { p.Lifecycle.AfterVersion = 2 },
		func(p *kernel.CommandPlan) { p.Audits = nil },
		func(p *kernel.CommandPlan) { p.Audits[0].Required = false },
		func(p *kernel.CommandPlan) { p.Audits[0].EventType = "identity.session.rotate" },
		func(p *kernel.CommandPlan) { p.Audits[0].RequiredRecordCount = 2 },
		func(p *kernel.CommandPlan) { p.Audits[0].RetentionClass = "" },
	} {
		candidate := plan
		l := *plan.Lifecycle
		candidate.Lifecycle = &l
		candidate.Audits = append([]kernel.AuditPlan(nil), plan.Audits...)
		change(&candidate)
		if repo.ValidateFeatureCommand(mapped, candidate) == nil {
			t.Fatal("incomplete issue effects accepted")
		}
	}
}

func TestNativeIssueRegistrationRequiresExplicitProfile(t *testing.T) {
	repo := &Repository{schema: "session_store"}
	for _, op := range repo.FeatureOperations() {
		if op == session.IssueOperation() {
			t.Fatal("unconfigured issue registered")
		}
	}
	repo.issueAdmission = &IssueAdmissionConfig{GlobalAuthorityID: "deployment-a", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	found := false
	for _, op := range repo.FeatureOperations() {
		if op == session.IssueOperation() {
			found = true
		}
	}
	if !found {
		t.Fatal("configured native issuance is not registered")
	}
}

func nativeIssueFixture(t *testing.T) session.SessionCommand {
	t.Helper()
	spec, _ := testSession(t).Bindings()
	spec.Version = 1
	a, _ := spec.Authority.Bindings()
	a.Session.Version = 1
	var err error
	spec.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", spec.SessionID
	command, err := session.NewIssueCommand(b, record)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestNativeIssueMappingPreservesOriginalRecord(t *testing.T) {
	native := nativeIssueFixture(t)
	mapped, err := MapCommand(native)
	if err != nil {
		t.Fatal("native issuance mapping missing", err)
	}
	projection, ok := mapped.Feature()
	if !ok || projection.Operation != session.IssueOperation() {
		t.Fatal("issue variant lost")
	}
	restored, err := nativeIssue(mapped)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := native.Issue()
	got, _ := restored.Issue()
	before, _, _ := encodeRecord(want.Session)
	after, _, _ := encodeRecord(got.Session)
	if got.Binding != want.Binding || !bytes.Equal(before, after) {
		t.Fatal("original record changed")
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureBytes}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "lookup.version" {
					s.Fields[i].Value.Uint64 = 1 << 32
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "lookup.digest" {
					s.Fields[i].Value.Bytes = s.Fields[i].Value.Bytes[:31]
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "proof.issued" {
					s.Fields[i].Value.Text = "2026-10-02T23:59:00.123456789+00:00"
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "authentication.kind" {
					s.Fields[i].Value.Uint64 = 257
				}
			}
		},
	} {
		s, _ := mapped.Feature()
		mutate(&s)
		bad, err := identity.NewFeatureCommand(s)
		if err == nil {
			if _, err := nativeIssue(bad); err == nil {
				t.Fatal("incomplete or lossy issue reconstructed")
			}
		}
	}
}
