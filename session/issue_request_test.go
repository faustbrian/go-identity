package session_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type issueClock struct{ now time.Time }

func (c issueClock) Now() time.Time { return c.now }

type issueProofSource struct{ record auth.SignedSignInRecord }

func (s issueProofSource) SignInAuthentication(context.Context, auth.ProofID) (auth.SignedSignInRecord, error) {
	return s.record, nil
}
func (issueProofSource) CurrentValidity(context.Context, auth.ValidityRequest) (auth.SignedValidityEvidence, error) {
	return auth.SignedValidityEvidence{}, errors.New("unused")
}
func (issueProofSource) PermanentAuthentication(context.Context, auth.ProofID) (auth.SignedAuthenticationRecord, error) {
	return auth.SignedAuthenticationRecord{}, errors.New("unused")
}

func issueRequestFixture(t *testing.T) (session.SessionCommand, *auth.AuthorityAuthenticator, auth.AuthenticatedProof, time.Time) {
	return issueRequestFixtureWith(t, nil)
}

func issueRequestFixtureWith(t *testing.T, configure func(*session.SessionSpec)) (session.SessionCommand, *auth.AuthorityAuthenticator, auth.AuthenticatedProof, time.Time) {
	t.Helper()
	s := sessionSpec(t)
	s.Version = 1
	a := authoritySpec()
	a.Session.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	if configure != nil {
		configure(&s)
	}
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := session.NewIssueCommand(identity.CommandBinding{CommandID: id, TenantID: s.TenantID, UserID: s.UserID, ActorKind: authorization.SubjectUser, ActorID: identity.ActorID(s.UserID), OperationID: "identity.session.issue", RecordID: s.SessionID, PolicyID: "policy", PolicyVersion: 1, SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation"}, record)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := auth.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: auth.SignInStateAuthenticated, Proof: s.Authentication.Proof, ProofVersion: s.Authentication.ProofVersion, CredentialID: s.Authentication.CredentialID, CredentialVersion: s.Authentication.CredentialVersion, KeyID: "key"}
	b, err := signed.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = ed25519.Sign(key, b)
	authority, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: "issuer", Environment: "test", Audience: s.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, EvidenceKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, Source: issueProofSource{record: signed}, Clock: issueClock{now: s.IssuedAt}, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.AuthenticatedProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := issuer.IssueAuthenticatedProof(context.Background(), s.Authentication.Proof)
	if err != nil {
		t.Fatal(err)
	}
	return command, authority, proof, s.IssuedAt
}

func TestIssueRequestRequiresOriginalFreshnessAndSessionLifetimeAfterProofAdmission(t *testing.T) {
	command, authority, proof, issued := issueRequestFixtureWith(t, func(s *session.SessionSpec) {
		c := config()
		c.AbsoluteTTL = 15 * time.Minute
		c.IdleTTL = 15 * time.Minute
		c.RefreshAfter = time.Minute
		c.FreshFor = 15 * time.Minute
		var err error
		s.Remember, err = session.ResolveRememberPolicy(session.BrowserSession, c)
		if err != nil {
			t.Fatal(err)
		}
		s.Authentication.Proof.ExpiresAt = s.IssuedAt.Add(20 * time.Minute)
	})
	request, err := session.NewAuthenticatedIssueRequest(command, proof)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		now  time.Time
		want error
	}{
		{issued.Add(14 * time.Minute), session.ErrInvalidSessionCommand},
		{issued.Add(15 * time.Minute), session.ErrExpired},
	} {
		bindings := proof.Bindings()
		if err := authority.ValidateAuthenticatedProof(proof, auth.ProofUse{Tenant: bindings.Proof.Tenant, Subject: bindings.Proof.Subject, Purpose: "session-issue", Audience: bindings.Proof.Audience, Now: tc.now}); err != nil {
			t.Fatal("proof did not reach session temporal denial", err)
		}
		if err := request.Validate(authority, tc.now); !errors.Is(err, tc.want) {
			t.Fatal("request bypassed original session temporal policy", err)
		}
	}
}

func TestIssueRequestBindsFinalProofToExpectedAuthority(t *testing.T) {
	command, authority, proof, now := issueRequestFixture(t)
	request, err := session.NewAuthenticatedIssueRequest(command, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(authority, now); err != nil {
		t.Fatal(err)
	}
	if got, ok := request.Command(); !ok || got != command {
		t.Fatal("native command changed")
	}
	_, foreign, _, _ := issueRequestFixture(t)
	if err := request.Validate(foreign, now); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("foreign authority accepted")
	}
	if _, err := session.NewAuthenticatedIssueRequest(command, auth.AuthenticatedProof{}); !errors.Is(err, session.ErrInvalidIssueRequest) {
		t.Fatal("zero proof accepted")
	}
}

func TestIssueRequestRejectsProjectionSubstitutionAndAnonymousState(t *testing.T) {
	command, _, proof, _ := issueRequestFixture(t)
	issue, _ := command.Issue()
	original, _ := issue.Session.Bindings()
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.ProofVersion++ },
		func(s *session.SessionSpec) { s.Authentication.CredentialID = "different" },
		func(s *session.SessionSpec) { s.Authentication.CredentialVersion++ },
		func(s *session.SessionSpec) { s.Authentication.Proof.ID = "zyxwvutsrqponmlkjihgfe" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Method = "other" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = auth.AssuranceMultiFactor },
		func(s *session.SessionSpec) {
			s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.Add(-time.Second)
		},
		func(s *session.SessionSpec) {
			s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.Add(time.Second)
		},
		func(s *session.SessionSpec) { s.TenantID = "different"; s.Authentication.Proof.Tenant = "different" },
		func(s *session.SessionSpec) { s.UserID = "different"; s.Authentication.Proof.Subject = "different" },
		func(s *session.SessionSpec) { s.Audience = "different"; s.Authentication.Proof.Audience = "different" },
		func(s *session.SessionSpec) {
			s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: s.IssuedAt}
		},
	} {
		spec := original
		mutate(&spec)
		record, err := session.NewSession(spec)
		if err != nil {
			t.Fatal("invalid negative fixture", err)
		}
		binding := issue.Binding
		binding.TenantID = spec.TenantID
		binding.UserID = spec.UserID
		changed, err := session.NewIssueCommand(binding, record)
		if err != nil {
			t.Fatal("invalid negative command", err)
		}
		if request, err := session.NewAuthenticatedIssueRequest(changed, proof); !errors.Is(err, session.ErrInvalidIssueRequest) || request != (session.IssueRequest{}) {
			t.Fatal("substituted metadata accepted")
		}
	}
	if _, err := session.NewAuthenticatedIssueRequest(session.SessionCommand{}, proof); !errors.Is(err, session.ErrInvalidIssueRequest) {
		t.Fatal("zero command accepted")
	}
	// Metadata matching uses instants, not caller location pointers.
	original.Authentication.Proof.IssuedAt = original.Authentication.Proof.IssuedAt.In(time.FixedZone("source", 3600))
	original.Authentication.Proof.ExpiresAt = original.Authentication.Proof.ExpiresAt.In(time.FixedZone("source", 3600))
	record, err := session.NewSession(original)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := session.NewIssueCommand(issue.Binding, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewAuthenticatedIssueRequest(changed, proof); err != nil {
		t.Fatal("same instants rejected", err)
	}
}

func TestIssueRequestMaintainsOriginalExpiryAndPrivateCustody(t *testing.T) {
	command, authority, proof, now := issueRequestFixture(t)
	request, err := session.NewAuthenticatedIssueRequest(command, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(authority, proof.Bindings().Proof.ExpiresAt); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("proof expiry equality accepted")
	}
	if err := request.Validate(nil, now); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("nil expected authority accepted")
	}
	if err := (session.IssueRequest{}).Validate(authority, now); !errors.Is(err, session.ErrInvalidIssueRequest) {
		t.Fatal("zero request accepted")
	}
	if c, ok := (session.IssueRequest{}).Command(); ok || c != (session.SessionCommand{}) {
		t.Fatal("zero projection")
	}
	issue, _ := command.Issue()
	spec, _ := issue.Session.Bindings()
	spec.LastActivityAt = now.Add(time.Second)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := session.NewIssueCommand(issue.Binding, record)
	if !errors.Is(err, session.ErrInvalidSessionCommand) || changed != (session.SessionCommand{}) {
		t.Fatal("future activity issue prepared")
	}
	for _, r := range []session.IssueRequest{request, {}} {
		if _, err := json.Marshal(r); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("request JSON disclosure")
		}
		if _, err := r.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("request text disclosure")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, r), "password-a") || strings.Contains(fmt.Sprintf(verb, r), "session-a") {
				t.Fatal("request formatted metadata")
			}
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if request.Validate(authority, now) != nil {
					t.Error("concurrent proof request changed")
				}
			}
		}()
	}
	wg.Wait()
}
