package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

type authenticatedCommandReservoir interface {
	ReserveAuthenticatedCommand(context.Context, identity.CommandBinding, identity.Command, authentication.AuthenticatedProof, CommandPlan) (Reservation, identity.CommandResult, error)
}

type finalProofClock struct{ now time.Time }

func (c finalProofClock) Now() time.Time { return c.now }

type finalProofSource struct {
	original authentication.SignedSignInRecord
}

func (*finalProofSource) CurrentValidity(context.Context, authentication.ValidityRequest) (authentication.SignedValidityEvidence, error) {
	return authentication.SignedValidityEvidence{}, errors.New("unused")
}
func (*finalProofSource) PermanentAuthentication(context.Context, authentication.ProofID) (authentication.SignedAuthenticationRecord, error) {
	return authentication.SignedAuthenticationRecord{}, errors.New("unused")
}
func (s *finalProofSource) SignInAuthentication(context.Context, authentication.ProofID) (authentication.SignedSignInRecord, error) {
	return s.original, nil
}

func finalProofFactory(t *testing.T, b identity.CommandBinding) (*authentication.AuthorityAuthenticator, func(authentication.AuthenticatedProofSpec) authentication.AuthenticatedProof, authentication.AuthenticatedProofSpec) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := &finalProofSource{}
	authority, err := authentication.NewAuthorityAuthenticator(authentication.AuthorityConfig{Issuer: "issuer", Environment: "test", Audience: "audience", Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []authentication.AuthorityKey{{ID: "key", PublicKey: public}}, EvidenceKeys: []authentication.AuthorityKey{{ID: "key", PublicKey: public}}, Source: source, Clock: finalProofClock{now}, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := authentication.AuthenticatedProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(s authentication.AuthenticatedProofSpec) authentication.AuthenticatedProof {
		t.Helper()
		record := authentication.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: authentication.SignInStateAuthenticated, Proof: s.Proof, ProofVersion: s.ProofVersion, CredentialID: s.CredentialID, CredentialVersion: s.CredentialVersion, KeyID: "key"}
		frame, err := record.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		record.Signature = ed25519.Sign(private, frame)
		source.original = record
		proof, err := issuer.IssueAuthenticatedProof(context.Background(), s.Proof)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	spec := authentication.AuthenticatedProofSpec{Proof: authentication.Proof{ID: "aaaaaaaaaaaaaaaaaaaaaa", Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "password", Purpose: "session-issue", Audience: "audience", Assurance: authentication.AssuranceSingleFactor, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: math.MaxUint64, CredentialID: "credential", CredentialVersion: math.MaxUint64}
	return authority, mint, spec
}

type finalFeatureOwner struct {
	featureRegistryContributor
	panicValidate, panicCheck, denyCheck bool
}

func (*finalFeatureOwner) ValidateFeatureCommand(identity.Command, CommandPlan) error { return nil }
func (p *finalFeatureOwner) ValidateAuthenticatedFeature(identity.Command, authentication.AuthenticatedProofSpec) error {
	if p.panicValidate {
		panic("private diagnostic")
	}
	return nil
}
func (p *finalFeatureOwner) CheckAuthenticatedFeature(context.Context, Work, identity.Command, authentication.AuthenticatedProofSpec, bool) error {
	if p.panicCheck {
		panic("private diagnostic")
	}
	if p.denyCheck {
		return identity.ForbiddenError{}
	}
	return nil
}
func (*finalFeatureOwner) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}
func (*finalFeatureOwner) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

type finalTestDomain struct{ Contributor }
type finalTestAudit struct{ *planAuditContributor }
type finalTestLifecycle struct{ *planLifecycleContributor }

func (finalTestDomain) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}
func (finalTestAudit) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}
func (finalTestLifecycle) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func finalFeatureFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan, *finalFeatureOwner) {
	t.Helper()
	c, _, p := featurePlanFixture(t)
	descriptor := featureRegistryInput().descriptor
	operation := identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	owner := &finalFeatureOwner{featureRegistryContributor: featureRegistryContributor{descriptor: descriptor, operations: []identity.FeatureOperation{operation}}}
	registry, err := NewContributorRegistry([]Contributor{finalTestDomain{c.registry.state.entries[0].contributor}, finalTestAudit{c.registry.state.entries[1].contributor.(*planAuditContributor)}, finalTestLifecycle{c.registry.state.entries[2].contributor.(*planLifecycleContributor)}, owner})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	s := featureCodecSpec()
	s.Operation = operation
	s.Binding.OperationID = operation.OperationID
	command := featureCodecCommand(t, s)
	p.Contributors = registry.Descriptors()
	p.Feature = &FeatureRegistration{Contributor: descriptor, Operation: operation}
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "protected"
	seed, err := securityMutationAudit(context.Background(), s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, operation, "session", seed)
	if err != nil {
		t.Fatal(err)
	}
	return c, command, p, owner
}

func TestAuthenticatedCommandOriginalBindingAndProvenance(t *testing.T) {
	c, command, p, owner := finalFeatureFixture(t)
	s, _ := command.Feature()
	authority, mint, original := finalProofFactory(t, s.Binding)
	proof := mint(original)
	c.finalAuthentication = &FinalAuthenticationConfig{Authority: authority, Namespace: "trusted-authority"}
	bound, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, proof, p)
	if err != nil || bound.Digest == ([32]byte{}) {
		t.Fatal("original proof preparation", err)
	}
	ordinary, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil || ordinary.Digest == bound.Digest {
		t.Fatal("authentication omitted from intent", err)
	}
	if r, result, err := c.ReserveCommand(context.Background(), s.Binding, command, ordinary); err == nil || r.state != nil || result != (identity.CommandResult{}) {
		t.Fatal("structural bypass")
	}
	foreign, foreignMint, foreignSpec := finalProofFactory(t, s.Binding)
	_ = foreign
	for _, bad := range []authentication.AuthenticatedProof{{}, foreignMint(foreignSpec)} {
		if p, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, bad, p); err == nil || p.Digest != ([32]byte{}) {
			t.Fatal("zero/foreign provenance admitted")
		}
	}
	for _, change := range []func(*authentication.AuthenticatedProofSpec){
		func(s *authentication.AuthenticatedProofSpec) { s.Proof.ID = "bbbbbbbbbbbbbbbbbbbbbb" },
		func(s *authentication.AuthenticatedProofSpec) { s.ProofVersion-- },
		func(s *authentication.AuthenticatedProofSpec) { s.CredentialID = "other" },
		func(s *authentication.AuthenticatedProofSpec) { s.CredentialVersion-- },
		func(s *authentication.AuthenticatedProofSpec) { s.Proof.Method = "passkey" },
		func(s *authentication.AuthenticatedProofSpec) {
			s.Proof.Assurance = authentication.AssuranceMultiFactor
		},
		func(s *authentication.AuthenticatedProofSpec) {
			s.Proof.IssuedAt = s.Proof.IssuedAt.Add(-time.Nanosecond)
		},
		func(s *authentication.AuthenticatedProofSpec) {
			s.Proof.ExpiresAt = s.Proof.ExpiresAt.Add(time.Nanosecond)
		},
	} {
		modified := original
		change(&modified)
		next, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, mint(modified), p)
		if err != nil || next.Digest == bound.Digest {
			t.Fatal("changed original authentication lost", err)
		}
	}
	q, _, _, request, err := c.prepareAuthenticated(s.Binding, command, proof, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(q.canonical, []byte(original.CredentialID)) || bytes.Contains(q.canonical, []byte(original.Proof.ID)) {
		t.Fatal("raw proof correlation in canonical frame")
	}
	if err := c.validateOriginalAuthentication(s.Binding, request, original.Proof.ExpiresAt); err == nil {
		t.Fatal("exclusive expiry admitted")
	}
	alternate := *c.finalAuthentication
	alternate.Namespace = "other-authority"
	c.finalAuthentication = &alternate
	next, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, proof, p)
	if err != nil || next.Digest == bound.Digest {
		t.Fatal("namespace not bound", err)
	}
	owner.panicValidate = true
	if p, err := c.PrepareAuthenticatedCommandPlan(s.Binding, command, proof, p); err == nil || p.Digest != ([32]byte{}) {
		t.Fatal("validation panic escaped")
	}
}

func TestAuthenticatedCommandCheckFailurePoisonsWork(t *testing.T) {
	for _, panicCheck := range []bool{false, true} {
		c, command, p, owner := finalFeatureFixture(t)
		s, _ := command.Feature()
		authority, mint, spec := finalProofFactory(t, s.Binding)
		c.finalAuthentication = &FinalAuthenticationConfig{Authority: authority, Namespace: "trusted"}
		_, _, admitted, original, err := c.prepareAuthenticated(s.Binding, command, mint(spec), p)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		w := Work{state: &workState{ctx: ctx, binding: s.Binding, feature: admitted.feature, execution: &domainExecution{reservation: &reservationState{authentication: original}}}}
		owner.panicCheck = panicCheck
		owner.denyCheck = !panicCheck
		if err := c.checkAuthenticatedCommand(ctx, w, false); err == nil || w.usable() == nil || w.state.featureInvocation != nil || w.state.sqlStarted {
			t.Fatal("failed check preserved authority", err)
		}
		cancel()
	}
}

func TestAuthenticatedCommandHasOwnedReservationBoundary(t *testing.T) {
	c, command, plan := featurePlanFixture(t)
	boundary, ok := any(c).(authenticatedCommandReservoir)
	if !ok {
		t.Fatal("protected final-authentication reservation is missing")
	}
	s, _ := command.Feature()
	if r, result, err := boundary.ReserveAuthenticatedCommand(context.Background(), s.Binding, command, authentication.AuthenticatedProof{}, plan); err == nil || r.state != nil || result != (identity.CommandResult{}) {
		t.Fatal("zero proof acquired reservation")
	}
}
