package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type phoneVerificationMapperFixture struct {
	FeatureCommitContributor
	intent PhoneVerificationIntent
	domain *PhoneEnrollmentDomain
}

func (phoneVerificationMapperFixture) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return nil
}

func (p phoneVerificationMapperFixture) PhoneVerification(identity.Command) (PhoneVerificationIntent, *PhoneEnrollmentDomain, error) {
	return p.intent, p.domain, nil
}

func phoneVerificationFixture(t *testing.T) (phoneVerificationMapperFixture, identity.FeatureCommandSpec, CommandPlan) {
	t.Helper()
	b := codecBinding()
	op := phoneVerificationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.RecordID, b.ActorID = "pending-phone", identity.ActorID(b.UserID)
	i := PhoneVerificationIntent{
		Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID,
			ID: identity.IdentifierID(b.RecordID), Action: identity.IdentifierVerify,
			ExpectedUserVersion: 10, ExpectedAuthorityVersion: 5,
			ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1},
		CanonicalNumber: "+358401234567", NormalizationProfile: phoneEnrollmentIntent().Change.NormalizationProfile,
		NormalizationVersion: 1, EnrollmentCommandID: "AgICAgICAgICAgICAgICAg",
	}
	fields, err := PhoneVerificationFields(i)
	if err != nil {
		t.Fatal(err)
	}
	owner := phoneVerificationMapperFixture{intent: i, domain: &PhoneEnrollmentDomain{repository: &Repository{},
		profile: i.NormalizationProfile, version: 1,
		reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}, reuseCooldown: 30 * 24 * time.Hour}}}
	plan := CommandPlan{Feature: &FeatureRegistration{Operation: op, Contributor: ContributorDescriptor{
		Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}},
		SubjectType: "identifier", OTP: &OTPAttemptPlan{Mode: OTPConsume, ChallengeID: string(i.EnrollmentCommandID)},
		Lifecycle: &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 1, AfterVersion: 2},
		Audits:    []AuditPlan{{Required: true, RetentionClass: "protected"}}}
	return owner, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, plan
}

func TestPhoneVerificationBindsPendingPhoneAndOriginalEnrollment(t *testing.T) {
	owner, spec, plan := phoneVerificationFixture(t)
	build := func(s identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSessionCommand(s, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	command := build(spec)
	if got, d, err := phoneVerificationCommand(owner, command, plan); err != nil || got != owner.intent || d != owner.domain {
		t.Fatal("original pending phone verification rejected", err)
	}
	if !otpFeatureInputAdmissionRequired(plan) {
		t.Fatal("phone OTP can charge before original target/session/factor admission")
	}
	for index := range spec.Fields {
		s := spec
		s.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		if s.Fields[index].Value.Kind == identity.FeatureText {
			s.Fields[index].Value.Text += "other"
		} else {
			s.Fields[index].Value.Uint64++
		}
		if _, _, err := phoneVerificationCommand(owner, build(s), plan); err == nil {
			t.Fatal("substituted original phone target accepted")
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.OTP = nil },
		func(p *CommandPlan) { copy := *p.OTP; copy.Mode = OTPCheck; p.OTP = &copy },
		func(p *CommandPlan) { copy := *p.OTP; copy.ChallengeID = "AwMDAwMDAwMDAwMDAwMDAw"; p.OTP = &copy },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		func(p *CommandPlan) { p.CapabilityIssuance = &CapabilityIssuancePlan{} },
		func(p *CommandPlan) { p.Delivery = &DeliveryPlan{} },
		func(p *CommandPlan) { p.SubjectType = "user" },
		func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "identifier.attached.v1", BeforeVersion: 1, AfterVersion: 2}
		},
		func(p *CommandPlan) { p.Audits = nil },
	} {
		p := plan
		mutate(&p)
		if _, _, err := phoneVerificationCommand(owner, command, p); err == nil {
			t.Fatal("foreign effects or nonconsuming verification accepted")
		}
	}
	for _, mutate := range []func(*PhoneVerificationIntent){
		func(i *PhoneVerificationIntent) { i.Change.Action = identity.IdentifierVerifyPrimary },
		func(i *PhoneVerificationIntent) { i.Change.Kind = identity.IdentifierEmail },
		func(i *PhoneVerificationIntent) { i.Change.ExpectedIdentifierVersion++ },
		func(i *PhoneVerificationIntent) { i.Change.ExpectedVerificationVersion++ },
		func(i *PhoneVerificationIntent) { i.Change.ExpectedUserVersion = ^uint64(0) },
		func(i *PhoneVerificationIntent) { i.Change.ExpectedAuthorityVersion = ^uint64(0) },
		func(i *PhoneVerificationIntent) { i.CanonicalNumber = "0401234567" },
		func(i *PhoneVerificationIntent) { i.NormalizationProfile = "" },
		func(i *PhoneVerificationIntent) { i.NormalizationVersion = 0 },
		func(i *PhoneVerificationIntent) { i.EnrollmentCommandID = "" },
	} {
		i := owner.intent
		mutate(&i)
		if _, err := PhoneVerificationFields(i); err == nil {
			t.Fatal("unsupported phone transition accepted")
		}
	}
	if err := (Work{}).RequirePhoneVerificationTarget(context.Background(), owner, command); err == nil {
		t.Fatal("caller target fabricated a live admission")
	}
}

func TestPhoneVerificationOnlyMapsItsOwnPersistedSuccessor(t *testing.T) {
	owner, spec, plan := phoneVerificationFixture(t)
	original := CredentialAdmission{Credential: identity.CredentialRef{ID: "password", Kind: identity.CredentialPassword,
		Owner: "identity/password", Version: 3}, UserAuthorityVersion: 6, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 8}
	progress := phoneVerificationProgress{intent: owner.intent, applied: true,
		before:   identity.IdentifierState{User: identity.User{Version: 10}, AuthorityVersion: 5},
		mutation: identity.IdentifierMutation{State: identity.IdentifierState{User: identity.User{Version: 11}, AuthorityVersion: 6}}}
	w := Work{state: &workState{binding: spec.Binding, feature: plan.Feature, phoneVerification: &progress}}
	got, err := otpPhoneVerificationCredential(w, spec.Binding, original)
	want := original
	want.IdentifierAuthorityVersion++
	if err != nil || got != want {
		t.Fatal("phone confirmation failed exact own-successor mapping", err)
	}
	for _, mutate := range []func(*phoneVerificationProgress, *CredentialAdmission, *identity.CommandBinding){
		func(p *phoneVerificationProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.mutation.State.AuthorityVersion++
		},
		func(p *phoneVerificationProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.mutation.State.User.Version++
		},
		func(p *phoneVerificationProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.intent.Change.ID = "other-phone"
		},
		func(_ *phoneVerificationProgress, c *CredentialAdmission, _ *identity.CommandBinding) {
			c.IdentifierAuthorityVersion++
		},
		func(_ *phoneVerificationProgress, _ *CredentialAdmission, b *identity.CommandBinding) {
			b.UserID = "other-user"
		},
	} {
		p, c, b := progress, original, spec.Binding
		mutate(&p, &c, &b)
		work := Work{state: &workState{binding: spec.Binding, feature: plan.Feature, phoneVerification: &p}}
		if _, err := otpPhoneVerificationCredential(work, b, c); err == nil {
			t.Fatal("arbitrary newer phone authority admitted")
		}
	}
	progress.applied = false
	if got, err := otpPhoneVerificationCredential(w, spec.Binding, original); err != nil || got != original {
		t.Fatal("unapplied phone confirmation renewed authority")
	}
}

func TestPhoneVerificationTargetRequiresExactPendingGeneration(t *testing.T) {
	owner, _, plan := phoneVerificationFixture(t)
	i := owner.intent
	state := identity.IdentifierState{User: identity.User{Version: i.Change.ExpectedUserVersion}, AuthorityVersion: i.Change.ExpectedAuthorityVersion,
		Identifiers: []identity.Identifier{{ID: i.Change.ID, Kind: identity.IdentifierPhone, CanonicalValue: i.CanonicalNumber,
			NormalizationProfile: i.NormalizationProfile, NormalizationVersion: i.NormalizationVersion, Version: 1}},
		Verifications: []identity.Verification{{IdentifierID: i.Change.ID, State: identity.VerificationPending, Version: 1}}}
	if !phoneVerificationTarget(state, i) {
		t.Fatal("original pending phone denied")
	}
	for _, mutate := range []func(*identity.IdentifierState){
		func(s *identity.IdentifierState) { s.User.Version++ },
		func(s *identity.IdentifierState) { s.AuthorityVersion++ },
		func(s *identity.IdentifierState) { s.Identifiers[0].Verified = true },
		func(s *identity.IdentifierState) { s.Identifiers[0].Primary = true },
		func(s *identity.IdentifierState) { s.Identifiers[0].Kind = identity.IdentifierEmail },
		func(s *identity.IdentifierState) { s.Identifiers[0].NormalizationVersion++ },
		func(s *identity.IdentifierState) { s.Identifiers[0].CanonicalValue = "+358401234568" },
		func(s *identity.IdentifierState) { s.Verifications[0].Version++ },
		func(s *identity.IdentifierState) { s.Verifications[0].State = identity.VerificationVerified },
	} {
		changed := state
		changed.Identifiers = append([]identity.Identifier(nil), state.Identifiers...)
		changed.Verifications = append([]identity.Verification(nil), state.Verifications...)
		mutate(&changed)
		if phoneVerificationTarget(changed, i) {
			t.Fatal("newer, verified or replaced phone admitted")
		}
	}
	// A contributor's receipt cannot substitute for the actual kernel mutation.
	w := Work{state: &workState{feature: plan.Feature, execution: &domainExecution{reservation: &reservationState{plan: &admittedKernelPlan{feature: plan.Feature, lifecycle: plan.Lifecycle}}}}}
	r := identity.CommandResult{Feature: &identity.FeatureReceipt{Operation: plan.Feature.Operation, BeforeVersion: 1, AfterVersion: 2}}
	w.state.featureReceipt = r.Feature
	if matchesDomainResult(w, r) {
		t.Fatal("receipt fabricated phone possession")
	}
	w.state.phoneVerification = &phoneVerificationProgress{applied: true}
	if !matchesDomainResult(w, r) {
		t.Fatal("applied kernel verification denied its receipt")
	}
}
