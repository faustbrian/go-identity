package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type phoneRemovalMapperFixture struct {
	FeatureCommitContributor
	intent PhoneRemovalIntent
	domain *PhoneRemovalDomain
}

func (p phoneRemovalMapperFixture) PhoneRemoval(identity.Command) (PhoneRemovalIntent, *PhoneRemovalDomain, error) {
	return p.intent, p.domain, nil
}

func phoneRemovalIntent() PhoneRemovalIntent {
	return PhoneRemovalIntent{Change: identity.IdentifierChange{TenantID: "tenant-a", UserID: "user-a", ID: "verified-phone", Action: identity.IdentifierRemove, ExpectedUserVersion: 10, ExpectedAuthorityVersion: 5, ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2},
		CanonicalNumber: "+358401234567", NormalizationProfile: phoneEnrollmentIntent().Change.NormalizationProfile, NormalizationVersion: 1, Reason: "user-requested"}
}

func TestPhoneRemovalConservesExactVerifiedTargetWithoutOTP(t *testing.T) {
	i := phoneRemovalIntent()
	fields, err := PhoneRemovalFields(i)
	if err != nil {
		t.Fatal(err)
	}
	b := codecBinding()
	op := phoneRemovalOperation()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, string(i.Change.ID)
	b.TenantID, b.UserID, b.ActorID = i.Change.TenantID, i.Change.UserID, identity.ActorID(i.Change.UserID)
	cascade, err := freezeIdentifierRemovalCascade(removalCascadeConfig())
	if err != nil {
		t.Fatal(err)
	}
	directory := &PhoneEnrollmentDomain{repository: &Repository{}, profile: i.NormalizationProfile, version: 1, reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}, reuseCooldown: 30 * 24 * time.Hour}}
	owner := phoneRemovalMapperFixture{intent: i, domain: &PhoneRemovalDomain{directory: directory, cascade: cascade}}
	plan := CommandPlan{Feature: &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op}, SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.removed.v1", BeforeVersion: 2, AfterVersion: 3}, Audits: []AuditPlan{{Required: true, RetentionClass: "protected"}}}
	build := func(spec identity.FeatureCommandSpec) identity.Command {
		t.Helper()
		c, err := identity.NewFeatureSessionCommand(spec, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}
	command := build(spec)
	if got, domain, err := phoneRemovalCommand(owner, command, plan); err != nil || got != i || domain != owner.domain {
		t.Fatal("exact phone removal intent rejected", err)
	}
	for index := range fields {
		s := spec
		s.Fields = append([]identity.FeatureField(nil), fields...)
		if s.Fields[index].Value.Kind == identity.FeatureText {
			s.Fields[index].Value.Text += "other"
		} else {
			s.Fields[index].Value.Uint64++
		}
		if _, _, err := phoneRemovalCommand(owner, build(s), plan); err == nil {
			t.Fatal("substituted phone removal custody accepted")
		}
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{Mode: OTPConsume} },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		func(p *CommandPlan) { p.CapabilityIssuance = &CapabilityIssuancePlan{} },
		func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 2, AfterVersion: 3}
		},
		func(p *CommandPlan) { p.Audits = nil },
	} {
		p := plan
		change(&p)
		if _, _, err := phoneRemovalCommand(owner, command, p); err == nil {
			t.Fatal("removal borrowed OTP, capability or unrelated effects")
		}
	}
	for _, change := range []func(*PhoneRemovalIntent){
		func(i *PhoneRemovalIntent) { i.CanonicalNumber = "0401234567" },
		func(i *PhoneRemovalIntent) { i.NormalizationProfile = "" },
		func(i *PhoneRemovalIntent) { i.NormalizationVersion = 0 },
		func(i *PhoneRemovalIntent) { i.Reason = "free text" },
		func(i *PhoneRemovalIntent) { i.Change.ExpectedIdentifierVersion = ^uint64(0) },
		func(i *PhoneRemovalIntent) { i.Change.Action = identity.IdentifierVerify },
	} {
		bad := i
		change(&bad)
		if _, err := PhoneRemovalFields(bad); err == nil {
			t.Fatal("invalid phone removal intent accepted")
		}
	}
	if err := (Work{}).RequirePhoneRemovalTarget(context.Background(), owner, command); err == nil {
		t.Fatal("caller intent fabricated live target admission")
	}
}
