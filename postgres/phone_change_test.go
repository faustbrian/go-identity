package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func phoneChangeIntent() PhoneChangeIntent {
	return PhoneChangeIntent{Change: identity.IdentifierChange{
		TenantID: "tenant", UserID: "user", ID: "phone", Action: identity.IdentifierReplaceVerifiedPhone,
		Kind: identity.IdentifierPhone, CanonicalValue: "+12025550124", DisplayValue: "+12025550124",
		NormalizationProfile: "phone-e164-v1", NormalizationVersion: 1,
		ExpectedUserVersion: 5, ExpectedAuthorityVersion: 4,
		ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2,
	}, PreviousNumber: "+12025550123", PreviousNormalizationProfile: "phone-e164-v1",
		PreviousNormalizationVersion: 1, SendCommandID: "AAAAAAAAAAAAAAAAAAAAAQ", Reason: "user-requested"}
}

type phoneChangeMapperFixture struct {
	PhoneChangeContributor
	intent PhoneChangeIntent
	domain *PhoneChangeDomain
}

func (p phoneChangeMapperFixture) PhoneChange(identity.Command) (PhoneChangeIntent, *PhoneChangeDomain, error) {
	return p.intent, p.domain, nil
}

func TestPhoneChangeCommandRequiresExactConsumingAndNoticePlan(t *testing.T) {
	i := phoneChangeIntent()
	fields, err := PhoneChangeFields(i)
	if err != nil {
		t.Fatal(err)
	}
	op := phoneChangeOperation()
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, string(i.Change.ID)
	b.TenantID, b.UserID, b.ActorID = i.Change.TenantID, i.Change.UserID, identity.ActorID(i.Change.UserID)
	policy, err := freezeIdentifierChangeCascade(removalCascadeConfig())
	if err != nil {
		t.Fatal(err)
	}
	domainState := &phoneChangeDomain{
		directory: &PhoneEnrollmentDomain{repository: &Repository{}, profile: i.Change.NormalizationProfile,
			version: 1, reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {7}}, reuseCooldown: 24 * time.Hour}},
		cascade: policy}
	owner := phoneChangeMapperFixture{intent: i, domain: &PhoneChangeDomain{read: func() *phoneChangeDomain { return domainState }}}
	plan := CommandPlan{Feature: &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, Operation: op},
		SubjectType: "identifier", Lifecycle: &LifecyclePlan{EventType: "identifier.changed.v1", BeforeVersion: 2, AfterVersion: 3},
		OTP:      &OTPAttemptPlan{Mode: OTPConsume, ChallengeID: string(i.SendCommandID)},
		Delivery: &DeliveryPlan{Intents: []DeliveryIntentPlan{{Purpose: "identity.phone.change-notification", SubjectID: string(b.UserID)}}},
		Audits:   []AuditPlan{{EventType: "identity.identifier.change", Required: true, RetentionClass: "standard"}}}
	build := func(fields []identity.FeatureField) identity.Command {
		t.Helper()
		command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	command := build(fields)
	if got, domain, err := phoneChangeCommand(owner, command, plan); err != nil || got != i || domain != owner.domain {
		t.Fatal("exact change command rejected", err)
	}
	for index := range fields {
		changed := append([]identity.FeatureField(nil), fields...)
		if changed[index].Value.Kind == identity.FeatureText {
			changed[index].Value.Text += "other"
		} else {
			changed[index].Value.Uint64++
		}
		if _, _, err := phoneChangeCommand(owner, build(changed), plan); err == nil {
			t.Fatal("substituted replacement field admitted")
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.OTP = nil },
		func(p *CommandPlan) {
			p.OTP = &OTPAttemptPlan{Mode: OTPCheck, ChallengeID: string(i.SendCommandID)}
		},
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{Mode: OTPConsume, ChallengeID: "different"} },
		func(p *CommandPlan) { p.Delivery = nil },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 2, AfterVersion: 3}
		},
		func(p *CommandPlan) {
			p.Audits = []AuditPlan{{EventType: "identity.phone.update", Required: true, RetentionClass: "protected"}}
		},
		func(p *CommandPlan) {
			p.Audits = []AuditPlan{{EventType: "identity.identifier.change", Required: true, RetentionClass: "protected"}}
		},
	} {
		p := plan
		mutate(&p)
		if _, _, err := phoneChangeCommand(owner, command, p); err == nil {
			t.Fatal("weaker or unrelated consuming plan admitted")
		}
	}
	if err := (Work{}).RequirePhoneChangeTarget(context.Background(), owner, command); err == nil {
		t.Fatal("zero Work manufactured current replacement authority")
	}
}

func phoneChangeState(now time.Time) identity.IdentifierState {
	return identity.IdentifierState{User: identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 5},
		AuthorityVersion: 4,
		Identifiers: []identity.Identifier{{ID: "email", UserID: "user", Kind: identity.IdentifierEmail,
			CanonicalValue: "retained@example.invalid", Verified: true, Primary: true, Version: 3},
			{ID: "phone", UserID: "user", Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123",
				Verified: true, Version: 2, NormalizationProfile: "phone-e164-v1", NormalizationVersion: 1}},
		Verifications: []identity.Verification{{IdentifierID: "email", State: identity.VerificationVerified,
			VerifiedAt: now.Add(-time.Hour), Version: 2}, {IdentifierID: "phone", State: identity.VerificationVerified,
			VerifiedAt: now.Add(-time.Hour), Version: 2}}}
}

func TestPhoneChangeFreezesBothNumberBindingsAndPredecessors(t *testing.T) {
	base := phoneChangeIntent()
	fields, err := PhoneChangeFields(base)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]identity.FeatureValue{}
	for _, field := range fields {
		if _, duplicate := seen[field.Name]; duplicate {
			t.Fatal("duplicate frozen field")
		}
		seen[field.Name] = field.Value
	}
	if seen["phone-change.previous-number"].Text != base.PreviousNumber ||
		seen["phone-change.new-number"].Text != base.Change.CanonicalValue ||
		seen["phone-change.identifier-version"].Uint64 != 2 ||
		seen["phone-change.verification-version"].Uint64 != 2 ||
		seen["phone-change.send-command"].Text != string(base.SendCommandID) {
		t.Fatal("frozen replacement omitted target, new possession or original send")
	}
	for name, mutate := range map[string]func(*PhoneChangeIntent){
		"same":                  func(i *PhoneChangeIntent) { i.PreviousNumber = i.Change.CanonicalValue },
		"unbound-previous":      func(i *PhoneChangeIntent) { i.PreviousNormalizationVersion = 0 },
		"wrong-kind":            func(i *PhoneChangeIntent) { i.Change.Kind = identity.IdentifierEmail },
		"attach":                func(i *PhoneChangeIntent) { i.Change.Action = identity.IdentifierAttach },
		"missing-send":          func(i *PhoneChangeIntent) { i.SendCommandID = "" },
		"overflow-aggregate":    func(i *PhoneChangeIntent) { i.Change.ExpectedUserVersion = ^uint64(0) },
		"overflow-authority":    func(i *PhoneChangeIntent) { i.Change.ExpectedAuthorityVersion = ^uint64(0) },
		"overflow-record":       func(i *PhoneChangeIntent) { i.Change.ExpectedIdentifierVersion = ^uint64(0) },
		"overflow-verification": func(i *PhoneChangeIntent) { i.Change.ExpectedVerificationVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			i := base
			mutate(&i)
			if _, err := PhoneChangeFields(i); err == nil {
				t.Fatal("invalid replacement intent accepted")
			}
		})
	}
}

func TestPhoneChangeMutationRetiresOldAndVerifiesNewWithoutTouchingEmail(t *testing.T) {
	now := time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)
	before, intent := phoneChangeState(now), phoneChangeIntent()
	mutation, err := phoneChangeMutation(before, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Retired == nil || mutation.Retired.CanonicalValue != intent.PreviousNumber {
		t.Fatal("replacement did not retain retired original")
	}
	after := mutation.State
	if after.User.Version != 6 || after.AuthorityVersion != 5 ||
		after.Identifiers[1].CanonicalValue != intent.Change.CanonicalValue || !after.Identifiers[1].Verified ||
		after.Identifiers[1].Version != 3 || after.Verifications[1].Version != 3 ||
		after.Verifications[1].VerifiedAt != now || after.Identifiers[0] != before.Identifiers[0] ||
		after.Verifications[0] != before.Verifications[0] || before.Identifiers[1].CanonicalValue != intent.PreviousNumber {
		t.Fatal("replacement changed unrelated identity, lost verification or mutated predecessor")
	}
	for name, mutate := range map[string]func(*identity.IdentifierState){
		"unverified": func(s *identity.IdentifierState) {
			s.Identifiers[1].Verified = false
			s.Verifications[1].State = identity.VerificationPending
			s.Verifications[1].VerifiedAt = time.Time{}
		},
		"version":          func(s *identity.IdentifierState) { s.Identifiers[1].Version++ },
		"different-number": func(s *identity.IdentifierState) { s.Identifiers[1].CanonicalValue = "+12025550125" },
		"profile":          func(s *identity.IdentifierState) { s.Identifiers[1].NormalizationVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := phoneChangeState(now)
			mutate(&candidate)
			if _, err := phoneChangeMutation(candidate, intent, now); err == nil {
				t.Fatal("replacement admitted a different or unverified predecessor")
			}
		})
	}
}

func TestPhoneChangeDomainRedactsBorrowedOwnersAndReuseKeys(t *testing.T) {
	state := &phoneChangeDomain{directory: &PhoneEnrollmentDomain{reuse: identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {17}}}}}
	domain := &PhoneChangeDomain{read: func() *phoneChangeDomain { return state }}
	values := []struct {
		value  any
		marker string
	}{
		{PhoneChangeDomainConfig{Directory: PhoneEnrollmentDomainConfig{RetainedIdentifierKeys: map[uint32][32]byte{1: {17}}}}, "postgres.PhoneChangeDomainConfig(redacted)"},
		{domain, "postgres.PhoneChangeDomain(redacted)"},
	}
	for _, item := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
			if got := fmt.Sprintf(verb, item.value); got != item.marker {
				t.Fatal("public domain/config traversed borrowed custody")
			}
		}
		if _, err := json.Marshal(item.value); err == nil {
			t.Fatal("implicit domain/config export accepted")
		}
	}
}

func TestPhoneChangeMapsOnlyItsOwnAppliedIdentifierSuccessor(t *testing.T) {
	i := phoneChangeIntent()
	b := codecBinding()
	op := phoneChangeOperation()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = i.Change.TenantID, i.Change.UserID, identity.ActorID(i.Change.UserID), string(i.Change.ID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	f := &FeatureRegistration{Operation: op}
	before := phoneChangeState(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC))
	mutation, err := phoneChangeMutation(before, i, time.Date(2026, 10, 19, 9, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	p := emailRemovalProgress{intent: EmailRemovalIntent{Change: i.Change}, before: before, mutation: mutation, applied: true}
	original := CredentialAdmission{Credential: identity.CredentialRef{ID: "password", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 3},
		UserAuthorityVersion: 6, IdentifierAuthorityVersion: before.AuthorityVersion, CredentialAuthorityVersion: 8}
	w := Work{state: &workState{binding: b, feature: f, phoneChange: &p}}
	got, err := otpMutationCredential(w, b, original)
	want := original
	want.IdentifierAuthorityVersion++
	if err != nil || got != want {
		t.Fatal("replacement did not map its own persisted successor", err)
	}
	for _, mutate := range []func(*emailRemovalProgress, *CredentialAdmission, *identity.CommandBinding){
		func(p *emailRemovalProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.mutation.State.AuthorityVersion++
		},
		func(p *emailRemovalProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.mutation.State.User.Version++
		},
		func(p *emailRemovalProgress, _ *CredentialAdmission, _ *identity.CommandBinding) {
			p.intent.Change.ID = "foreign-phone"
		},
		func(_ *emailRemovalProgress, c *CredentialAdmission, _ *identity.CommandBinding) {
			c.IdentifierAuthorityVersion++
		},
		func(_ *emailRemovalProgress, _ *CredentialAdmission, b *identity.CommandBinding) {
			b.UserID = "foreign-user"
		},
	} {
		candidate, admission, binding := p, original, b
		mutate(&candidate, &admission, &binding)
		work := Work{state: &workState{binding: b, feature: f, phoneChange: &candidate}}
		if _, err := otpMutationCredential(work, binding, admission); err == nil {
			t.Fatal("replacement mapped arbitrary newer or foreign authority")
		}
	}
	p.applied = false
	if got, err := otpMutationCredential(w, b, original); err != nil || got != original {
		t.Fatal("unapplied replacement renewed original authority")
	}
}

func TestPhoneChangeRequiresPreAttemptCurrentInputAdmission(t *testing.T) {
	p := CommandPlan{OTP: &OTPAttemptPlan{Mode: OTPConsume}, Feature: &FeatureRegistration{Operation: phoneChangeOperation()}}
	if !otpFeatureInputAdmissionRequired(p) {
		t.Fatal("replacement can compare/debit an OTP before original input admission")
	}
}
