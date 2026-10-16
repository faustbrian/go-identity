package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

type otpEmailChangePreparationProbe struct{ *emailOTPMapper }

func (*otpEmailChangePreparationProbe) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return nil
}

func (*otpEmailChangePreparationProbe) ValidateOTPAttemptCommand(identity.Command, OTPAttemptPlan) error {
	return nil
}
func (*otpEmailChangePreparationProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}
func (*otpEmailChangePreparationProbe) RecordOTPAttemptDenial(context.Context, OTPAttemptWork) (OTPAttemptDisposition, error) {
	return OTPAttemptUnchanged, nil
}
func (*otpEmailChangePreparationProbe) ReserveOTP(context.Context, OTPReservationWork) error {
	return nil
}
func (*otpEmailChangePreparationProbe) RebindOTP(context.Context, OTPReservationWork) error {
	return nil
}

func TestOTPEmailChangePreparationEnlistsOnlyItsRequiredNotice(t *testing.T) {
	mapper, spec, plan := otpEmailChangeFixture(t)
	owner := &otpEmailChangePreparationProbe{mapper}
	c, _, existing := featurePlanFixture(t)
	registry, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{existing.Contributors[0]}}, &riskPassiveProbe{registryContributor{existing.Contributors[1]}}, &riskPassiveProbe{registryContributor{existing.Contributors[2]}}, owner, &deliveryPlanProbe{}})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	_, attempt := otpPlanFixture(t)
	send := plan.OTP.ChallengeID
	plan.OTP = attempt.OTP
	plan.OTP.ChallengeID = send
	plan.Contributors = registry.Descriptors()
	plan.Audits = existing.Audits
	plan.Audits[0].EventType = spec.Binding.OperationID
	plan.Audits[0].RetentionClass = "protected"
	plan.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &spec.Operation, "identifier", spec.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	command := codeCodecCommand(t, spec, "123456")
	prepared, err := c.PrepareOTPReservationPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal("exact primary OTP plus required notice cannot reach preparation", err)
	}
	if prepared.Delivery == nil || !reflect.DeepEqual(prepared.Delivery, plan.Delivery) {
		t.Fatal("required notice omitted from frozen consuming plan")
	}
	other := spec
	other.Operation = otpEmailVerificationOperation()
	other.Binding.OperationID, other.Binding.SchemaID = other.Operation.OperationID, other.Operation.SchemaID
	otherPlan := plan
	f := *plan.Feature
	f.Operation = other.Operation
	otherPlan.Feature = &f
	if _, err := c.PrepareOTPReservationPlan(other.Binding, codeCodecCommand(t, other, "123456"), otherPlan); err == nil {
		t.Fatal("verification-only attempt admitted delivery effects")
	}
}

func TestOTPEmailInitialPrimaryRequiresExplicitFields(t *testing.T) {
	owner, spec, plan := otpEmailChangeFixture(t)
	owner.intent.Previous.Primary = false
	owner.intent.Previous.AllowInitialPrimary = true
	send := identity.CommandID(plan.OTP.ChallengeID)
	if _, err := OTPEmailChangeFields(owner.intent, send); err == nil {
		t.Fatal("existing primary-only fields acquired initial authority")
	}
	var err error
	spec.Fields, err = OTPEmailInitialPrimaryFields(owner.intent, send)
	if err != nil {
		t.Fatal("explicit initial-primary fields denied", err)
	}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil || validateFeatureCommand(owner, command, plan) != nil {
		t.Fatal("explicit initial-primary intent cannot reach the shared writer", err)
	}
	for _, previous := range []ManagedEmailPrevious{
		{},
		{ID: "old-primary", CanonicalAddress: "old@example.test", IdentifierVersion: 3, VerificationVersion: 2, Primary: true, AllowInitialPrimary: true},
		{ID: "old-primary", CanonicalAddress: "old@example.test", IdentifierVersion: 3, VerificationVersion: 2},
	} {
		owner.intent.Previous = previous
		if _, err := OTPEmailInitialPrimaryFields(owner.intent, send); err == nil {
			t.Fatal("initial-primary fields inferred missing or replacement policy")
		}
	}
}

func otpEmailChangeFixture(t *testing.T) (*emailOTPMapper, identity.FeatureCommandSpec, CommandPlan) {
	t.Helper()
	owner, spec, plan := otpEmailFixture(t)
	op := otpEmailChangeOperation()
	spec.Operation = op
	spec.Binding.OperationID, spec.Binding.SchemaID = op.OperationID, op.SchemaID
	owner.intent.Change.Action = identity.IdentifierVerifyPrimary
	owner.intent.RequestCommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
	owner.intent.Previous = ManagedEmailPrevious{ID: "old-primary", CanonicalAddress: "old@example.test", IdentifierVersion: 3, VerificationVersion: 2, Primary: true}
	owner.operations = []identity.FeatureOperation{op}
	var err error
	spec.Fields, err = OTPEmailChangeFields(owner.intent, identity.CommandID(plan.OTP.ChallengeID))
	if err != nil {
		t.Fatal("original change fields rejected", err)
	}
	plan.Feature.Operation = op
	plan.Lifecycle.EventType = "identifier.primary-changed.v1"
	plan.Delivery = deliveryTestPlan()
	plan.Delivery.Intents[0].SubjectID = string(spec.Binding.UserID)
	plan.Delivery.Intents[0].Purpose = "identity.email.change-notification"
	plan.Contributors = []ContributorDescriptor{owner.Descriptor(), plan.Delivery.Contributor}
	return owner, spec, plan
}

func TestOTPEmailChangeAuditRetainsItsSelectorAndActualTransition(t *testing.T) {
	_, spec, _ := otpEmailChangeFixture(t)
	for _, class := range []string{"committed", "denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		t.Run(class, func(t *testing.T) {
			record, err := securityMutationAudit(context.Background(), spec.Binding, 2, 3, time.Now().UTC(), class, spec.Binding.OperationID, "identifier", spec.Binding.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			attributes := record.Attributes()
			if attributes["authentication.recovery_path"] != "email_change_otp" {
				t.Fatal("primary replacement audit lost its distinct original selector")
			}
			after := "2"
			if class == "committed" {
				after = "3"
			}
			if attributes["aggregate.before_version"] != "2" || attributes["aggregate.after_version"] != after || !validSecurityAuditRecord(record, "identifier") {
				t.Fatal("audit describes a fictitious replacement")
			}
			if _, err := securityAuditBindingDigest(spec.Binding, &spec.Operation, "identifier", spec.Binding.RecordID, record); err != nil {
				t.Fatal("replacement audit not bound to native operation", err)
			}
		})
	}
}

func TestOTPEmailChangeBindsDistinctOriginSendAndPrimaryReplacement(t *testing.T) {
	owner, spec, plan := otpEmailChangeFixture(t)
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFeatureCommand(owner, command, plan); err != nil {
		t.Fatal("exact independently issued change plan denied", err)
	}
	for name, mutate := range map[string]func(*ManagedEmailVerificationIntent){
		"verification only": func(i *ManagedEmailVerificationIntent) { i.Change.Action = identity.IdentifierVerify },
		"generic pending":   func(i *ManagedEmailVerificationIntent) { i.Previous = ManagedEmailPrevious{} },
		"initial primary": func(i *ManagedEmailVerificationIntent) {
			i.Previous.Primary = false
			i.Previous.AllowInitialPrimary = true
		},
		"send as origin": func(i *ManagedEmailVerificationIntent) { i.RequestCommandID = identity.CommandID(plan.OTP.ChallengeID) },
	} {
		t.Run(name, func(t *testing.T) {
			i := owner.intent
			mutate(&i)
			if _, err := OTPEmailChangeFields(i, identity.CommandID(plan.OTP.ChallengeID)); err == nil {
				t.Fatal("unsupported intent entered primary replacement")
			}
		})
	}
}

func TestOTPEmailChangeRejectsMissingNoticeOrAliasedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*identity.FeatureCommandSpec, *CommandPlan){
		"missing notice":    func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Delivery = nil },
		"unenlisted notice": func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Contributors = p.Contributors[:1] },
		"foreign notice":    func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Delivery.Intents[0].SubjectID = "other-user" },
		"wrong notice purpose": func(_ *identity.FeatureCommandSpec, p *CommandPlan) {
			p.Delivery.Intents[0].Purpose = "identity.email.verification-request"
		},
		"wrong lifecycle":    func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Lifecycle.EventType = "identifier.verified.v1" },
		"nonconsuming check": func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.OTP.Mode = OTPCheck },
		"link reinterpreted": func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"foreign challenge":  func(_ *identity.FeatureCommandSpec, p *CommandPlan) { p.OTP.ChallengeID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"generic verification selector": func(s *identity.FeatureCommandSpec, _ *CommandPlan) {
			for n := range s.Fields {
				if s.Fields[n].Name == "email-otp.recovery-path" {
					s.Fields[n].Value.Text = "email_verification_otp"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			owner, spec, plan := otpEmailChangeFixture(t)
			mutate(&spec, &plan)
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				return
			}
			if err := validateFeatureCommand(owner, command, plan); err == nil {
				t.Fatal("incomplete or substituted change plan admitted")
			}
		})
	}
}

func TestOTPEmailChangeRetainsConsumptionAndNoticeInExistingPlanEncoding(t *testing.T) {
	owner, spec, plan := otpEmailChangeFixture(t)
	_, _, base := featurePlanFixture(t)
	plan.Contributors = append(append([]ContributorDescriptor(nil), base.Contributors[:3]...), owner.Descriptor(), plan.Delivery.Contributor)
	plan.Audits = base.Audits
	plan.Audits[0].EventType = spec.Binding.OperationID
	plan.Audits[0].RetentionClass = "protected"
	_, attempt := otpPlanFixture(t)
	send := plan.OTP.ChallengeID
	plan.OTP = attempt.OTP
	plan.OTP.ChallengeID = send
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal("existing durable plan cannot carry required code/notice together", err)
	}
	decoded, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(decoded.Delivery, plan.Delivery) || !reflect.DeepEqual(decoded.OTP, plan.OTP) || !reflect.DeepEqual(decoded.Feature, plan.Feature) {
		t.Fatal("original consumption/notification changed through retained plan", err)
	}
}

func TestOTPEmailChangeAdmitsOnlyItsOwnPersistedSuccessor(t *testing.T) {
	owner, spec, plan := otpEmailChangeFixture(t)
	original := CredentialAdmission{Credential: identity.CredentialRef{ID: "password", Kind: identity.CredentialPassword, Version: 3, Owner: "identity/password"}, UserAuthorityVersion: 6, IdentifierAuthorityVersion: 4, CredentialAuthorityVersion: 8}
	progress := managedEmailVerificationProgress{intent: owner.intent, applied: true, before: identity.IdentifierState{User: identity.User{Version: 9}, AuthorityVersion: 4}, mutation: identity.IdentifierMutation{State: identity.IdentifierState{User: identity.User{Version: 10}, AuthorityVersion: 5}}}
	w := Work{state: &workState{binding: spec.Binding, feature: plan.Feature, managedEmailVerification: &progress}}
	want := original
	want.IdentifierAuthorityVersion++
	got, err := otpEmailVerificationCredential(w, spec.Binding, original)
	if err != nil || got != want {
		t.Fatal("primary replacement renewed or changed unrelated credential authority", err)
	}
	for _, mutate := range []func(*managedEmailVerificationProgress){
		func(p *managedEmailVerificationProgress) { p.before.AuthorityVersion++ },
		func(p *managedEmailVerificationProgress) { p.mutation.State.AuthorityVersion++ },
		func(p *managedEmailVerificationProgress) { p.mutation.State.User.Version++ },
		func(p *managedEmailVerificationProgress) { p.intent.Change.ID = "another-candidate" },
	} {
		changed := progress
		mutate(&changed)
		work := Work{state: &workState{binding: spec.Binding, feature: plan.Feature, managedEmailVerification: &changed}}
		if _, err := otpEmailVerificationCredential(work, spec.Binding, original); err == nil {
			t.Fatal("unrelated successor admitted as this primary replacement")
		}
	}
	if !otpFeatureInputAdmissionRequired(plan) {
		t.Fatal("primary replacement can compare or debit code before original-target admission")
	}
}
