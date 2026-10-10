package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	"testing"
)

func TestPreparedFeatureRejectsUnownedInputs(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			result, err := c.ExecutePreparedFeature(ctx, identity.Command{}, CommandPlan{})
			if err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("unowned preparation executed")
			}
		}
	}
}

func TestPreparationFinalDeclarationConservesCounterScope(t *testing.T) {
	_, _, plan := featurePlanFixture(t)
	plan.SubjectType = "session"
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
	if !preparationFinalDeclaration(codecBinding(), plan, plan) {
		t.Fatal("matching counter declaration rejected")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion++ },
		func(p *CommandPlan) { p.CommandCounters.Fingerprint[0]++ },
		func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
	} {
		final := plan
		counter := *plan.CommandCounters
		final.CommandCounters = &counter
		change(&final)
		if preparationFinalDeclaration(codecBinding(), plan, final) {
			t.Fatal("final plan changed protected scope")
		}
	}
	without := plan
	without.CommandCounters = nil
	if preparationFinalDeclaration(codecBinding(), without, plan) {
		t.Fatal("generated plan introduced an uncharged counter")
	}
}

func TestPreparationFinalDeclarationAllowsSignupVerificationIssuance(t *testing.T) {
	b, original, final := signupPreparationPlanFixture(t)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("original prepared signup cannot enlist generated verification issuance")
	}
	if !preparationProtected(final) {
		t.Fatal("issuance entered the original admission declaration")
	}
	final.Delivery = deliveryTestPlan()
	final.Contributors = append(final.Contributors, final.Delivery.Contributor)
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("original verification issuance cannot enlist delivery")
	}
}

func signupPreparationPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan, CommandPlan) {
	t.Helper()
	_, _, original := featurePlanFixture(t)
	original.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
	original.Contributors[3] = original.Feature.Contributor
	original.SubjectType, original.Lifecycle = "user", &LifecyclePlan{EventType: "user.created.v1"}
	final := original
	final.CapabilityIssuance = issuanceTestPlan()
	final.CapabilityIssuance.RegistrationUserID = "new-user"
	final.Contributors = append(append([]ContributorDescriptor(nil), original.Contributors...), final.CapabilityIssuance.Contributor)
	b := codecBinding()
	b.UserID, b.AnonymousFlowID, b.RecordID = "", string(b.CommandID), ""
	b.OperationID, b.SchemaID, b.SchemaVersion = original.Feature.Operation.OperationID, original.Feature.Operation.SchemaID, original.Feature.Operation.SchemaVersion
	return b, original, final
}

func TestPreparationSignupIssuanceDoesNotBroadenProtectedProfiles(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"missing-target":     func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.RegistrationUserID = "" },
		"authenticated-user": func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "new-user" },
		"missing-flow":       func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"non-verification": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.attach"
		},
		"invalid-grant":  func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.Grants[0].MaxUses = 2 },
		"consumption":    func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"identifier":     func(_ *identity.CommandBinding, p *CommandPlan) { p.IdentifierAdmission = &ContributorDescriptor{} },
		"otp":            func(_ *identity.CommandBinding, p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		"risk":           func(_ *identity.CommandBinding, p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		"captcha":        func(_ *identity.CommandBinding, p *CommandPlan) { p.CaptchaEvidence = &CaptchaEvidencePlan{} },
		"captcha-replay": func(_ *identity.CommandBinding, p *CommandPlan) { p.CaptchaReplayReservation = true },
		"foreign-owner":  func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.ContractID = "foreign" },
		"wrong-operation": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.signin"
		},
		"changed-lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "other.created.v1" },
		"changed-audit":     func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].BindingDigest[0]++ },
		"removed-base":      func(_ *identity.CommandBinding, p *CommandPlan) { p.Contributors = p.Contributors[1:] },
		"reordered-base": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors[0], p.Contributors[1] = p.Contributors[1], p.Contributors[0]
		},
		"duplicate-issuer": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
		},
		"unknown-owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "foreign", ContractID: "foreign", Version: 1})
		},
		"delivery-before-issuer": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Delivery = deliveryTestPlan()
			p.Contributors[len(p.Contributors)-1] = p.Delivery.Contributor
			p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, original, final := signupPreparationPlanFixture(t)
			feature, lifecycle := *final.Feature, *final.Lifecycle
			final.Feature, final.Lifecycle = &feature, &lifecycle
			final.Audits = append([]AuditPlan(nil), final.Audits...)
			change(&b, &final)
			if preparationFinalDeclaration(b, original, final) {
				t.Fatal("generated issuance broadened original preparation authority")
			}
		})
	}
}
