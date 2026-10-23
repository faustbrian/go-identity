package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestOTPActivePreparationRetainsOriginalIntentAndAddsOnlyNativeConsume(t *testing.T) {
	b, original := magicLinkConsumptionPlanFixture(t)
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-step-up", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, "AwMDAwMDAwMDAwMDAwMDAw"
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	original.Capability = nil
	original.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, Operation: op}
	original.SubjectType = "factor"
	original.Lifecycle = &LifecyclePlan{EventType: "factor.verified.v1", BeforeVersion: 3, AfterVersion: 4}
	original.Contributors = []ContributorDescriptor{original.Feature.Contributor}
	final := original
	final.OTP = &OTPAttemptPlan{AttemptID: "BAQEBAQEBAQEBAQEBAQEBA", AttemptFingerprint: [32]byte{1}, FingerprintKeyVersion: 1, ChallengeID: "BQUFBQUFBQUFBQUFBQUFBQ", ScopeDigest: [32]byte{2}, DigestKeyVersion: 1, ExpectedVersion: 1, Mode: OTPConsume}
	final.Contributors = append([]ContributorDescriptor{original.Feature.Contributor}, otpDescriptor())
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("active OTP cannot retain its original consuming attempt")
	}
	for name, change := range map[string]func(*CommandPlan){
		"check instead of consume": func(p *CommandPlan) { v := *p.OTP; v.Mode = OTPCheck; p.OTP = &v },
		"missing OTP owner":        func(p *CommandPlan) { p.Contributors = p.Contributors[:1] },
		"login child":              func(p *CommandPlan) { p.MFACompletion = &MFACompletionPlan{} },
		"delivery":                 func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"capability":               func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"removed counters":         func(p *CommandPlan) { p.CommandCounters = nil },
		"enrollment substitution":  func(p *CommandPlan) { v := *p.Lifecycle; v.EventType = "factor.enrolled.v1"; p.Lifecycle = &v },
		"changed action schema":    func(p *CommandPlan) { v := *p.Feature; v.Operation.SchemaID = "foreign"; p.Feature = &v },
	} {
		t.Run(name, func(t *testing.T) {
			bad := final
			change(&bad)
			if preparationFinalDeclaration(b, original, bad) {
				t.Fatal("active restoration expanded original authority")
			}
		})
	}
}
