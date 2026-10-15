package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestOTPEnrollmentPreparationRetainsOriginalIntentAndAddsOnlyNativeConsume(t *testing.T) {
	b, original := magicLinkConsumptionPlanFixture(t)
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, "AwMDAwMDAwMDAwMDAwMDAw"
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	original.Capability = nil
	original.Feature = &FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, Operation: op}
	original.SubjectType = "factor"
	original.Lifecycle = &LifecyclePlan{EventType: "factor.enrolled.v1", BeforeVersion: 2, AfterVersion: 3}
	original.Contributors = []ContributorDescriptor{original.Feature.Contributor}
	final := original
	final.OTP = &OTPAttemptPlan{AttemptID: "BAQEBAQEBAQEBAQEBAQEBA", AttemptFingerprint: [32]byte{1}, FingerprintKeyVersion: 1, ChallengeID: "BQUFBQUFBQUFBQUFBQUFBQ", ScopeDigest: [32]byte{2}, DigestKeyVersion: 1, ExpectedVersion: 1, Mode: OTPConsume}
	final.Contributors = append([]ContributorDescriptor{original.Feature.Contributor}, otpDescriptor())
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("native enrollment confirmation cannot retain one original consuming attempt")
	}
	for name, change := range map[string]func(*CommandPlan){
		"non-consuming": func(p *CommandPlan) { copy := *p.OTP; copy.Mode = OTPCheck; p.OTP = &copy },
		"missing-owner": func(p *CommandPlan) { p.Contributors = p.Contributors[:1] },
		"foreign-owner": func(p *CommandPlan) {
			p.Contributors = append([]ContributorDescriptor{original.Feature.Contributor}, ContributorDescriptor{Owner: "foreign", ContractID: "foreign", Version: 1})
		},
		"removed-risk":     func(p *CommandPlan) { p.CommandCounters = nil },
		"added-delivery":   func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"added-capability": func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"changed-lifecycle": func(p *CommandPlan) {
			p.Lifecycle = &LifecyclePlan{EventType: "factor.enrolled.v1", BeforeVersion: 3, AfterVersion: 4}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := final
			change(&bad)
			if preparationFinalDeclaration(b, original, bad) {
				t.Fatal("restoration changed original risk/lifecycle or native consume ownership")
			}
		})
	}
}
