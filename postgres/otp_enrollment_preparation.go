package postgres

import identity "github.com/faustbrian/go-identity"

// Enrollment confirmation is a closed authenticated-session profile. It may
// retain one native OTP attempt under the existing preparation journal, but
// cannot introduce a login child, capability, delivery or session issuance.
func otpEnrollmentPreparation(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) &&
		p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) &&
		p.SubjectType == "factor" && p.CommandCounters != nil && p.Lifecycle != nil && p.Lifecycle.EventType == "factor.enrolled.v1" && p.Lifecycle.BeforeVersion > 0 && p.Lifecycle.BeforeVersion != ^uint64(0) && p.Lifecycle.AfterVersion == p.Lifecycle.BeforeVersion+1 &&
		p.Capability == nil && p.CapabilityIssuance == nil && p.MFACompletion == nil && p.MFAContinuation == nil && p.Delivery == nil && (p.OTP == nil || p.OTP.Mode == OTPConsume && validateOTPPlan(p) == nil)
}
