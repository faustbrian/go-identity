package postgres

import (
	"time"

	identity "github.com/faustbrian/go-identity"
)

func emailVerificationSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func emailVerificationMFAOperation(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation == emailVerificationSigninOperation() && p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1})
}

func validPrimaryMFAPlanMode(b identity.CommandBinding, p CommandPlan, origin string, ungenerated bool) bool {
	switch origin {
	case "password", "username", "phone":
		return origin == passwordMFAOrigin(b.OperationID) && validPasswordMFAPlanMode(b, p, ungenerated)
	case "email-verification":
		return validEmailVerificationMFAPlanMode(b, p, ungenerated)
	default:
		return false
	}
}

// Verification is a separately committed parent, not a capability consumed in
// this Work or a password comparison. Its exact native owner must authenticate
// that parent and original signup browser before this challenge may be staged.
func validEmailVerificationMFAPlanMode(b identity.CommandBinding, p CommandPlan, allowUngenerated bool) bool {
	m, i := p.MFAContinuation, p.CapabilityIssuance
	if m == nil || !emailVerificationMFAOperation(p) || b.ValidateFor(emailVerificationSigninOperation()) != nil || b.UserID == "" || b.AnonymousFlowID != "" || b.RecordID == string(b.CommandID) || m.UserID != b.UserID || m.PolicyVersion != b.PolicyVersion || m.FactorVersion == 0 || p.SubjectType != "authentication_attempt" || p.MFACompletion != nil || p.MagicLinkRegistration != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.Delivery != nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.IdentifierAdmission != nil || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "mfa.challenge.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 || len(p.Contributors) == 0 {
		return false
	}
	if _, err := identity.ParseCommandID(b.RecordID); err != nil {
		return false
	}
	if allowUngenerated && ungeneratedMFAContinuation(m) {
		return i == nil && p.CommandCounters == nil
	}
	if _, err := identity.ParseCommandID(string(m.ID)); err != nil {
		return false
	}
	if m.ScopeDigest == ([32]byte{}) || !postgresExactTime(m.IssuedAt) || !postgresExactTime(m.ExpiresAt) || m.IssuedAt.Nanosecond() != 0 || m.ExpiresAt.Nanosecond() != 0 || m.IssuedAt.Unix() <= 0 || !m.ExpiresAt.After(m.IssuedAt) || m.ExpiresAt.Sub(m.IssuedAt) > 5*time.Minute {
		return false
	}
	if i == nil {
		return true
	}
	return validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == m.UserID && i.Grants[0].Purpose == "identity.mfa.complete" && i.Grants[0].CapabilityID == string(m.ID) && i.Grants[0].ExpiresAt.Equal(m.ExpiresAt) && p.Contributors[len(p.Contributors)-1] == i.Contributor
}
