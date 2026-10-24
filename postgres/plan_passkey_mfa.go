package postgres

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func passkeyMFAOperation(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation == passkeyMFAPrimaryOperation() && p.Feature.Contributor == (ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1})
}

func passkeyMFAPrimaryOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// The protocol's genuine assertion participant still authenticates and consumes
// the original ceremony here. The parent creates only the bound MFA child,
// never a session or an invented primary capability. Existing known-empty
// passkey plans have no MFAContinuation and retain their historical encoding.
func validPasskeyMFAPlanMode(b identity.CommandBinding, p CommandPlan, ungenerated bool) bool {
	m, i := p.MFAContinuation, p.CapabilityIssuance
	if m == nil || !passkeyMFAOperation(p) || b.ValidateFor(passkeyMFAPrimaryOperation()) != nil || b.UserID == "" || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.RecordID != string(b.CommandID) || m.UserID != b.UserID || m.PolicyVersion == 0 || m.FactorVersion == 0 || p.SubjectType != "authentication_attempt" || p.MFACompletion != nil || p.PasskeyRegistration != nil || p.OrganizationInvitationOrigin != nil || p.MagicLinkRegistration != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.Delivery != nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.IdentifierAdmission != nil || p.Capability != nil || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}) || len(p.Contributors) == 0 {
		return false
	}
	if ungenerated && ungeneratedMFAContinuation(m) {
		return i == nil && p.CommandCounters == nil
	}
	if _, err := identity.ParseCommandID(string(m.ID)); err != nil || m.ID == b.CommandID {
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
