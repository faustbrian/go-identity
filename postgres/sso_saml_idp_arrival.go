package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLIDPArrivalPurpose = "identity.sso.saml-idp-prepare"

// SSOSAMLIDPArrivalOperation selects internal pending-record creation for the
// linked recipient of an unsolicited assertion. The record is the original
// arrival command ID. This has no consumption, session or HTTP authority.
func SSOSAMLIDPArrivalOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLIDPArrivalPurpose, SchemaID: "sso-enterprise-saml-idp-prepare-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

func ssoSAMLIDPArrivalDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-arrival", Version: 1}
}

func ssoSAMLIDPArrivalLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "sso.saml_confirmation.created.v1", AfterVersion: 1}
}

func validSSOSAMLIDPArrivalPlan(b identity.CommandBinding, p CommandPlan) bool {
	if b.ValidateFor(SSOSAMLIDPArrivalOperation()) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(b.CommandID) ||
		p.Feature == nil || *p.Feature != (FeatureRegistration{Operation: SSOSAMLIDPArrivalOperation(), Contributor: ssoSAMLIDPArrivalDescriptor()}) ||
		p.SubjectType != "sso_saml_confirmation" || p.Lifecycle == nil || *p.Lifecycle != ssoSAMLIDPArrivalLifecycle() ||
		len(p.Audits) != 1 || p.Audits[0].EventType != ssoSAMLIDPArrivalPurpose || p.Audits[0].RetentionClass != "protected" || !p.Audits[0].Required ||
		p.Capability != nil || p.Delivery != nil || p.RiskEvidence != nil || p.CommandCounters != nil || p.OTP != nil || p.CaptchaReplayReservation || p.CaptchaEvidence != nil {
		return false
	}
	i := p.CapabilityIssuance
	return validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == capability.Purpose(ssoSAMLIDPConfirmationPurpose) &&
		i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

func plainSSOSAMLIDPArrival(command identity.Command) bool {
	feature, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, bearer := command.SessionToken()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	return ok && feature.Operation == SSOSAMLIDPArrivalOperation() && !cookie && !bearer && !otp && !recovery
}
