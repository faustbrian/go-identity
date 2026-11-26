package postgres

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

const (
	oneTapStartPurpose    = "identity.oauth.onetap-start"
	oneTapCallbackPurpose = "identity.oauth.onetap-callback"
)

// OneTapStartOperation selects only the prepared Google One Tap start. It
// grants no browser, credential, callback or final-session authority.
func OneTapStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: oneTapStartPurpose,
		SchemaID: "oauth-onetap-start-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

// OneTapCallbackOperation selects consumption of the original Google One Tap
// flow in the native callback. It grants no browser, proof or session authority.
func OneTapCallbackOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "identity/oauth/onetap", OperationID: oneTapCallbackPurpose,
		SchemaID: "oauth-onetap-callback-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

func validOneTapCallbackBinding(b identity.CommandBinding) bool {
	return b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == b.AnonymousFlowID && b.ValidateFor(OneTapCallbackOperation()) == nil
}

func oneTapCallbackDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-completion", Version: 1}
}

func oneTapStartClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == oneTapStartPurpose && *q.feature == OneTapStartOperation()
}

func oneTapStartSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation.OperationID == oneTapStartPurpose
}

func oneTapStartDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-initiation", Version: 1}
}

func validOneTapStartBinding(b identity.CommandBinding) bool {
	return b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == b.AnonymousFlowID && b.ValidateFor(OneTapStartOperation()) == nil
}

func validOneTapStartPlan(b identity.CommandBinding, p CommandPlan) bool {
	lifecycle := LifecyclePlan{EventType: "session.preauth-issued.v1", AfterVersion: 1}
	if !validOneTapStartBinding(b) || p.Feature == nil || p.Feature.Operation != OneTapStartOperation() || p.Feature.Contributor != oneTapStartDescriptor() ||
		p.SubjectType != "preauth_transaction" || p.Lifecycle == nil || *p.Lifecycle != lifecycle || p.Capability != nil || p.Delivery != nil || p.CommandCounters != nil {
		return false
	}
	i := p.CapabilityIssuance
	return i == nil || validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == oneTapCallbackPurpose &&
		i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

func oneTapStartGrantSubject(b identity.CommandBinding, p CommandPlan, payload capability.Payload) (string, error) {
	if !validOneTapStartPlan(b, p) || p.CapabilityIssuance == nil {
		return "", invalidWork()
	}
	meta := p.CapabilityIssuance.Grants[0]
	if payload.Subject != b.AnonymousFlowID || payload.Resource != b.RecordID || payload.Tenant != string(b.TenantID) ||
		payload.CorrelationID != b.CorrelationID || payload.ID != meta.CapabilityID || payload.Operation != oneTapCallbackPurpose ||
		payload.Bearer || payload.MaxUses != 1 || !payload.ExpiresAt.Equal(meta.ExpiresAt) {
		return "", invalidWork()
	}
	// Match the original five-minute One Tap callback pre-auth profile; the
	// native owner separately fences its exact provider, origin and deadline.
	issued := payload.IssuedAt
	if issued.Location() != time.UTC || issued.Unix() <= 0 || issued.Nanosecond() != 0 || !payload.NotBefore.Equal(issued) || !payload.ExpiresAt.After(issued) || payload.ExpiresAt.Sub(issued) > 5*time.Minute {
		return "", invalidWork()
	}
	return b.AnonymousFlowID, nil
}
