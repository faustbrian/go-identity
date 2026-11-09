package postgres

import (
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// RP initiation creates only a transaction and its one original callback-state
// grant. It is distinct from callback consumption and from a signed link grant.
// This metadata selects no user, possession, allowance or execution authority;
// the exact native preparation owner must admit the original session/preauth.
func oauthRPInitiationOperation(anonymous bool) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if anonymous {
		op.OperationID, op.SchemaID, op.SubjectRequirement = "identity.oauth.signin-start", "identity.oauth.signin-start.rp-v1", identity.FeatureSubjectAnonymousFlow
	}
	return op
}

func oauthRPInitiationClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == q.feature.OperationID && (*q.feature == oauthRPInitiationOperation(false) || *q.feature == oauthRPInitiationOperation(true))
}

// The shared RP transaction profile fixes a ten-minute original state lifetime
// (REFERENCE_CONFIGURATION.md, struct:ref.oauth.rp_transaction). Earlier native
// deadlines may shorten it; restoration and issuance cannot renew or expand it.
const oauthRPMaximumStateLifetime = 10 * time.Minute

func oauthRPInitiationGrantSubject(b identity.CommandBinding, p CommandPlan, payload capability.Payload) (string, error) {
	if !validOAuthRPInitiation(b, p) || p.CapabilityIssuance == nil {
		return "", invalidWork()
	}
	subject := string(b.UserID)
	if b.OperationID == "identity.oauth.signin-start" {
		// A capability subject is an opaque scope string. An anonymous flow is
		// not a local user and must never enter a UserID override or user fence.
		subject = b.AnonymousFlowID
	}
	meta := p.CapabilityIssuance.Grants[0]
	if payload.Subject != subject || payload.Tenant != string(b.TenantID) || payload.Resource != b.RecordID || payload.ID != meta.CapabilityID || payload.Operation != "identity.oauth.callback" || payload.Bearer || payload.MaxUses != 1 || !payload.ExpiresAt.Equal(meta.ExpiresAt) || payload.IssuedAt.Location() != time.UTC || payload.IssuedAt.Nanosecond() != 0 || payload.IssuedAt.Unix() <= 0 || !payload.NotBefore.Equal(payload.IssuedAt) || !payload.ExpiresAt.After(payload.IssuedAt) || payload.ExpiresAt.Sub(payload.IssuedAt) > oauthRPMaximumStateLifetime {
		return "", invalidWork()
	}
	return subject, nil
}

func oauthRPInitiationSelected(p CommandPlan) bool {
	return p.Feature != nil && (p.Feature.Operation.OperationID == "identity.account.link-start" || p.Feature.Operation.OperationID == "identity.oauth.signin-start")
}

func validOAuthRPInitiation(b identity.CommandBinding, p CommandPlan) bool {
	if p.Feature == nil || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}) || p.SubjectType != "oauth_transaction" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}) || p.Capability != nil || p.Delivery != nil {
		return false
	}
	anonymous := b.OperationID == "identity.oauth.signin-start"
	if p.Feature.Operation != oauthRPInitiationOperation(anonymous) || b.ValidateFor(p.Feature.Operation) != nil {
		return false
	}
	if anonymous {
		if b.UserID != "" || b.AnonymousFlowID == "" || b.ActorKind != authorization.SubjectServiceAccount || b.ActorID == "" {
			return false
		}
	} else if b.UserID == "" || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) {
		return false
	}
	if p.CapabilityIssuance == nil {
		return true
	}
	i := p.CapabilityIssuance
	return validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == "identity.oauth.callback" && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}
