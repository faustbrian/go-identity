package postgres

import (
	"encoding/base64"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

const (
	oauthProxyStartPurpose  = "identity.oauth.proxy-start"
	oauthProxyStartAudit    = "identity.oauth.start_authorization"
	oauthProxySubjectType   = "oauth_proxy_transaction"
	oauthProxyBindingCaveat = "identity.oauth.proxy.binding"
)

// OAuthProxyStartOperation selects the native prepared creation of one proxy
// transaction. It does not grant an identity, session or provider credential.
func OAuthProxyStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "identity/oauth/proxy", OperationID: oauthProxyStartPurpose,
		SchemaID: oauthProxyStartPurpose + ".native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

// OAuthProxyStartDescriptor names the sole native adapter for proxy creation.
func OAuthProxyStartDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: oauthProxyStartPurpose, Version: 1}
}

// OAuthProxyStartLifecycle creates only the original proxy transaction record.
func OAuthProxyStartLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "oauth.proxy.started.v1", AfterVersion: 1}
}

func oauthProxyStartClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == oauthProxyStartPurpose && *q.feature == OAuthProxyStartOperation()
}

func oauthProxyStartSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation.OperationID == oauthProxyStartPurpose
}

func validOAuthProxyStartBinding(b identity.CommandBinding) bool {
	flow, err := identity.ParsePreAuthTransactionID(b.AnonymousFlowID)
	return err == nil && b.ActorKind == authorization.SubjectServiceAccount && b.RecordID == string(flow) &&
		b.CorrelationID == string(b.CommandID) && b.RecordID != b.CorrelationID && b.ValidateFor(OAuthProxyStartOperation()) == nil
}

func validOAuthProxyStartPlan(b identity.CommandBinding, p CommandPlan) bool {
	if !validOAuthProxyStartBinding(b) || p.Feature == nil || p.Feature.Operation != OAuthProxyStartOperation() ||
		p.Feature.Contributor != OAuthProxyStartDescriptor() || p.Lifecycle == nil || *p.Lifecycle != OAuthProxyStartLifecycle() ||
		p.SubjectType != oauthProxySubjectType || p.Capability != nil || p.Delivery != nil || p.OTP != nil ||
		p.CommandCounters != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation ||
		len(p.Audits) != 1 || p.Audits[0].EventType != oauthProxyStartAudit || p.Audits[0].RetentionClass != "protected" {
		return false
	}
	i := p.CapabilityIssuance
	return i == nil || validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.Grants[0].Purpose == oauthProxyForwardPurpose &&
		i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == ""
}

type oauthProxyStartIntent struct {
	binding identity.CommandBinding
	request [32]byte
	sealed  [32]byte
}

func decodeOAuthProxyStart(c identity.Command) (oauthProxyStartIntent, bool) {
	s, ok := c.Feature()
	if !ok || s.Operation != OAuthProxyStartOperation() || !validOAuthProxyStartBinding(s.Binding) || len(s.Fields) < 1 || len(s.Fields) > 2 {
		return oauthProxyStartIntent{}, false
	}
	intent := oauthProxyStartIntent{binding: s.Binding}
	for _, field := range s.Fields {
		if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
			return oauthProxyStartIntent{}, false
		}
		digest := [32]byte(field.Value.Bytes)
		if digest == ([32]byte{}) {
			return oauthProxyStartIntent{}, false
		}
		switch field.Name {
		case "oauth.proxy.request":
			intent.request = digest
		case oauthProxyBindingCaveat:
			intent.sealed = digest
		default:
			return oauthProxyStartIntent{}, false
		}
	}
	return intent, intent.request != ([32]byte{})
}

func sameOAuthProxyStartCustody(original, generated identity.Command) bool {
	a, aOK := decodeOAuthProxyStart(original)
	b, bOK := decodeOAuthProxyStart(generated)
	return aOK && bOK && a.binding == b.binding && a.request == b.request && a.sealed == ([32]byte{}) && b.sealed != ([32]byte{})
}

func oauthProxyStartGrantSubject(b identity.CommandBinding, p CommandPlan, c identity.Command, payload capability.Payload) (string, error) {
	intent, ok := decodeOAuthProxyStart(c)
	if !ok || intent.binding != b || intent.sealed == ([32]byte{}) || !validOAuthProxyStartPlan(b, p) || p.CapabilityIssuance == nil {
		return "", invalidWork()
	}
	grant := p.CapabilityIssuance.Grants[0]
	if payload.Tenant != string(b.TenantID) || payload.Subject != b.AnonymousFlowID || payload.Resource != b.RecordID ||
		payload.CorrelationID != b.CorrelationID || payload.ID != grant.CapabilityID || payload.Operation != oauthProxyForwardPurpose ||
		payload.Bearer || payload.MaxUses != 1 || len(payload.Audiences) != 1 || len(payload.Caveats) != 1 ||
		payload.Caveats[oauthProxyBindingCaveat] != base64.RawURLEncoding.EncodeToString(intent.sealed[:]) || !payload.ExpiresAt.Equal(grant.ExpiresAt) {
		return "", invalidWork()
	}
	// Match the issuance and callback proof's original exclusive, whole-second
	// validity. A retry cannot replace the frozen lifetime or extend it via skew.
	if payload.IssuedAt.Location() != time.UTC || payload.IssuedAt.Unix() <= 0 || payload.IssuedAt.Nanosecond() != 0 ||
		payload.NotBefore != payload.IssuedAt || payload.ExpiresAt.Location() != time.UTC || payload.ExpiresAt.Nanosecond() != 0 ||
		!payload.ExpiresAt.After(payload.IssuedAt) || payload.ExpiresAt.Sub(payload.IssuedAt) > 5*time.Minute {
		return "", invalidWork()
	}
	return b.AnonymousFlowID, nil
}
