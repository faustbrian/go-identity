package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const (
	oauthProxyRetirementOperation = "identity.oauth.proxy-custody-retire"
	oauthProxyRetirementSubject   = "oauth_proxy_retirement"
	oauthProxyRetirementAudit     = "identity.oauth.proxy_custody.retire"
)

// OAuthProxyRetirementKind selects the one grant role eligible for retirement.
type OAuthProxyRetirementKind uint8

const (
	// OAuthProxyRetireProduction selects the production forward grant.
	OAuthProxyRetireProduction OAuthProxyRetirementKind = iota + 1
	// OAuthProxyRetirePreview selects the preview browser callback grant.
	OAuthProxyRetirePreview
)

// OAuthProxyOriginRetirementOperation selects one native custody retirement,
// not a callback, provider exchange, or identity/session mutation.
func OAuthProxyOriginRetirementOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth/proxy", OperationID: oauthProxyRetirementOperation,
		SchemaID: oauthProxyRetirementOperation + ".native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// OAuthProxyOriginRetirementDescriptor identifies the native OAuth custody owner.
func OAuthProxyOriginRetirementDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: oauthProxyRetirementOperation, Version: 1}
}

// OAuthProxyOriginRetirementLifecycle records local retirement, not the outcome
// of any interrupted or uncertain external exchange.
func OAuthProxyOriginRetirementLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "oauth.proxy.custody_retired.v1", AfterVersion: 1}
}

// OAuthProxyOriginRetirementScope carries the original local grant scope and
// the source transition's identity, not proof that retirement is authorized.
type OAuthProxyOriginRetirementScope struct {
	TenantID        identity.TenantID
	OriginCommandID identity.CommandID
	FlowID          identity.PreAuthTransactionID
	GrantPurpose    string
	SourceCommandID identity.CommandID
	SourceVersion   uint64
}

// NewOAuthProxyOriginRetirementCommand freezes the exact original scope. Use
// the service actor and original anonymous flow as both target and RecordID;
// set CorrelationID to the issuing command ID. Source identifies the trusted
// transition that the native owner must independently authorize in Apply.
func NewOAuthProxyOriginRetirementCommand(b identity.CommandBinding, kind OAuthProxyRetirementKind, source identity.CommandID, version uint64) (identity.Command, error) {
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: OAuthProxyOriginRetirementOperation(), Fields: []identity.FeatureField{
		{Name: "oauth.proxy.retirement.kind", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(kind)}},
		{Name: "oauth.proxy.retirement.source-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(source)}},
		{Name: "oauth.proxy.retirement.source-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}},
	}})
	if err != nil {
		return identity.Command{}, err
	}
	if _, ok := decodeOAuthProxyRetirement(c); !ok {
		return identity.Command{}, invalidPlan()
	}
	return c, nil
}

// OAuthProxyOriginRetirementScope returns the frozen target only during the
// exact registered OAuth custody owner's original Apply. The owner must
// authenticate the retirement source and original custody. When the callback
// path locks the grant first, use the same lock order and compare the exact
// custody locator when erasing it in Work. This guard performs no I/O.
func (w Work) OAuthProxyOriginRetirementScope(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (OAuthProxyOriginRetirementScope, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return OAuthProxyOriginRetirementScope{}, err
	}
	b, f, l, err := w.FeatureScope(owner)
	scope, ok := decodeOAuthProxyRetirement(command)
	plan := w.state.execution.reservation.plan
	if err != nil || !ok || l != OAuthProxyOriginRetirementLifecycle() || f != (FeatureRegistration{Operation: OAuthProxyOriginRetirementOperation(), Contributor: OAuthProxyOriginRetirementDescriptor()}) ||
		!validOAuthProxyRetirementPlan(b, plan.snapshot()) {
		return OAuthProxyOriginRetirementScope{}, w.fail(ctx, invalidPlan())
	}
	return scope, nil
}

func oauthProxyRetirementScope(b identity.CommandBinding) (OAuthProxyOriginRetirementScope, bool) {
	flow, flowErr := identity.ParsePreAuthTransactionID(b.AnonymousFlowID)
	origin, originErr := identity.ParseCommandID(b.CorrelationID)
	if flowErr != nil || originErr != nil || b.ValidateFor(OAuthProxyOriginRetirementOperation()) != nil ||
		b.ActorKind != authorization.SubjectServiceAccount || b.UserID != "" || b.RecordID != string(flow) ||
		origin == b.CommandID || string(origin) == string(flow) || string(b.CommandID) == string(flow) {
		return OAuthProxyOriginRetirementScope{}, false
	}
	return OAuthProxyOriginRetirementScope{TenantID: b.TenantID, OriginCommandID: origin, FlowID: flow}, true
}

func decodeOAuthProxyRetirement(c identity.Command) (OAuthProxyOriginRetirementScope, bool) {
	s, ok := c.Feature()
	_, cookie := c.PreAuthCookie()
	_, bearer := c.SessionToken()
	_, otp := c.OneTimeCode()
	_, recovery := c.RecoveryCode()
	if !ok || cookie || bearer || otp || recovery || s.Operation != OAuthProxyOriginRetirementOperation() || len(s.Fields) != 3 {
		return OAuthProxyOriginRetirementScope{}, false
	}
	scope, ok := oauthProxyRetirementScope(s.Binding)
	if !ok {
		return OAuthProxyOriginRetirementScope{}, false
	}
	for _, field := range s.Fields {
		v := field.Value
		switch field.Name {
		case "oauth.proxy.retirement.kind":
			if v.Kind == identity.FeatureUint64 {
				switch v.Uint64 {
				case uint64(OAuthProxyRetireProduction):
					scope.GrantPurpose = oauthProxyForwardPurpose
				case uint64(OAuthProxyRetirePreview):
					scope.GrantPurpose = "identity.oauth.callback"
				}
			}
		case "oauth.proxy.retirement.source-command":
			if v.Kind == identity.FeatureText {
				source, err := identity.ParseCommandID(v.Text)
				if err == nil {
					scope.SourceCommandID = source
				}
			}
		case "oauth.proxy.retirement.source-version":
			if v.Kind == identity.FeatureUint64 {
				scope.SourceVersion = v.Uint64
			}
		}
	}
	if scope.GrantPurpose == "" || scope.SourceCommandID == "" || scope.SourceVersion == 0 ||
		scope.SourceCommandID == s.Binding.CommandID || scope.SourceCommandID == scope.OriginCommandID || string(scope.SourceCommandID) == string(scope.FlowID) {
		return OAuthProxyOriginRetirementScope{}, false
	}
	return scope, true
}

func oauthProxyRetirementSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation.OperationID == oauthProxyRetirementOperation
}

func validOAuthProxyRetirementPlan(b identity.CommandBinding, p CommandPlan) bool {
	_, scoped := oauthProxyRetirementScope(b)
	return scoped && p.Feature != nil && *p.Feature == (FeatureRegistration{Operation: OAuthProxyOriginRetirementOperation(), Contributor: OAuthProxyOriginRetirementDescriptor()}) &&
		p.SubjectType == oauthProxyRetirementSubject && p.Lifecycle != nil && *p.Lifecycle == OAuthProxyOriginRetirementLifecycle() &&
		len(p.Audits) == 1 && p.Audits[0].EventType == oauthProxyRetirementAudit && p.Audits[0].Required && p.Audits[0].RetentionClass == "protected" &&
		p.Capability == nil && p.CapabilityIssuance == nil && p.AccountLinkState == nil && p.Delivery == nil && p.RiskEvidence == nil && p.CommandCounters == nil &&
		p.OTP == nil && p.CaptchaEvidence == nil && !p.CaptchaReplayReservation && p.IdentifierAdmission == nil && p.APIKeyVerification == nil &&
		p.PasskeyRegistration == nil && p.MFACompletion == nil && p.MFAContinuation == nil && p.OrganizationInvitationOrigin == nil &&
		p.MagicLinkRegistration == nil && !p.SignupAcceptance && !p.MagicLinkRequestAcceptance && p.SCIMUserUpdate == nil && p.SCIMBulkDenial == 0
}
