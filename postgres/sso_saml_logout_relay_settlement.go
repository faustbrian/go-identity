package postgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const samlLogoutRelayIssueCommand = "sso.saml.logout.issue-command"
const samlLogoutRelayResponse = "sso.saml.logout.response"

// SSOSAMLLogoutRelaySettlementContributor owns the exact native response
// mutation. Pure validation must match the authenticated original request,
// response and verified grant. Apply and the final fence retain installed
// provider authority and the original expiry in the sole Work.
type SSOSAMLLogoutRelaySettlementContributor interface {
	FeatureCommitContributor
	ValidateSSOSAMLLogoutRelaySettlement(identity.Command, CapabilityPlan) error
}

// SSOSAMLLogoutRelaySettlementOperation selects settlement of one remote
// logout request by the installed service. Its record is the original remote
// issue command, never a session or this settlement command.
func SSOSAMLLogoutRelaySettlementOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLLogoutRelaySettlePurpose,
		SchemaID: "sso-enterprise-saml-logout-relay-settle-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// SSOSAMLLogoutRelaySettlementDescriptor identifies the native settlement owner.
func SSOSAMLLogoutRelaySettlementDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-logout-relay-settle", Version: 1}
}

// SSOSAMLLogoutRelaySettlementLifecycle terminalizes one remote request.
func SSOSAMLLogoutRelaySettlementLifecycle() LifecyclePlan {
	return LifecyclePlan{EventType: "sso.saml_logout.settled.v1", BeforeVersion: 1, AfterVersion: 2}
}

// SSOSAMLLogoutRelaySettlementIntent binds the originally issued request and
// one authenticated provider response without receiving either wire value.
// The provider owner must still validate signature, signed InResponseTo,
// source, retained custody, proof and the original expiry.
type SSOSAMLLogoutRelaySettlementIntent struct {
	IssueCommandID, LocalCommandID identity.CommandID
	OrganizationID, ProviderID     string
	RequestDigest, ResponseDigest  [32]byte
	ExpiresAt                      time.Time
}

// SSOSAMLLogoutRelaySettlementFields encodes the original request and response
// commitment, commit identities and original exclusive cutoff.
func SSOSAMLLogoutRelaySettlementFields(intent SSOSAMLLogoutRelaySettlementIntent) ([]identity.FeatureField, error) {
	_, issueErr := identity.ParseCommandID(string(intent.IssueCommandID))
	_, localErr := identity.ParseCommandID(string(intent.LocalCommandID))
	if issueErr != nil || localErr != nil || intent.IssueCommandID == intent.LocalCommandID ||
		!queryScopeText(intent.OrganizationID) || !queryScopeText(intent.ProviderID) || !validSAMLLogoutRelayInstant(intent.ExpiresAt) ||
		intent.RequestDigest == ([32]byte{}) || intent.ResponseDigest == ([32]byte{}) {
		return nil, invalidPlan()
	}
	return []identity.FeatureField{
		{Name: samlLogoutRelayExpiresAt, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: intent.ExpiresAt}},
		{Name: samlLogoutRelayIssueCommand, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(intent.IssueCommandID)}},
		{Name: samlLogoutRelayLocalCommand, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(intent.LocalCommandID)}},
		{Name: samlLogoutRelayOrganization, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.OrganizationID}},
		{Name: samlLogoutRelayProvider, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.ProviderID}},
		{Name: samlLogoutRelayRequest, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent.RequestDigest[:]}},
		{Name: samlLogoutRelayResponse, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent.ResponseDigest[:]}},
	}, nil
}

func validSSOSAMLLogoutRelaySettlementBinding(b identity.CommandBinding) bool {
	issue, issueErr := identity.ParseCommandID(b.RecordID)
	local, localErr := identity.ParseCommandID(b.CorrelationID)
	return issueErr == nil && localErr == nil && issue != local && issue != b.CommandID && local != b.CommandID &&
		b.ActorKind == authorization.SubjectServiceAccount && b.ValidateFor(SSOSAMLLogoutRelaySettlementOperation()) == nil
}

func decodeSSOSAMLLogoutRelaySettlement(command identity.Command) (SSOSAMLLogoutRelaySettlementIntent, bool) {
	spec, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, bearer := command.SessionToken()
	_, otp := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	if !ok || spec.Operation != SSOSAMLLogoutRelaySettlementOperation() || !validSSOSAMLLogoutRelaySettlementBinding(spec.Binding) ||
		len(spec.Fields) != 7 || cookie || bearer || otp || recovery {
		return SSOSAMLLogoutRelaySettlementIntent{}, false
	}
	var intent SSOSAMLLogoutRelaySettlementIntent
	for _, field := range spec.Fields {
		v := field.Value
		switch field.Name {
		case samlLogoutRelayIssueCommand:
			intent.IssueCommandID = identity.CommandID(v.Text)
		case samlLogoutRelayLocalCommand:
			intent.LocalCommandID = identity.CommandID(v.Text)
		case samlLogoutRelayOrganization:
			intent.OrganizationID = v.Text
		case samlLogoutRelayProvider:
			intent.ProviderID = v.Text
		case samlLogoutRelayRequest:
			if len(v.Bytes) != len(intent.RequestDigest) {
				return SSOSAMLLogoutRelaySettlementIntent{}, false
			}
			intent.RequestDigest = [32]byte(v.Bytes)
		case samlLogoutRelayResponse:
			if len(v.Bytes) != len(intent.ResponseDigest) {
				return SSOSAMLLogoutRelaySettlementIntent{}, false
			}
			intent.ResponseDigest = [32]byte(v.Bytes)
		case samlLogoutRelayExpiresAt:
			intent.ExpiresAt = v.Time
		}
	}
	want, err := SSOSAMLLogoutRelaySettlementFields(intent)
	if err != nil || spec.Binding.RecordID != string(intent.IssueCommandID) || spec.Binding.CorrelationID != string(intent.LocalCommandID) ||
		!slices.EqualFunc(spec.Fields, want, equalSAMLIDPLogoutField) {
		return SSOSAMLLogoutRelaySettlementIntent{}, false
	}
	return intent, true
}

func validateSSOSAMLLogoutRelaySettlement(owner FeatureExecutionContributor, command identity.Command, plan CommandPlan) error {
	native, selected := owner.(SSOSAMLLogoutRelaySettlementContributor)
	intent, valid := decodeSSOSAMLLogoutRelaySettlement(command)
	if !selected || !valid || plan.Capability == nil || plan.Capability.Purpose != ssoSAMLLogoutRelaySettlePurpose ||
		!plan.Capability.ExpiresAt.Equal(intent.ExpiresAt) {
		return invalidPlan()
	}
	return native.ValidateSSOSAMLLogoutRelaySettlement(command, *plan.Capability)
}

// RequireSSOSAMLLogoutRelaySettlement proves the exact synchronous native
// invocation and original immutable command. Apply requires a provisional
// one-use effect; the final check requires its finalized receipt. This does
// not perform signature, provider or clock validation for the native owner.
// A failed check poisons live Work, even if a caller ignores the error.
func (w Work) RequireSSOSAMLLogoutRelaySettlement(ctx context.Context, owner SSOSAMLLogoutRelaySettlementContributor, command identity.Command, intent SSOSAMLLogoutRelaySettlementIntent) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	b, f, lifecycle, err := w.FeatureScope(owner)
	if err != nil || f.Operation != SSOSAMLLogoutRelaySettlementOperation() || f.Contributor != SSOSAMLLogoutRelaySettlementDescriptor() ||
		lifecycle != SSOSAMLLogoutRelaySettlementLifecycle() || w.state.subjectType != ssoSAMLLogoutRequestSubject ||
		w.state.featurePreparationPlan != nil || !w.state.samlLogoutRelayConsumed {
		return w.fail(ctx, invalidWork())
	}
	if w.state.featureApplying {
		if w.state.samlLogoutRelayFinalized {
			return w.fail(ctx, invalidWork())
		}
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return err
		}
	} else if !w.state.samlLogoutRelayFinalized || w.state.featureReceipt == nil ||
		w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return w.fail(ctx, invalidWork())
	}
	got, valid := decodeSSOSAMLLogoutRelaySettlement(command)
	spec, _ := command.Feature()
	if !valid || spec.Binding != b || got != intent {
		return w.fail(ctx, invalidPlan())
	}
	return nil
}

func (c *Coordinator) applySSOSAMLLogoutRelaySettlement(ctx context.Context, w Work) error {
	if w.state.samlLogoutRelayConsumed || w.state.samlLogoutRelayFinalized {
		return w.fail(ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.samlLogoutRelayConsumed = true
	return nil
}

func (c *Coordinator) finalizeSSOSAMLLogoutRelaySettlement(w Work) error {
	receipt := w.state.featureReceipt
	if !w.state.samlLogoutRelayConsumed || w.state.samlLogoutRelayFinalized || receipt == nil ||
		receipt.Operation != SSOSAMLLogoutRelaySettlementOperation() {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.samlLogoutRelayFinalized = true
	return nil
}
