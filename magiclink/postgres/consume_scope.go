package magiclinkpostgres

import (
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// validateConsumptionScope conserves the complete issuer-owned request profile,
// not merely a valid signature or selected caveats. grant and origin must come
// from ReadIssuanceOrigin; recipient from current primary discovery. The same
// payload constructor used for issuance reconstructs every mandatory caveat
// from current recipient versions and original browser policy. Extra, missing,
// noncanonical or foreign scope denies. No IO, token transfer, use reservation,
// session generation or renewal occurs. Current factor authority and cookie
// possession must still be fenced separately in the consuming transaction.
func (s *RequestService) validateConsumptionScope(r magiclink.ConsumeRequest, flow session.PreAuthTransaction, grant capability.Grant, origin identity.CommandID, recipient kernel.RecipientRecord, now time.Time) (requestSelection, error) {
	deny := func() (requestSelection, error) { return requestSelection{}, identity.ForbiddenError{} }
	if s == nil || s.config == nil || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != r.TenantID || recipient.Query.UserID != "" || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != kernel.RecipientVerified {
		return deny()
	}
	if _, err := identity.ParseCommandID(string(origin)); err != nil || origin == r.CommandID {
		return deny()
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return deny()
	}
	f, err := flow.Bindings()
	if err != nil || f.Binding.ID != r.PreAuthID || f.Binding.Intent.TenantID != r.TenantID || f.Binding.Intent.Action != "identity.magic-link.consume" || f.Binding.Intent.CallbackURL != r.Callback || f.Binding.Intent.Origin != r.Origin {
		return deny()
	}
	actual := grant.Payload()
	factor, err := strconv.ParseUint(actual.Caveats["magiclink.factor-version"], 10, 64)
	if err != nil || factor == 0 || strconv.FormatUint(factor, 10) != actual.Caveats["magiclink.factor-version"] || actual.ID == "" || now.IsZero() || now.Before(actual.IssuedAt) || !now.Before(actual.ExpiresAt) || actual.IssuedAt.Before(f.Binding.IssuedAt.UTC().Truncate(time.Second)) {
		return deny()
	}
	op := requestOperation()
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: origin, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: f.Binding.Intent.PolicyID, PolicyVersion: f.Binding.Intent.PolicyVersion, CorrelationID: string(origin)}, Operation: op})
	if err != nil {
		return deny()
	}
	selected := requestSelection{recipient: recipient, factor: factor, issued: actual.IssuedAt, expires: actual.ExpiresAt}
	p := &requestPhase{service: s, original: command, flow: flow, request: magiclink.RequestRequest{Intent: magiclink.SignInOnly, Callback: r.Callback}}
	expected, err := p.payload(selected)
	if err != nil {
		return deny()
	}
	expected.ID = actual.ID
	if !reflect.DeepEqual(actual, expected) {
		return deny()
	}
	return selected, nil
}
