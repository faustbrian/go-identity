package magiclinkpostgres

import (
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Reconstruct the email owner's input from original native custody, rather
// than projecting caller callback fields or trusting a signed digest alone.
// This issues no additional grant and stores no second ownership receipt.
func (p *requestPhase) possessionSpec(s requestSelection) (email.MagicLinkPossessionSpec, error) {
	if s.prospective == nil {
		return email.MagicLinkPossessionSpec{}, invalid()
	}
	payload, err := p.payload(s)
	if err != nil {
		return email.MagicLinkPossessionSpec{}, err
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return email.MagicLinkPossessionSpec{}, err
	}
	binding, err := p.flowDigest()
	if err != nil {
		return email.MagicLinkPossessionSpec{}, err
	}
	scope, err := issuerpg.MagicLinkScopeFromPayload(payload)
	if err != nil {
		return email.MagicLinkPossessionSpec{}, err
	}
	creation, err := kernel.MagicLinkRegistrationDigest(*s.prospective)
	if err != nil {
		return email.MagicLinkPossessionSpec{}, err
	}
	original, ok := p.original.Feature()
	if !ok {
		return email.MagicLinkPossessionSpec{}, invalid()
	}
	return email.MagicLinkPossessionSpec{
		TenantID: original.Binding.TenantID, UserID: s.prospective.Creation.Binding.UserID,
		IdentifierID: s.prospective.Identifier.ID, CanonicalAddress: s.prospective.Identifier.CanonicalValue,
		Callback: p.request.Callback, RequestCommandID: original.Binding.CommandID,
		FlowID: string(flow.Binding.ID), FlowBinding: binding, Profile: p.service.configuration,
		Supersession: scope.Digest(), CreationDigest: creation,
		PolicyVersion: s.prospective.EmailPossessionPolicyVersion, IssuedAt: s.issued, ExpiresAt: s.expires,
	}, nil
}
