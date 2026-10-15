package magiclinkpostgres

import (
	"context"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Prospective scalars describe the session being prepared, not current account
// authority. Only applySignup obtains an actual recipient in the protected Work.
func (p *consumePhase) sessionIdentity() (identity.UserID, identity.IdentifierID, uint64, uint64) {
	if p.signup != nil {
		return p.signup.Creation.Binding.UserID, p.signup.Identifier.ID, 1, 1
	}
	r := p.selected.recipient
	return r.User.ID, r.Identifier.ID, r.Identifier.Version, r.Verification.Version
}

func (p *consumePhase) MagicLinkRegistration(c identity.Command) (kernel.MagicLinkRegistrationIntent, error) {
	if p == nil || p.signup == nil || (c != p.original && c != p.command) {
		return kernel.MagicLinkRegistrationIntent{}, invalid()
	}
	owned, err := identity.NewUserCreationCommand(p.signup.Creation)
	if err != nil {
		return kernel.MagicLinkRegistrationIntent{}, err
	}
	result := *p.signup
	result.Creation, _ = owned.CreateUser()
	return result, nil
}

// Recheck original signed possession at database time without extending its
// lifetime or treating the original request's risk evidence as consume authority.
func (p *consumePhase) checkProspectiveScope(now time.Time) error {
	if p.signup == nil || p.selected.prospective == nil || p.service.request.config().Possession == nil {
		return identity.ForbiddenError{}
	}
	original := *p.selected.prospective
	digest, err := kernel.MagicLinkRegistrationDigest(original)
	rebound, e := kernel.MagicLinkRegistrationDigest(*p.signup)
	if err != nil || e != nil || digest != rebound {
		return identity.ForbiddenError{}
	}
	b := original.Creation.Binding
	b.OperationID, b.UserID, b.AnonymousFlowID = requestOperation().OperationID, "", string(p.request.PreAuthID)
	b.SchemaID, b.SchemaVersion = requestOperation().SchemaID, requestOperation().SchemaVersion
	if b.CommandID != p.origin {
		return identity.ForbiddenError{}
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: requestOperation()})
	if err != nil {
		return err
	}
	request := &requestPhase{service: p.service.request, original: command, flow: p.flow, canonical: original.Identifier.CanonicalValue, request: magiclink.RequestRequest{Intent: magiclink.SignupIfAllowed, Callback: p.request.Callback}}
	actual := p.grant.Payload()
	expected, err := request.payload(p.selected)
	if err != nil {
		return err
	}
	expected.ID = actual.ID
	if !reflect.DeepEqual(expected, actual) {
		return identity.ForbiddenError{}
	}
	spec, err := request.possessionSpec(p.selected)
	if err != nil {
		return err
	}
	return p.service.request.config().Possession.Authorize(p.grant, spec, now)
}

func (p *consumePhase) applySignup(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.signup == nil || c != p.command || p.execution == nil {
		return invalid()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if err = p.checkProspectiveScope(now); err != nil {
		return err
	}
	if err = sessionpg.RequirePreAuth(ctx, w, p.service.request.config().Session, p.flow); err != nil {
		return err
	}
	user, err := p.service.request.registration.Apply(ctx, w, p, c)
	if err != nil {
		return err
	}
	if err = mfapg.InitializeMagicLinkSignup(ctx, w, p, c, user.ID); err != nil {
		return err
	}
	policy, err := authoritypg.InitializeAuthority(ctx, w, authoritypg.AuthorityScope{TenantID: authorization.TenantID(p.request.TenantID), SubjectID: authorization.SubjectID(user.ID), PolicyNamespace: p.service.config.PolicyNamespace}, p.service.request.config().MaximumDuration)
	if err != nil {
		return err
	}
	if policy.Version != p.policyVersion {
		return identity.ForbiddenError{}
	}
	recipient, err := p.service.request.registration.Recipient(ctx, w, p, c)
	if err != nil {
		return err
	}
	p.createdRecipient = &recipient
	return nil
}

var _ kernel.MagicLinkRegistrationContributor = (*consumePhase)(nil)
