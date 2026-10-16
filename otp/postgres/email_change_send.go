package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func (p *Contributor) admitEmailChangeSend(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, r sendRequestRecord) error {
	if p == nil || p.emailChange == nil || r.recipient == nil {
		return ErrInvalidCommand
	}
	o := p.emailChange.origin
	spec, ok := command.Feature()
	scope, err := r.continuation.Bindings()
	target, _ := p.emailChange.target.ScopeTarget()
	if !ok || err != nil || scope.Scope.Purpose != otp.PurposeEmailChange || scope.Scope.Channel != otp.ChannelEmail || scope.Scope.TargetID != target || scope.Scope.Destination.Value() != o.Spec.Payload.CanonicalAddress.Record().Value || spec.Binding.TenantID != o.Spec.Binding.TenantID || spec.Binding.UserID != o.Spec.Binding.UserID || r.authority != p.emailChange.authority || r.recipient.User.Version != o.UserVersion+1 || r.recipient.Identifier.ID != o.Spec.IdentifierID || r.recipient.Identifier.Version != o.Spec.IdentifierVersion || r.recipient.Verification.Version != o.Spec.VerificationVersion || r.recipient.Identifier.Verified || r.recipient.Identifier.Primary || r.recipient.Verification.State != identity.VerificationPending || r.expiresAt.After(o.Spec.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if _, session := scope.Authorization.AuthenticatedSession(); !session {
		return identity.ForbiddenError{}
	}
	if _, err := mfapg.RequireEmailOTPFactors(ctx, w, owner, command, o.FactorVersion); err != nil {
		return err
	}
	// The later Send session is additional authority, never a replacement for
	// the initiating family's immutable record, revocation and temporal bounds.
	if err := sessionpg.RequireSession(ctx, w, p.session.store, o.Session); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !p.emailChange.validAt(now) {
		return identity.ForbiddenError{}
	}
	return nil
}
