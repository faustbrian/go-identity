package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Dispatch only between explicitly authenticated original-primary owners.
// Passkey subjects never acquire an invented email-recipient admission.
func (p *magicTOTPPhase) requirePrimary(ctx context.Context, w kernel.Work) error {
	if p.input.passkeyPrimary != nil {
		_, err := w.RequireMFAPasskeyCredential(ctx, p, p.input.passkeyPrimary.Credential)
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return err
	}
	if p.input.passwordPrimary != nil {
		credential, err := p.input.passwordCredential()
		if err != nil {
			return err
		}
		_, err = w.RequireRecipientCredential(ctx, p, p.input.recipient, credential)
		return err
	}
	return nil
}

func (p *magicTOTPPhase) requirePreparationPrimary(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p.input.passkeyPrimary != nil {
		_, err := w.RequireMFAPasskeyPreparationCredential(ctx, p, command, p.input.passkeyPrimary.Credential)
		return err
	}
	return p.requirePrimary(ctx, w)
}

func (p *magicTOTPPhase) requireAttemptPrimary(ctx context.Context, w kernel.MFATOTPAttemptWork) error {
	if p.input.passkeyPrimary != nil {
		_, err := w.RequirePasskeyCredential(ctx, p, p.input.passkeyPrimary.Credential)
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return err
	}
	if p.input.passwordPrimary != nil {
		credential, err := p.input.passwordCredential()
		if err != nil {
			return err
		}
		_, err = w.RequireRecipientCredential(ctx, p, p.input.recipient, credential)
		return err
	}
	return nil
}

func (p *magicTOTPPhase) requireBrowser(ctx context.Context, w kernel.Work, command identity.Command, primary identity.CommandID) error {
	require := sessionpg.RequireMFAConsumedPreAuth
	if p.input.passkeyPrimary != nil {
		// Native passkey MFA leaves its original browser issued. The signed
		// child/primary reader authenticates provenance; this existing owner
		// fences the exact original issued record and expiry under Work locks.
		return sessionpg.RequirePreAuth(ctx, w, p.state.config.Session, p.input.flow)
	} else if p.input.verificationPrimary != nil {
		require = sessionpg.RequireMFAVerificationConsumedPreAuth
	}
	return require(ctx, w, p, command, p.state.config.Session, p.input.flow, primary)
}

func (p *magicTOTPPhase) requireAttemptBrowser(ctx context.Context, w kernel.MFATOTPAttemptWork, primary identity.CommandID) error {
	require := sessionpg.RequireMFAConsumedPreAuthAttempt
	if p.input.passkeyPrimary != nil {
		return sessionpg.RequirePreAuth(ctx, w, p.state.config.Session, p.input.flow)
	} else if p.input.verificationPrimary != nil {
		require = sessionpg.RequireMFAVerificationConsumedPreAuthAttempt
	}
	return require(ctx, w, p, p.state.config.Session, p.input.flow, primary)
}

func (p *magicTOTPPhase) passkeySessionAuthority(id, family string) (session.AuthoritySnapshot, error) {
	primary := p.input.passkeyPrimary.Primary
	v, err := primary.Authority.Bindings()
	if err != nil || primary.UserID != identity.UserID(p.input.scope.SubjectID) || primary.TenantID != p.input.scope.TenantID {
		return session.AuthoritySnapshot{}, identity.ForbiddenError{}
	}
	keys, err := sessionpg.SessionAuthorityKeys(primary.TenantID, primary.UserID, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: v.Global, Tenant: v.Tenant, User: v.User, Identifier: v.Identifier, Credential: v.Credential, SessionFamily: session.AuthorityBinding{ScopeKey: keys.Family, Version: 1}, Session: session.AuthorityBinding{ScopeKey: keys.Session, Version: 1}, Authorization: v.Authorization, Factor: v.Factor, Passkey: v.Passkey})
}
