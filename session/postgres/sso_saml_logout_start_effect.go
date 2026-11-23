package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func samlLogoutStartProfile() enterpriseLogoutProfile {
	return enterpriseLogoutProfile{"sso-saml", "sso.saml.logout.session.", kernel.SSOSAMLLogoutStartOperation(), kernel.SSOSAMLLogoutStartDescriptor()}
}

// SSOSAMLLogoutStartFields freezes the admitted SAML session and its original
// exclusive cutoff. The caller must floor the original validity to microseconds
// without extending it. These fields neither authenticate nor renew the session.
func SSOSAMLLogoutStartFields(source session.Session, until time.Time) ([]identity.FeatureField, error) {
	return samlLogoutStartProfile().fields(source, until)
}

// SSOSAMLLogoutStartEffect revokes only the exact original SAML session in the
// owning command's Work. It neither contacts the provider nor decides its outcome.
type SSOSAMLLogoutStartEffect struct{ native Repository }

// NewSSOSAMLLogoutStartEffect selects the installed SAML admission without I/O.
// Apply the journal migration before enabling the caller. The native owner
// must authenticate the source and match its exact linked provider, then
// commit local revocation independently of the remote logout outcome.
func NewSSOSAMLLogoutStartEffect(c Config, admission SSOSAMLSessionAdmission) (*SSOSAMLLogoutStartEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !admission.valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	return &SSOSAMLLogoutStartEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration, revokeSSOSAML: &admission}}, nil
}

// Apply proves original command custody and CSRF and writes the session
// revocation and journal. The receipt is provisional until Work commits.
func (e *SSOSAMLLogoutStartEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, token session.CSRFToken, key session.CSRFKey) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.native.revokeSSOSAML == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return samlLogoutStartProfile().apply(ctx, &e.native, w, owner, c, token, key)
}

// Check fences the exact terminal session, original expiry and current
// authority before commit. It never re-authenticates the revoked session.
func (e *SSOSAMLLogoutStartEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || e == nil || e.native.revokeSSOSAML == nil {
		return session.ErrInvalidSessionCommand
	}
	return samlLogoutStartProfile().check(ctx, &e.native, w, owner, c)
}

// Recover votes from the original journal without repeating revocation or
// granting the caller a new time window. It does not decide remote status.
func (e *SSOSAMLLogoutStartEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, source session.Session) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.native.revokeSSOSAML == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	return samlLogoutStartProfile().recover(ctx, &e.native, w, owner, source)
}
