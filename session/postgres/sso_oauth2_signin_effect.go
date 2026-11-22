package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// SSOOAuth2SigninEffect persists a linked member's OAuth-only session and
// browser use in the original callback transaction. The native SSO owner
// authenticates the provider and browser, owns Work, and controls disclosure.
// Immutable configuration may be used by distinct serial Works concurrently.
type SSOOAuth2SigninEffect struct {
	effect *ssoSigninEffect
}

// NewSSOOAuth2SigninEffect selects the OAuth-only profile. The organization
// owner must fence the original selected membership in the same Work. Install
// SSOOAuth2SigninMigrationSource before use. Construction performs no I/O.
func NewSSOOAuth2SigninEffect(c Config, p IdentifierAdmissionConfig, org OrganizationSessionAuthority) (*SSOOAuth2SigninEffect, error) {
	effect, err := newSSOSigninEffect(c, p, org, true)
	if err != nil {
		return nil, err
	}
	return &SSOOAuth2SigninEffect{effect}, nil
}

// Format redacts all native configuration and borrowed dependencies.
func (*SSOOAuth2SigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOAuth2SigninEffect(redacted)"))
}

// MarshalJSON denies serialization.
func (*SSOOAuth2SigninEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies serialization.
func (*SSOOAuth2SigninEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (e *SSOOAuth2SigninEffect) core() *ssoSigninEffect {
	if e == nil {
		return nil
	}
	return e.effect
}

// Apply requires the exact original command, browser transaction and
// provisionally consumed OAuth state. Every error must abort the original Work;
// success is provisional and does not permit credential disclosure.
func (e *SSOOAuth2SigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	return e.core().apply(ctx, w, owner, command, preauth, nil)
}

// CheckCurrent rechecks the original session and authority in final admission.
// It never substitutes a newer authority generation or renews the lease.
func (e *SSOOAuth2SigninEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return e.core().checkCurrent(ctx, w, owner, command)
}

// Recover reports only the original issuance evidence through RecoveryWork. It
// cannot restore a bearer or establish other callback participants' outcomes.
func (e *SSOOAuth2SigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	return e.core().recover(ctx, w, owner)
}

func (e *ssoSigninEffect) consumption(w kernel.Work, owner kernel.FeatureExecutionContributor) (kernel.CapabilityReservationBinding, error) {
	if e.oauth2 {
		return w.SSOOAuth2SigninConsumption(owner)
	}
	return w.SSOOIDCSigninConsumption(owner)
}

func (e *ssoSigninEffect) session(command identity.Command) (session.Session, error) {
	if e.oauth2 {
		return SSOOAuth2SigninSession(command)
	}
	return SSOOIDCSigninSession(command)
}

func ssoOAuth2SigninIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-sso-oauth2-signin-issuance-v1\x00", binding, user, id, family, record)
}
