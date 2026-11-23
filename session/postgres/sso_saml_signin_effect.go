package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// SSOSAMLSigninEffect writes the exact original linked SAML session and consumes
// its authenticated frontchannel flow within the native callback's Work. The
// owner must validate the signed response and reserve the replay pair before
// calling Apply. This effect cannot authenticate the provider or expose a token.
type SSOSAMLSigninEffect struct{ effect *ssoSigninEffect }

// NewSSOSAMLSigninEffect opts into the separate SP-initiated SAML issuance
// intent. The caller must install the SAML issuance migration and use the
// authoritative organization owner with the same Work. Construction is I/O-free.
func NewSSOSAMLSigninEffect(config Config, profile IdentifierAdmissionConfig, organization OrganizationSessionAuthority) (*SSOSAMLSigninEffect, error) {
	effect, err := newSSOSigninEffect(config, profile, organization, "sso-saml")
	if err != nil {
		return nil, err
	}
	return &SSOSAMLSigninEffect{effect: effect}, nil
}

// Format redacts native configuration and borrowed dependencies.
func (*SSOSAMLSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOSAMLSigninEffect(redacted)"))
}

// MarshalJSON denies implicit serialization.
func (*SSOSAMLSigninEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit serialization.
func (*SSOSAMLSigninEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

func (e *SSOSAMLSigninEffect) core() *ssoSigninEffect {
	if e == nil {
		return nil
	}
	return e.effect
}

// Apply checks the original capability, account, factor, policy and membership
// and consumes the original flow with the new session. Every error aborts Work;
// provisional success never permits disclosure. The replay owner runs first.
func (e *SSOSAMLSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preAuth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	return e.core().apply(ctx, w, owner, command, preAuth, nil)
}

// CheckCurrent rechecks the persisted session and exact original authority
// through the native callback's final commit phase without renewing evidence.
func (e *SSOSAMLSigninEffect) CheckCurrent(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return e.core().checkCurrent(ctx, w, owner, command)
}

// Recover reports the exact historical SAML issuance through RecoveryWork.
// It never restores a bearer, updates authority, or votes for other effects.
func (e *SSOSAMLSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	return e.core().recover(ctx, w, owner)
}

func ssoSAMLSigninIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-sso-saml-signin-issuance-v1\x00", binding, user, id, family, record)
}
